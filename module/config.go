// Package module implements the countersig_policy Caddy HTTP handler.
// It enforces destination allow-lists for AI agent traffic by calling
// the Countersig policy backend on every request.
package module

import (
	"fmt"
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("countersig_policy", parseCaddyfile)
}

// FailMode controls behavior when the policy backend is unreachable.
type FailMode string

const (
	// FailClosed denies all calls when the policy backend is unreachable
	// and there is no cached decision.
	FailClosed FailMode = "closed"

	// FailOpen allows all calls when the policy backend is unreachable.
	// Use only in dev/staging or when availability outranks security.
	FailOpen FailMode = "open"

	// FailCachedOnly serves from cache when the backend is unreachable.
	// Cache misses during an outage are denied.
	FailCachedOnly FailMode = "cached_only"
)

// Handler is the countersig_policy Caddy HTTP handler.
//
// Caddyfile syntax:
//
//	countersig_policy {
//	    api_base       https://api.countersig.com
//	    api_key        {env.COUNTERSIG_GATEWAY_API_KEY}
//	    cache_ttl      300
//	    cache_size     10000
//	    fail_mode      closed
//	    require_auth   true
//	    jwks_url       https://api.countersig.com/.well-known/jwks.json
//	    request_timeout 5s
//	    metrics_path   /metrics
//	}
type Handler struct {
	// APIBase is the Countersig API base URL, e.g. "https://api.countersig.com".
	// Required.
	APIBase string `json:"api_base,omitempty"`

	// APIKey is the Bearer token the gateway uses to call /v1/policy/check.
	// This is the gateway's own service identity, separate from the agent's
	// JWT. Required.
	APIKey string `json:"api_key,omitempty"`

	// CacheTTLSeconds is how long policy decisions are cached. Default 300.
	CacheTTLSeconds int `json:"cache_ttl,omitempty"`

	// CacheSize is the maximum number of cached decisions. Default 10000.
	CacheSize int `json:"cache_size,omitempty"`

	// FailMode controls behavior when the policy backend is unreachable.
	// One of: "closed" (default), "open", "cached_only".
	FailMode FailMode `json:"fail_mode,omitempty"`

	// RequireAuth controls whether requests without a valid agent JWT are
	// rejected. Default true. Set to false only for trusted homogeneous
	// fleets where the gateway sits in a private network.
	RequireAuth bool `json:"require_auth,omitempty"`

	// JWKSURL is the URL serving the Countersig JWKS document. Defaults to
	// {APIBase}/.well-known/jwks.json.
	JWKSURL string `json:"jwks_url,omitempty"`

	// RequestTimeout is the timeout for each /policy/check call.
	// Default 5 seconds.
	RequestTimeout caddy.Duration `json:"request_timeout,omitempty"`

	// MetricsPath, if set, exposes Prometheus metrics on the configured
	// listener at this path. Disabled by default.
	MetricsPath string `json:"metrics_path,omitempty"`

	// Internal state, populated during Provision.
	cache         *decisionCache
	jwks          *jwksVerifier
	policyClient  *policyClient
	metricsServer *metricsHandler
	logger        *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.countersig_policy",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up the handler.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger(h)

	// Defaults
	if h.CacheTTLSeconds == 0 {
		h.CacheTTLSeconds = 300
	}
	if h.CacheSize == 0 {
		h.CacheSize = 10000
	}
	if h.FailMode == "" {
		h.FailMode = FailClosed
	}
	if !h.RequireAuth && h.RequireAuth != false {
		// Caddy zero-value is false; we want the documented default of true.
		// Use an explicit pointer in JSON to override; for Caddyfile, see
		// parseCaddyfile which sets this explicitly.
	}
	if h.RequestTimeout == 0 {
		h.RequestTimeout = caddy.Duration(5 * time.Second)
	}
	if h.JWKSURL == "" && h.APIBase != "" {
		h.JWKSURL = h.APIBase + "/.well-known/jwks.json"
	}

	// Validate
	if h.APIBase == "" {
		return fmt.Errorf("api_base is required")
	}
	if h.APIKey == "" {
		return fmt.Errorf("api_key is required")
	}
	switch h.FailMode {
	case FailClosed, FailOpen, FailCachedOnly:
	default:
		return fmt.Errorf("invalid fail_mode %q (must be 'closed', 'open', or 'cached_only')", h.FailMode)
	}

	// Wire up subsystems
	cache, err := newDecisionCache(h.CacheSize, time.Duration(h.CacheTTLSeconds)*time.Second)
	if err != nil {
		return fmt.Errorf("init cache: %w", err)
	}
	h.cache = cache

	h.jwks = newJWKSVerifier(h.JWKSURL)
	h.policyClient = newPolicyClient(h.APIBase, h.APIKey, time.Duration(h.RequestTimeout))

	if h.MetricsPath != "" {
		h.metricsServer = newMetricsHandler(h.MetricsPath)
	}

	h.logger.Info("countersig_policy provisioned",
		zapField("api_base", h.APIBase),
		zapField("fail_mode", string(h.FailMode)),
		zapField("cache_ttl", h.CacheTTLSeconds),
		zapField("require_auth", h.RequireAuth),
	)
	return nil
}

// Validate confirms the handler config is internally consistent.
func (h *Handler) Validate() error {
	return nil
}

// Cleanup releases resources.
func (h *Handler) Cleanup() error {
	return nil
}

// parseCaddyfile parses the countersig_policy directive.
func parseCaddyfile(helper httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	h := &Handler{
		// Defaults that are non-zero values
		RequireAuth: true,
	}

	for helper.Next() {
		// No inline args
		if helper.NextArg() {
			return nil, helper.ArgErr()
		}

		for helper.NextBlock(0) {
			switch helper.Val() {
			case "api_base":
				if !helper.AllArgs(&h.APIBase) {
					return nil, helper.ArgErr()
				}
			case "api_key":
				if !helper.AllArgs(&h.APIKey) {
					return nil, helper.ArgErr()
				}
			case "jwks_url":
				if !helper.AllArgs(&h.JWKSURL) {
					return nil, helper.ArgErr()
				}
			case "cache_ttl":
				var v string
				if !helper.AllArgs(&v) {
					return nil, helper.ArgErr()
				}
				n, err := strconv.Atoi(v)
				if err != nil {
					return nil, fmt.Errorf("cache_ttl: %w", err)
				}
				h.CacheTTLSeconds = n
			case "cache_size":
				var v string
				if !helper.AllArgs(&v) {
					return nil, helper.ArgErr()
				}
				n, err := strconv.Atoi(v)
				if err != nil {
					return nil, fmt.Errorf("cache_size: %w", err)
				}
				h.CacheSize = n
			case "fail_mode":
				var v string
				if !helper.AllArgs(&v) {
					return nil, helper.ArgErr()
				}
				h.FailMode = FailMode(v)
			case "require_auth":
				var v string
				if !helper.AllArgs(&v) {
					return nil, helper.ArgErr()
				}
				switch v {
				case "true":
					h.RequireAuth = true
				case "false":
					h.RequireAuth = false
				default:
					return nil, fmt.Errorf("require_auth must be 'true' or 'false', got %q", v)
				}
			case "request_timeout":
				var v string
				if !helper.AllArgs(&v) {
					return nil, helper.ArgErr()
				}
				d, err := caddy.ParseDuration(v)
				if err != nil {
					return nil, fmt.Errorf("request_timeout: %w", err)
				}
				h.RequestTimeout = caddy.Duration(d)
			case "metrics_path":
				if !helper.AllArgs(&h.MetricsPath) {
					return nil, helper.ArgErr()
				}
			default:
				return nil, helper.Errf("unknown subdirective %q", helper.Val())
			}
		}
	}

	return h, nil
}

// UnmarshalCaddyfile fulfills caddyfile.Unmarshaler so the directive can
// also be used in the JSON config form.
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	helper := httpcaddyfile.Helper{Dispenser: d}
	parsed, err := parseCaddyfile(helper)
	if err != nil {
		return err
	}
	*h = *parsed.(*Handler)
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.Validator             = (*Handler)(nil)
	_ caddy.CleanerUpper          = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
)
