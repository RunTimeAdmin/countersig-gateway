package module

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// Header names used by the gateway for policy reasoning and dispatch.
const (
	HeaderTargetUpstream = "X-Target-Upstream"
	HeaderReason         = "X-Countersig-Reason"
	HeaderScope          = "X-Countersig-Scope"
	HeaderMode           = "X-Countersig-Mode"
	HeaderAgent          = "X-Countersig-Agent"
)

// ServeHTTP is the request lifecycle:
//
//  1. Optionally serve the metrics endpoint.
//  2. Extract the destination (forward proxy or reverse proxy mode).
//  3. Authenticate the calling agent (JWT or basic auth or skipped).
//  4. Cache lookup.
//  5. On miss, call /v1/policy/check.
//  6. Apply the decision: forward (allow) or 403 (deny).
//  7. Inject A2A token for agent: destinations.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// 1. Metrics
	if h.metricsServer != nil && h.metricsServer.Matches(r.URL.Path) {
		h.metricsServer.ServeHTTP(w, r)
		return nil
	}

	// 2. Destination
	destination, err := h.extractDestination(r)
	if err != nil {
		h.deny(w, r, "no_destination", "input", "enforced", err.Error())
		return nil
	}

	// 3. Identity
	agentID, _, err := h.authenticateAgent(r)
	if err != nil {
		if h.RequireAuth {
			authFailuresTotal.WithLabelValues(err.Error()).Inc()
			h.deny(w, r, "auth_failed", "input", "enforced", err.Error())
			return nil
		}
		// require_auth=false: allow unauthenticated through with no policy check.
		// This is documented as opt-in for trusted private deployments only.
		h.logger.Debug("unauthenticated request allowed (require_auth=false)",
			zap.String("destination", destination),
		)
		return next.ServeHTTP(w, r)
	}

	// 4. Cache
	if cached, hit := h.cache.Get(agentID, destination); hit {
		cacheHitsTotal.Inc()
		return h.applyDecision(w, r, next, agentID, destination, &PolicyDecision{
			Allowed: cached.Allowed,
			Reason:  cached.Reason,
			Scope:   cached.Scope,
			Mode:    cached.Mode,
			Token:   cached.Token,
		})
	}
	cacheMissesTotal.Inc()

	// 5. Backend call
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(h.RequestTimeout))
	defer cancel()

	start := time.Now()
	decision, err := h.policyClient.Check(ctx, agentID, destination)
	checkLatencySeconds.Observe(time.Since(start).Seconds())

	if err != nil {
		return h.handleBackendError(w, r, next, agentID, destination, err)
	}

	// Cache the fresh decision
	h.cache.Put(agentID, destination, &CachedDecision{
		Allowed: decision.Allowed,
		Reason:  decision.Reason,
		Scope:   decision.Scope,
		Mode:    decision.Mode,
		Token:   decision.Token,
	})

	return h.applyDecision(w, r, next, agentID, destination, decision)
}

// extractDestination identifies what the request is trying to reach.
//
// Forward proxy mode: the request URL is absolute (e.g. for HTTP) or this
// is a CONNECT (for HTTPS). We use Host header for both.
//
// Reverse proxy mode: callers set X-Target-Upstream to indicate where they
// want to go.
//
// Returns the destination as host[:port], no scheme.
func (h *Handler) extractDestination(r *http.Request) (string, error) {
	// Reverse-proxy mode: explicit header
	if upstream := r.Header.Get(HeaderTargetUpstream); upstream != "" {
		return strings.TrimPrefix(strings.TrimPrefix(upstream, "https://"), "http://"), nil
	}

	// Forward-proxy mode: CONNECT or absolute URI
	if r.Method == http.MethodConnect {
		return r.Host, nil
	}
	if r.URL.Host != "" {
		return r.URL.Host, nil
	}
	if r.Host != "" {
		return r.Host, nil
	}
	return "", errors.New("request has no destination (no Host header, no X-Target-Upstream)")
}

// authenticateAgent extracts the calling agent's identity from the request.
//
// Primary path: Authorization: Bearer <jwt> verified against JWKS.
// Fallback: X-Countersig-Agent header with API key (treated opaquely;
// the backend validates it on /policy/check).
//
// Returns (agentID, orgID, nil) on success.
func (h *Handler) authenticateAgent(r *http.Request) (string, string, error) {
	// Primary: Bearer JWT
	authz := r.Header.Get("Authorization")
	if strings.HasPrefix(authz, "Bearer ") {
		token := strings.TrimPrefix(authz, "Bearer ")
		claims, err := h.jwks.VerifyAgentJWT(r.Context(), token)
		if err != nil {
			return "", "", fmt.Errorf("invalid_jwt")
		}
		return claims.AgentID, claims.OrgID, nil
	}

	// Fallback: API key header. We can't introspect it locally; the
	// backend's /policy/check call will accept this token via its
	// existing authenticate middleware, but we still need an agentID
	// for caching and for the request body.
	//
	// Convention: customers using API-key auth set BOTH:
	//   X-Countersig-Agent: <api-key>
	//   X-Countersig-Agent-Id: <agent-uuid>
	// The agent-id header is unverified locally but the backend will
	// enforce that the API key's org owns the agent.
	if apiKey := r.Header.Get(HeaderAgent); apiKey != "" {
		agentID := r.Header.Get(HeaderAgent + "-Id")
		if agentID == "" {
			return "", "", fmt.Errorf("missing_agent_id_header")
		}
		// Stash the API key on the request for the backend call to use
		// instead of the gateway's own service key. This is set on a
		// per-request basis via context.
		r = r.WithContext(context.WithValue(r.Context(), apiKeyOverrideKey{}, apiKey))
		return agentID, "", nil
	}

	return "", "", fmt.Errorf("no_credentials")
}

// handleBackendError applies the configured fail_mode behavior.
func (h *Handler) handleBackendError(
	w http.ResponseWriter,
	r *http.Request,
	next caddyhttp.Handler,
	agentID, destination string,
	err error,
) error {
	h.logger.Warn("policy backend call failed",
		zap.String("agent_id", agentID),
		zap.String("destination", destination),
		zap.Error(err),
	)

	switch h.FailMode {
	case FailOpen:
		backendErrorsTotal.WithLabelValues("allow").Inc()
		return next.ServeHTTP(w, r)

	case FailCachedOnly:
		// Use any cached decision regardless of TTL
		if stale, ok := h.cache.GetStale(agentID, destination); ok {
			backendErrorsTotal.WithLabelValues("stale_cache").Inc()
			return h.applyDecision(w, r, next, agentID, destination, &PolicyDecision{
				Allowed: stale.Allowed,
				Reason:  stale.Reason + "_stale",
				Scope:   stale.Scope,
				Mode:    stale.Mode,
				Token:   stale.Token,
			})
		}
		backendErrorsTotal.WithLabelValues("deny").Inc()
		h.deny(w, r, "backend_unreachable_no_cache", "input", "enforced", err.Error())
		return nil

	case FailClosed:
		fallthrough
	default:
		backendErrorsTotal.WithLabelValues("deny").Inc()
		h.deny(w, r, "backend_unreachable", "input", "enforced", err.Error())
		return nil
	}
}

// applyDecision returns 403 on deny or hands off to next on allow.
// For agent: destinations with a server-minted A2A token, the token is
// injected as Authorization: Bearer on the forwarded request.
func (h *Handler) applyDecision(
	w http.ResponseWriter,
	r *http.Request,
	next caddyhttp.Handler,
	agentID, destination string,
	decision *PolicyDecision,
) error {
	if !decision.Allowed {
		deniedTotal.WithLabelValues(decision.Reason, decision.Scope, decision.Mode).Inc()
		h.logger.Info("policy denied",
			zap.String("agent_id", agentID),
			zap.String("destination", destination),
			zap.String("reason", decision.Reason),
			zap.String("scope", decision.Scope),
			zap.String("mode", decision.Mode),
		)
		h.deny(w, r, decision.Reason, decision.Scope, decision.Mode, "")
		return nil
	}

	allowedTotal.WithLabelValues(decision.Reason, decision.Mode).Inc()

	// For internal agent-to-agent traffic, the backend mints a short-
	// lived A2A token. Replace the caller's Authorization header so the
	// downstream agent sees the minted token, not the caller's identity.
	if decision.Token != "" {
		r.Header.Set("Authorization", "Bearer "+decision.Token)
	}

	// Strip Countersig-specific headers before forwarding so they don't
	// leak to upstream destinations.
	r.Header.Del(HeaderTargetUpstream)
	r.Header.Del(HeaderAgent)
	r.Header.Del(HeaderAgent + "-Id")

	return next.ServeHTTP(w, r)
}

// deny writes a 403 response with the policy reason in headers and body.
func (h *Handler) deny(w http.ResponseWriter, r *http.Request, reason, scope, mode, detail string) {
	w.Header().Set(HeaderReason, reason)
	w.Header().Set(HeaderScope, scope)
	w.Header().Set(HeaderMode, mode)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)

	body := fmt.Sprintf(
		`{"allowed":false,"reason":%q,"scope":%q,"mode":%q,"detail":%q}`,
		reason, scope, mode, detail,
	)
	_, _ = w.Write([]byte(body))
}

// apiKeyOverrideKey is the context key for overriding the gateway's
// service API key with a per-request API key from the agent header.
type apiKeyOverrideKey struct{}
