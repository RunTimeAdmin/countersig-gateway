package module

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	// CountersigBundleKID is the Key ID used by the Countersig backend for
	// signing both A2A tokens and policy bundles. The backend publishes
	// this key in its JWKS at /.well-known/jwks.json.
	CountersigBundleKID = "a2a-ed25519-1"

	jwksCacheMaxAge = 10 * time.Minute
)

// AgentClaims is the subset of JWT claims we extract from an agent's token.
// The Countersig backend issues A2A tokens with these claims (and others).
type AgentClaims struct {
	AgentID string `json:"agent_id"`
	OrgID   string `json:"org_id"`
	Subject string `json:"sub"`
	Issuer  string `json:"iss"`
	Expiry  int64  `json:"exp"`
}

// jwksVerifier fetches and caches the Countersig JWKS, then verifies
// agent JWTs against it.
type jwksVerifier struct {
	url string
	mu  sync.RWMutex

	keys      *jose.JSONWebKeySet
	fetchedAt time.Time
	httpClient *http.Client
}

func newJWKSVerifier(url string) *jwksVerifier {
	return &jwksVerifier{
		url:        url,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// VerifyAgentJWT verifies a Bearer JWT issued by the Countersig backend
// and returns the agent claims. Returns an error if the token is invalid,
// expired, or signed with an unknown key.
func (v *jwksVerifier) VerifyAgentJWT(ctx context.Context, token string) (*AgentClaims, error) {
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		return nil, fmt.Errorf("parse jwt: %w", err)
	}

	keys, err := v.getKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}

	// The Countersig backend signs A2A tokens with kid 'a2a-ed25519-1'.
	// Find that key and verify against it.
	matched := keys.Key(CountersigBundleKID)
	if len(matched) == 0 {
		// Fall back to trying each key (allows for future key rotation
		// where backends might publish multiple kids during transitions).
		matched = keys.Keys
	}

	var claims AgentClaims
	var verified bool
	var lastErr error
	for _, key := range matched {
		if err := parsed.Claims(key.Public(), &claims); err == nil {
			verified = true
			break
		} else {
			lastErr = err
		}
	}
	if !verified {
		return nil, fmt.Errorf("verify signature: %w", lastErr)
	}

	if claims.AgentID == "" {
		return nil, fmt.Errorf("token missing agent_id claim")
	}
	if claims.OrgID == "" {
		return nil, fmt.Errorf("token missing org_id claim")
	}
	if claims.Expiry > 0 && time.Now().Unix() > claims.Expiry {
		return nil, fmt.Errorf("token expired")
	}

	return &claims, nil
}

// getKeys returns the cached JWKS, refreshing if older than jwksCacheMaxAge.
func (v *jwksVerifier) getKeys(ctx context.Context) (*jose.JSONWebKeySet, error) {
	v.mu.RLock()
	if v.keys != nil && time.Since(v.fetchedAt) < jwksCacheMaxAge {
		k := v.keys
		v.mu.RUnlock()
		return k, nil
	}
	v.mu.RUnlock()

	v.mu.Lock()
	defer v.mu.Unlock()

	// Double-check after acquiring write lock
	if v.keys != nil && time.Since(v.fetchedAt) < jwksCacheMaxAge {
		return v.keys, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks endpoint returned %d", resp.StatusCode)
	}

	var keys jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return nil, fmt.Errorf("decode jwks: %w", err)
	}
	if len(keys.Keys) == 0 {
		return nil, fmt.Errorf("jwks document is empty")
	}

	v.keys = &keys
	v.fetchedAt = time.Now()
	return v.keys, nil
}
