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
	CountersigIssuer    = "countersig.com"
	CountersigAudience  = "countersig-a2a"

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

	keys       *jose.JSONWebKeySet
	fetchedAt  time.Time
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
	if len(parsed.Headers) == 0 || parsed.Headers[0].KeyID == "" {
		return nil, fmt.Errorf("token missing kid header")
	}
	if parsed.Headers[0].KeyID != CountersigBundleKID {
		return nil, fmt.Errorf("unexpected kid %q", parsed.Headers[0].KeyID)
	}

	keys, err := v.getKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}

	// The Countersig backend signs A2A tokens with kid 'a2a-ed25519-1'.
	// Find that key and verify against it.
	matched := keys.Key(parsed.Headers[0].KeyID)
	if len(matched) == 0 {
		return nil, fmt.Errorf("no key found for kid %q", parsed.Headers[0].KeyID)
	}

	var claims AgentClaims
	var standard struct {
		Audience any `json:"aud"`
	}
	var verified bool
	var verifyErr error
	for _, key := range matched {
		if err := parsed.Claims(key.Public(), &claims, &standard); err != nil {
			verifyErr = err
			continue
		}
		verified = true
		break
	}
	if !verified {
		return nil, fmt.Errorf("verify signature: %w", verifyErr)
	}

	if claims.AgentID == "" {
		return nil, fmt.Errorf("token missing agent_id claim")
	}
	if claims.OrgID == "" {
		return nil, fmt.Errorf("token missing org_id claim")
	}
	if claims.Issuer != CountersigIssuer {
		return nil, fmt.Errorf("invalid issuer %q", claims.Issuer)
	}
	if !hasExpectedAudience(standard.Audience, CountersigAudience) {
		return nil, fmt.Errorf("token missing required audience %q", CountersigAudience)
	}
	if claims.Expiry > 0 && time.Now().Unix() > claims.Expiry {
		return nil, fmt.Errorf("token expired")
	}

	return &claims, nil
}

func hasExpectedAudience(audience any, expected string) bool {
	switch aud := audience.(type) {
	case string:
		return aud == expected
	case []any:
		for _, item := range aud {
			if value, ok := item.(string); ok && value == expected {
				return true
			}
		}
	case []string:
		for _, value := range aud {
			if value == expected {
				return true
			}
		}
	}
	return false
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
