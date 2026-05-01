package module

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

func testLogger(t *testing.T) *zap.Logger {
	return zaptest.NewLogger(t)
}

// fakeNext records that it was invoked. We use it to assert allow paths
// reach the next handler in the chain.
type fakeNext struct {
	called bool
}

func (f *fakeNext) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	f.called = true
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("forwarded"))
	return nil
}

// makeHandler builds a Handler with a mock policy backend and skipped JWKS.
func makeHandler(t *testing.T, decision *PolicyDecision, backendErr error) (*Handler, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/v1/policy/check") {
			http.NotFound(w, r)
			return
		}
		if backendErr != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(decision)
	}))

	cache, err := newDecisionCache(100, 60*time.Second)
	if err != nil {
		t.Fatalf("cache init: %v", err)
	}

	h := &Handler{
		APIBase:        srv.URL,
		APIKey:         "test-gateway-key",
		FailMode:       FailClosed,
		RequireAuth:    false, // tests inject identity manually
		RequestTimeout: 5_000_000_000, // 5s as caddy.Duration (int64 ns)
		cache:          cache,
		policyClient:   newPolicyClient(srv.URL, "test-gateway-key", 5*time.Second),
		logger:         testLogger(t),
	}
	return h, srv
}

// requestWithDest builds a request that the handler will see as targeting
// the given destination.
func requestWithDest(method, dest string) *http.Request {
	r := httptest.NewRequest(method, "http://gateway/", nil)
	r.Header.Set(HeaderTargetUpstream, dest)
	return r
}

// runWithIdentity invokes the handler with an identity already attached
// to bypass JWKS verification.
func runWithIdentity(t *testing.T, h *Handler, r *http.Request, agentID string) (*httptest.ResponseRecorder, *fakeNext) {
	t.Helper()

	// Inject identity by wrapping ServeHTTP with a synthetic auth path.
	// In production this happens via Authorization: Bearer + JWKS; for
	// tests we monkey-patch by intercepting the handler.
	// The cleanest way is to test through a thin adapter that calls the
	// internals.

	rec := httptest.NewRecorder()
	next := &fakeNext{}

	dest, err := h.extractDestination(r)
	if err != nil {
		h.deny(rec, r, "no_destination", "input", "enforced", err.Error())
		return rec, next
	}

	// Cache lookup
	if cached, hit := h.cache.Get(agentID, dest); hit {
		_ = h.applyDecision(rec, r, next, agentID, dest, &PolicyDecision{
			Allowed: cached.Allowed,
			Reason:  cached.Reason,
			Scope:   cached.Scope,
			Mode:    cached.Mode,
			Token:   cached.Token,
		})
		return rec, next
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	decision, err := h.policyClient.Check(ctx, agentID, dest)
	if err != nil {
		_ = h.handleBackendError(rec, r, next, agentID, dest, err)
		return rec, next
	}

	h.cache.Put(agentID, dest, &CachedDecision{
		Allowed: decision.Allowed,
		Reason:  decision.Reason,
		Scope:   decision.Scope,
		Mode:    decision.Mode,
		Token:   decision.Token,
	})
	_ = h.applyDecision(rec, r, next, agentID, dest, decision)
	return rec, next
}

// ----- Tests -----

func TestAllowedDestinationForwarded(t *testing.T) {
	registerMetrics()
	h, srv := makeHandler(t, &PolicyDecision{
		Allowed: true,
		Reason:  "whitelisted",
		Scope:   "org",
		Mode:    "enforced",
	}, nil)
	defer srv.Close()

	r := requestWithDest(http.MethodGet, "api.openai.com")
	rec, next := runWithIdentity(t, h, r, "agent-uuid-1")

	if !next.called {
		t.Fatalf("expected next handler to be called for allow")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestDeniedDestinationReturns403(t *testing.T) {
	registerMetrics()
	h, srv := makeHandler(t, &PolicyDecision{
		Allowed: false,
		Reason:  "not_whitelisted",
		Scope:   "org",
		Mode:    "enforced",
	}, nil)
	defer srv.Close()

	r := requestWithDest(http.MethodGet, "evil.example.com")
	rec, next := runWithIdentity(t, h, r, "agent-uuid-1")

	if next.called {
		t.Fatalf("next should NOT be called on deny")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	if rec.Header().Get(HeaderReason) != "not_whitelisted" {
		t.Fatalf("missing reason header")
	}

	// Body should be parseable JSON
	body, _ := io.ReadAll(rec.Body)
	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("body not JSON: %v / %s", err, body)
	}
	if parsed["allowed"].(bool) {
		t.Fatalf("body says allowed=true on deny")
	}
}

func TestCacheHitAvoidsBackendCall(t *testing.T) {
	registerMetrics()
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&PolicyDecision{
			Allowed: true, Reason: "whitelisted", Scope: "org", Mode: "enforced",
		})
	}))
	defer srv.Close()

	cache, _ := newDecisionCache(100, 60*time.Second)
	h := &Handler{
		APIBase: srv.URL, APIKey: "k", FailMode: FailClosed,
		cache:        cache,
		policyClient: newPolicyClient(srv.URL, "k", 5*time.Second),
		logger:       testLogger(t),
	}

	for i := 0; i < 3; i++ {
		r := requestWithDest(http.MethodGet, "api.openai.com")
		rec, _ := runWithIdentity(t, h, r, "agent-1")
		if rec.Code != http.StatusOK {
			t.Fatalf("iter %d: expected 200, got %d", i, rec.Code)
		}
	}
	if callCount != 1 {
		t.Fatalf("expected 1 backend call (rest cached), got %d", callCount)
	}
}

func TestFailClosedOnBackendError(t *testing.T) {
	registerMetrics()
	h, srv := makeHandler(t, nil, errors.New("backend down"))
	srv.Close() // close immediately so connections fail
	h.policyClient = newPolicyClient("http://127.0.0.1:1", "k", 200*time.Millisecond)
	h.FailMode = FailClosed

	r := requestWithDest(http.MethodGet, "api.openai.com")
	rec, next := runWithIdentity(t, h, r, "agent-1")

	if next.called {
		t.Fatalf("next should not be called when fail_mode=closed and backend down")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestFailOpenOnBackendError(t *testing.T) {
	registerMetrics()
	h, srv := makeHandler(t, nil, errors.New("backend down"))
	srv.Close()
	h.policyClient = newPolicyClient("http://127.0.0.1:1", "k", 200*time.Millisecond)
	h.FailMode = FailOpen

	r := requestWithDest(http.MethodGet, "api.openai.com")
	rec, next := runWithIdentity(t, h, r, "agent-1")

	if !next.called {
		t.Fatalf("next should be called when fail_mode=open even on backend error")
	}
	_ = rec
}

func TestFailCachedOnlyServesStaleCache(t *testing.T) {
	registerMetrics()
	cache, _ := newDecisionCache(100, 60*time.Second)
	cache.Put("agent-1", "api.openai.com", &CachedDecision{
		Allowed: true, Reason: "whitelisted", Scope: "org", Mode: "enforced",
	})

	h := &Handler{
		APIBase: "http://127.0.0.1:1", APIKey: "k", FailMode: FailCachedOnly,
		cache:        cache,
		policyClient: newPolicyClient("http://127.0.0.1:1", "k", 200*time.Millisecond),
		logger:       testLogger(t),
	}

	r := requestWithDest(http.MethodGet, "api.openai.com")
	// Make cache appear stale by advancing storedAt back in time
	h.cache.lru.Peek(cacheKey("agent-1", "api.openai.com"))
	if entry, _ := h.cache.GetStale("agent-1", "api.openai.com"); entry != nil {
		entry.StoredAt = time.Now().Add(-1 * time.Hour)
	}

	rec, next := runWithIdentity(t, h, r, "agent-1")

	if !next.called {
		t.Fatalf("expected next called from stale cache")
	}
	_ = rec
}

func TestFailCachedOnlyDeniesOnCacheMiss(t *testing.T) {
	registerMetrics()
	cache, _ := newDecisionCache(100, 60*time.Second)

	h := &Handler{
		APIBase: "http://127.0.0.1:1", APIKey: "k", FailMode: FailCachedOnly,
		cache:        cache,
		policyClient: newPolicyClient("http://127.0.0.1:1", "k", 200*time.Millisecond),
		logger:       testLogger(t),
	}

	r := requestWithDest(http.MethodGet, "api.openai.com")
	rec, next := runWithIdentity(t, h, r, "agent-1")

	if next.called {
		t.Fatalf("next should NOT be called on cache miss + backend down + fail_cached_only")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestExtractDestinationForwardProxyConnect(t *testing.T) {
	h := &Handler{}
	r := httptest.NewRequest(http.MethodConnect, "/", nil)
	r.Host = "api.openai.com:443"
	dest, err := h.extractDestination(r)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if dest != "api.openai.com:443" {
		t.Fatalf("got %q", dest)
	}
}

func TestExtractDestinationReverseProxyHeader(t *testing.T) {
	h := &Handler{}
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set(HeaderTargetUpstream, "https://api.openai.com")
	dest, err := h.extractDestination(r)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if dest != "api.openai.com" {
		t.Fatalf("got %q", dest)
	}
}

func TestStripsCountersigHeadersOnAllow(t *testing.T) {
	registerMetrics()
	h, srv := makeHandler(t, &PolicyDecision{
		Allowed: true, Reason: "whitelisted", Scope: "org", Mode: "enforced",
	}, nil)
	defer srv.Close()

	r := httptest.NewRequest(http.MethodGet, "http://gateway/", nil)
	r.Header.Set(HeaderTargetUpstream, "api.openai.com")
	r.Header.Set(HeaderAgent, "secret-api-key")
	r.Header.Set(HeaderAgent+"-Id", "agent-uuid")

	_, next := runWithIdentity(t, h, r, "agent-uuid")
	if !next.called {
		t.Fatalf("expected next called")
	}
	// After applyDecision, the Countersig headers should be stripped from r
	if r.Header.Get(HeaderTargetUpstream) != "" {
		t.Errorf("X-Target-Upstream not stripped")
	}
	if r.Header.Get(HeaderAgent) != "" {
		t.Errorf("X-Countersig-Agent not stripped")
	}
}

func TestInjectsA2ATokenForAgentDestinations(t *testing.T) {
	registerMetrics()
	h, srv := makeHandler(t, &PolicyDecision{
		Allowed: true,
		Reason:  "internal_agent_reference",
		Scope:   "inherit",
		Mode:    "enforced",
		Token:   "minted-a2a-jwt",
	}, nil)
	defer srv.Close()

	r := requestWithDest(http.MethodPost, "agent:550e8400-e29b-41d4-a716-446655440000")
	r.Header.Set("Authorization", "Bearer caller-token")

	_, _ = runWithIdentity(t, h, r, "agent-1")

	got := r.Header.Get("Authorization")
	if got != "Bearer minted-a2a-jwt" {
		t.Fatalf("expected A2A token injected, got %q", got)
	}
}

// Ensure the package-level interface guards still compile against
// our test wiring.
var _ caddyhttp.MiddlewareHandler = (*Handler)(nil)
