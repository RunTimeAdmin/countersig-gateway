package module

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPolicyClientUsesOverrideAPIKey(t *testing.T) {
	t.Helper()

	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&PolicyDecision{
			Allowed: true,
			Reason:  "whitelisted",
			Scope:   "org",
			Mode:    "enforced",
		})
	}))
	defer srv.Close()

	client := newPolicyClient(srv.URL, "gateway-service-key", 2*time.Second)
	_, err := client.Check(context.Background(), "agent-1", "api.openai.com", "agent-fallback-key")
	if err != nil {
		t.Fatalf("expected successful check, got error: %v", err)
	}

	if gotAuth != "Bearer agent-fallback-key" {
		t.Fatalf("expected override auth header, got %q", gotAuth)
	}
}
