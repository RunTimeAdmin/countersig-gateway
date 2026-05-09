package module

import "testing"

func TestRequireAuthEnabledDefaultsTrueWhenUnset(t *testing.T) {
	h := &Handler{}
	if !h.requireAuthEnabled() {
		t.Fatalf("expected require_auth default to true when unset")
	}
}

func TestRequireAuthEnabledRespectsExplicitFalse(t *testing.T) {
	h := &Handler{RequireAuth: boolPtr(false)}
	if h.requireAuthEnabled() {
		t.Fatalf("expected require_auth false when explicitly set")
	}
}
