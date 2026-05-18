package module

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func makeJWKSVerifier(t *testing.T, keys []jose.JSONWebKey) (*jwksVerifier, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: keys})
	}))
	return newJWKSVerifier(server.URL), server
}

func signAgentToken(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	kid string,
	agentID string,
	orgID string,
	issuer string,
	audience any,
	expiry time.Time,
) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.EdDSA, Key: jose.JSONWebKey{Key: privateKey, KeyID: kid}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	claims := map[string]any{
		"agent_id": agentID,
		"org_id":   orgID,
		"sub":      agentID,
		"iss":      issuer,
		"aud":      audience,
		"exp":      expiry.Unix(),
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return token
}

func TestVerifyAgentJWT_ValidToken(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	verifier, server := makeJWKSVerifier(t, []jose.JSONWebKey{
		{Key: pub, KeyID: CountersigBundleKID, Algorithm: string(jose.EdDSA), Use: "sig"},
	})
	defer server.Close()

	token := signAgentToken(
		t,
		priv,
		CountersigBundleKID,
		"agent-123",
		"org-456",
		CountersigIssuer,
		[]string{CountersigAudience},
		time.Now().Add(5*time.Minute),
	)

	claims, verifyErr := verifier.VerifyAgentJWT(context.Background(), token)
	if verifyErr != nil {
		t.Fatalf("verify failed: %v", verifyErr)
	}
	if claims.AgentID != "agent-123" {
		t.Fatalf("expected agent_id agent-123, got %q", claims.AgentID)
	}
	if claims.OrgID != "org-456" {
		t.Fatalf("expected org_id org-456, got %q", claims.OrgID)
	}
}

func TestVerifyAgentJWT_RejectsWrongIssuer(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	verifier, server := makeJWKSVerifier(t, []jose.JSONWebKey{
		{Key: pub, KeyID: CountersigBundleKID, Algorithm: string(jose.EdDSA), Use: "sig"},
	})
	defer server.Close()

	token := signAgentToken(
		t,
		priv,
		CountersigBundleKID,
		"agent-123",
		"org-456",
		"not-countersig",
		CountersigAudience,
		time.Now().Add(5*time.Minute),
	)

	_, verifyErr := verifier.VerifyAgentJWT(context.Background(), token)
	if verifyErr == nil || !strings.Contains(verifyErr.Error(), "invalid issuer") {
		t.Fatalf("expected invalid issuer error, got %v", verifyErr)
	}
}

func TestVerifyAgentJWT_RejectsSubjectMismatch(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	verifier, server := makeJWKSVerifier(t, []jose.JSONWebKey{
		{Key: pub, KeyID: CountersigBundleKID, Algorithm: string(jose.EdDSA), Use: "sig"},
	})
	defer server.Close()

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.EdDSA, Key: jose.JSONWebKey{Key: priv, KeyID: CountersigBundleKID}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	token, err := jwt.Signed(signer).Claims(map[string]any{
		"agent_id": "agent-123",
		"org_id":   "org-456",
		"sub":      "different-agent",
		"iss":      CountersigIssuer,
		"aud":      CountersigAudience,
		"exp":      time.Now().Add(5 * time.Minute).Unix(),
	}).Serialize()
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	_, verifyErr := verifier.VerifyAgentJWT(context.Background(), token)
	if verifyErr == nil || !strings.Contains(verifyErr.Error(), "subject must match agent_id") {
		t.Fatalf("expected subject mismatch error, got %v", verifyErr)
	}
}

func TestVerifyAgentJWT_RejectsMissingKid(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	verifier, server := makeJWKSVerifier(t, []jose.JSONWebKey{
		{Key: pub, KeyID: CountersigBundleKID, Algorithm: string(jose.EdDSA), Use: "sig"},
	})
	defer server.Close()

	token := signAgentToken(
		t,
		priv,
		"",
		"agent-123",
		"org-456",
		CountersigIssuer,
		CountersigAudience,
		time.Now().Add(5*time.Minute),
	)

	_, verifyErr := verifier.VerifyAgentJWT(context.Background(), token)
	if verifyErr == nil || !strings.Contains(verifyErr.Error(), "missing kid") {
		t.Fatalf("expected missing kid error, got %v", verifyErr)
	}
}

func TestVerifyAgentJWT_RejectsExpiredAndUnknownKid(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	verifier, server := makeJWKSVerifier(t, []jose.JSONWebKey{
		{Key: pub, KeyID: CountersigBundleKID, Algorithm: string(jose.EdDSA), Use: "sig"},
	})
	defer server.Close()

	tokenWithUnknownKid := signAgentToken(
		t,
		priv,
		"rotated-kid",
		"agent-123",
		"org-456",
		CountersigIssuer,
		CountersigAudience,
		time.Now().Add(5*time.Minute),
	)
	if _, verifyErr := verifier.VerifyAgentJWT(context.Background(), tokenWithUnknownKid); verifyErr == nil {
		t.Fatalf("expected unknown kid rejection")
	}

	expired := signAgentToken(
		t,
		priv,
		CountersigBundleKID,
		"agent-123",
		"org-456",
		CountersigIssuer,
		CountersigAudience,
		time.Now().Add(-1*time.Minute),
	)
	if _, verifyErr := verifier.VerifyAgentJWT(context.Background(), expired); verifyErr == nil ||
		!strings.Contains(verifyErr.Error(), "expired") {
		t.Fatalf("expected expired token rejection, got %v", verifyErr)
	}
}

func TestVerifyAgentJWT_RejectsTamperedSignatureAndEmptyJWKS(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	verifier, server := makeJWKSVerifier(t, []jose.JSONWebKey{
		{Key: pub, KeyID: CountersigBundleKID, Algorithm: string(jose.EdDSA), Use: "sig"},
	})
	defer server.Close()

	token := signAgentToken(
		t,
		priv,
		CountersigBundleKID,
		"agent-123",
		"org-456",
		CountersigIssuer,
		CountersigAudience,
		time.Now().Add(5*time.Minute),
	)
	parts := strings.Split(token, ".")
	if len(parts) != 3 || len(parts[2]) < 2 {
		t.Fatalf("unexpected jwt format")
	}
	mutatedSig := "A" + parts[2][1:]
	if parts[2][0] == 'A' {
		mutatedSig = "B" + parts[2][1:]
	}
	tampered := parts[0] + "." + parts[1] + "." + mutatedSig
	if _, verifyErr := verifier.VerifyAgentJWT(context.Background(), tampered); verifyErr == nil {
		t.Fatalf("expected signature verification failure for tampered token")
	}

	emptyVerifier, emptyServer := makeJWKSVerifier(t, []jose.JSONWebKey{})
	defer emptyServer.Close()
	if _, verifyErr := emptyVerifier.VerifyAgentJWT(context.Background(), token); verifyErr == nil {
		t.Fatalf("expected empty jwks rejection")
	}
}
