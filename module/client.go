package module

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// PolicyDecision is the response shape from POST /v1/policy/check.
type PolicyDecision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
	Scope   string `json:"scope"`
	Mode    string `json:"mode"`
	Token   string `json:"token,omitempty"`
}

// policyClient is a thin HTTP client for the Countersig policy API.
type policyClient struct {
	apiBase string
	apiKey  string
	http    *http.Client
}

func newPolicyClient(apiBase, apiKey string, timeout time.Duration) *policyClient {
	return &policyClient{
		apiBase: strings.TrimRight(apiBase, "/"),
		apiKey:  apiKey,
		http: &http.Client{
			Timeout: timeout,
		},
	}
}

// Check calls POST /v1/policy/check with the given agent_id and destination.
// Returns the decision or an error on transport/auth failure.
func (c *policyClient) Check(ctx context.Context, agentID, destination string) (*PolicyDecision, error) {
	body, err := json.Marshal(map[string]string{
		"agent_id":    agentID,
		"destination": destination,
	})
	if err != nil {
		return nil, err
	}

	url := c.apiBase + "/v1/policy/check"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "countersig-gateway/0.1")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("policy/check transport: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("policy/check auth error: HTTP %d", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		// Best-effort body capture for diagnostics
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("policy/check returned %d: %s", resp.StatusCode, strings.TrimSpace(string(buf)))
	}

	var d PolicyDecision
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, fmt.Errorf("decode decision: %w", err)
	}
	if d.Reason == "" || d.Scope == "" || d.Mode == "" {
		return nil, fmt.Errorf("policy/check returned malformed decision")
	}
	return &d, nil
}
