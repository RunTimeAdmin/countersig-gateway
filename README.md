# Countersig Gateway

Network-layer policy enforcement for AI agents registered with [Countersig](https://countersig.com).

This is a Caddy module that sits in front of your AI agents and enforces destination allow-lists at the network layer. Unlike the [`@countersig/policy-client`](https://www.npmjs.com/package/@countersig/policy-client) SDK — which can be bypassed by any code that doesn't route through it — the gateway sees all egress traffic and cannot be circumvented by a compromised agent.

## When to use this

Use the gateway when:
- You need a real security boundary, not a hint
- You're running agents in production with sensitive data access
- Compliance frameworks require enforced egress controls (SOC2, ISO 27001, HIPAA)
- You can't trust every line of code your agent will ever execute

Use the [SDK alone](https://www.npmjs.com/package/@countersig/policy-client) when:
- You're in dev or staging
- You control all the code in the agent
- You want microsecond decision latency without a network hop

The recommended pattern for production is **both**: SDK in the agent for fast feedback during development, gateway in front of the agent for non-bypassable enforcement.

## Architecture

```
┌──────────────┐     HTTPS_PROXY=     ┌──────────────────┐     ┌──────────────────┐
│   AI Agent   │ ───────────────────▶ │ Countersig       │────▶│  Destination     │
│              │     :8080            │ Gateway (Caddy)  │     │  (OpenAI, etc.)  │
└──────────────┘                      └──────────────────┘     └──────────────────┘
                                              │
                                              │ POST /v1/policy/check
                                              ▼
                                      ┌──────────────────┐
                                      │ Countersig API   │
                                      │ (your backend)   │
                                      └──────────────────┘
```

For each request, the gateway:
1. Extracts the destination from the request (forward proxy CONNECT, or `X-Target-Upstream` header for reverse proxy)
2. Verifies the agent's JWT against your Countersig JWKS endpoint
3. Looks up the cached policy decision (LRU + TTL)
4. On cache miss, calls `POST /v1/policy/check` on your Countersig API
5. Allows or denies based on the decision
6. Records metrics and structured logs

## Quick start

### Option 1: Pre-built Docker image

```bash
docker run -d \
  --name countersig-gateway \
  -p 8080:8080 \
  -e COUNTERSIG_GATEWAY_API_KEY=$YOUR_GATEWAY_API_KEY \
  -v $(pwd)/Caddyfile:/etc/caddy/Caddyfile:ro \
  ghcr.io/runtimeadmin/countersig-gateway:latest
```

### Option 2: Build with xcaddy

```bash
xcaddy build \
  --with github.com/RunTimeAdmin/countersig-gateway/module \
  --with github.com/caddyserver/forwardproxy@caddy2

./caddy run --config Caddyfile
```

### Option 3: Build from source

```bash
git clone https://github.com/RunTimeAdmin/countersig-gateway
cd countersig-gateway
go build -o caddy ./cmd/caddy
```

## Configuration

```caddy
{
    order countersig_policy before forward_proxy
}

:8080 {
    countersig_policy {
        api_base        https://api.countersig.com
        api_key         {env.COUNTERSIG_GATEWAY_API_KEY}
        cache_ttl       300
        cache_size      10000
        fail_mode       closed
        require_auth    true
        request_timeout 5s
        metrics_path    /metrics
    }

    forward_proxy {
        basic_auth {env.PROXY_USER} {env.PROXY_PASS}
    }
}
```

### Configuration reference

| Directive | Required | Default | Description |
|---|---|---|---|
| `api_base` | yes | — | Countersig API base URL |
| `api_key` | yes | — | Service API key for the gateway itself |
| `cache_ttl` | no | 300 | Decision cache TTL in seconds |
| `cache_size` | no | 10000 | LRU cache max entries |
| `fail_mode` | no | `closed` | `closed` \| `open` \| `cached_only` |
| `require_auth` | no | `true` | Require valid agent JWT/API key |
| `jwks_url` | no | `{api_base}/.well-known/jwks.json` | JWKS for verifying agent JWTs |
| `request_timeout` | no | `5s` | Timeout for `/policy/check` calls |
| `metrics_path` | no | (disabled) | Prometheus metrics endpoint |

### Fail modes explained

- **`closed`** (recommended): If the policy backend is unreachable, deny all calls. This is the safe default for production.
- **`open`**: If the policy backend is unreachable, allow all calls. Acceptable for dev/staging where availability outranks security.
- **`cached_only`**: If the policy backend is unreachable, serve from cache regardless of TTL. Cache misses are denied. Best middle ground for production deployments that need to survive short backend outages.

### Auth modes

The gateway supports two ways for agents to identify themselves:

**Bearer JWT (recommended):**
```
Authorization: Bearer <countersig-issued-jwt>
```
The gateway verifies the signature against your JWKS endpoint, extracts `agent_id` and `org_id` from the claims, and uses them for the policy check.

**API key fallback:**
```
X-Countersig-Agent: <api-key>
X-Countersig-Agent-Id: <agent-uuid>
```
For runtimes that can't easily set an `Authorization` header. The API key is treated opaquely — the backend validates it on the policy check call, and you can configure your existing API key permissions to constrain what agent IDs each key can act as.

## Deployment patterns

### Forward proxy (recommended)

Agents use the gateway as their `HTTPS_PROXY`. Zero code changes required. See [`examples/forward-proxy/`](examples/forward-proxy/Caddyfile).

```bash
export HTTPS_PROXY=http://gateway:8080
export HTTP_PROXY=http://gateway:8080
# All outbound HTTPS now flows through the gateway
```

### Reverse proxy

Agents call the gateway directly, specifying upstream via `X-Target-Upstream` header. See [`examples/reverse-proxy/`](examples/reverse-proxy/Caddyfile).

### Sidecar

One gateway per agent pod, listening on localhost only. See [`examples/sidecar/`](examples/sidecar/docker-compose.yml).

### Service mesh (Envoy ext_authz)

For customers already running Envoy or Istio, use the `ext_authz` HTTP filter pointed at `/v1/policy/check`. No custom Caddy build required. Documentation pending in v0.2.

## Observability

### Prometheus metrics

When `metrics_path /metrics` is set, the gateway exposes:

```
countersig_gateway_allowed_total{reason, mode}
countersig_gateway_denied_total{reason, scope, mode}
countersig_gateway_cache_hits_total
countersig_gateway_cache_misses_total
countersig_gateway_auth_failures_total{reason}
countersig_gateway_backend_errors_total{fallback}
countersig_gateway_check_latency_seconds (histogram)
```

### Structured logs

Caddy emits JSON logs by default. The Countersig module writes:
- `info` on each policy denial with `agent_id`, `destination`, `reason`, `scope`
- `warn` on backend call failures with the failure mode applied
- `debug` on unauthenticated allows when `require_auth: false`

Configure log routing through standard Caddy log directives.

### Audit trail

Every policy decision (allow and deny) flows through the Countersig backend's audit hash chain. The gateway is intentionally not the source of truth for audit records — your backend `audit_logs` table is. Gateway logs and metrics are operational telemetry, not compliance evidence.

## Security model

### What the gateway protects against

- **Compromised agent code:** A malicious or buggy agent that imports `node-fetch` directly cannot bypass the gateway. The HTTPS_PROXY env var is a system-level setting; subverting it requires container escape.
- **Unauthorized destinations:** Calls to non-whitelisted destinations are denied at the network layer regardless of what the agent code attempts.
- **Stolen agent credentials within their authorized scope:** A leaked JWT can only access destinations in that agent's policy bundle.

### What the gateway does NOT protect against

- **Container escape:** If an attacker breaks out of the agent container, they can configure outbound traffic to bypass the gateway. Use container hardening, kernel sandboxing, and network policy as defense in depth.
- **DNS exfiltration:** The gateway sees HTTP/HTTPS. DNS queries to attacker-controlled nameservers can leak data outside the gateway's view. Use DNS egress filtering separately.
- **Side-channel data leakage:** An agent that's allowed to call OpenAI can still send arbitrary data in its OpenAI API request body. Egress allow-listing controls *where*, not *what*.
- **Trust in the agent JWT itself:** If your Countersig backend issues a JWT to a compromised agent, the gateway will honor it. Revocation through your backend remains the source of truth.

### Threat model summary

The gateway raises the bar for adversaries from "any code in the agent process" to "kernel-level container escape." That's a meaningful security improvement, not a panacea. Combine it with container hardening, network policy, and runtime monitoring for defense in depth.

## Performance

Hot path latency on cache hit: <1ms (in-memory lookup, no network).
Hot path latency on cache miss: 20-100ms (single round-trip to Countersig API).

A single gateway instance handles thousands of cached requests per second. For very high traffic, deploy multiple gateway instances behind a load balancer; each instance maintains its own cache.

For agents making thousands of calls per minute to a small set of destinations (typical), the cache hit rate is >99% and per-request overhead is negligible.

## Development

```bash
# Run tests
go test ./module/...

# Build the binary
go build -o caddy ./cmd/caddy

# Run with example config
./caddy run --config examples/forward-proxy/Caddyfile
```

The test suite (`module/handler_test.go`) covers:
- Allow path forwards to next handler
- Deny path returns 403 with reason headers
- Cache hits skip backend calls
- Each fail mode behavior (closed / open / cached_only)
- Header extraction for forward and reverse proxy modes
- Countersig headers stripped on forward
- A2A token injection for `agent:` destinations

## License

MIT

## Links

- Backend: https://github.com/RunTimeAdmin/Countersig-Public
- SDK: https://www.npmjs.com/package/@countersig/policy-client
- Docs: https://countersig.com/docs/POLICY_GATEWAY
