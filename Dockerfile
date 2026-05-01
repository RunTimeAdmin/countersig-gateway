# Build stage: compile Caddy with the Countersig module embedded
FROM caddy:2.8.4-builder AS builder

# Add the Countersig module + the standard forwardproxy module needed
# for the HTTPS_PROXY deployment pattern.
RUN xcaddy build \
    --with github.com/RunTimeAdmin/countersig-gateway/module \
    --with github.com/caddyserver/forwardproxy@caddy2

# Runtime stage
FROM caddy:2.8.4

# Replace the default caddy binary with our custom build that includes
# the Countersig policy module.
COPY --from=builder /usr/bin/caddy /usr/bin/caddy

# Default port for forward proxy / reverse proxy
EXPOSE 8080

# Healthcheck hits the metrics endpoint (returns 200 if the listener
# is up, even if metrics_path is not configured at this exact path).
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/metrics || exit 1

CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
