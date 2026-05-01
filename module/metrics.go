package module

import (
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	metricsOnce sync.Once

	allowedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "countersig",
			Subsystem: "gateway",
			Name:      "allowed_total",
			Help:      "Number of requests allowed by policy",
		},
		[]string{"reason", "mode"},
	)

	deniedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "countersig",
			Subsystem: "gateway",
			Name:      "denied_total",
			Help:      "Number of requests denied by policy",
		},
		[]string{"reason", "scope", "mode"},
	)

	cacheHitsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "countersig",
			Subsystem: "gateway",
			Name:      "cache_hits_total",
			Help:      "Number of policy decisions served from local cache",
		},
	)

	cacheMissesTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "countersig",
			Subsystem: "gateway",
			Name:      "cache_misses_total",
			Help:      "Number of policy decisions that required a backend call",
		},
	)

	authFailuresTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "countersig",
			Subsystem: "gateway",
			Name:      "auth_failures_total",
			Help:      "Number of requests rejected for missing or invalid agent JWT",
		},
		[]string{"reason"},
	)

	backendErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "countersig",
			Subsystem: "gateway",
			Name:      "backend_errors_total",
			Help:      "Number of failed calls to the policy backend",
		},
		[]string{"fallback"},
	)

	checkLatencySeconds = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "countersig",
			Subsystem: "gateway",
			Name:      "check_latency_seconds",
			Help:      "Latency of /policy/check calls",
			Buckets:   prometheus.DefBuckets,
		},
	)
)

func registerMetrics() {
	metricsOnce.Do(func() {
		prometheus.MustRegister(
			allowedTotal,
			deniedTotal,
			cacheHitsTotal,
			cacheMissesTotal,
			authFailuresTotal,
			backendErrorsTotal,
			checkLatencySeconds,
		)
	})
}

// metricsHandler wraps a promhttp handler at a configurable path.
type metricsHandler struct {
	path    string
	handler http.Handler
}

func newMetricsHandler(path string) *metricsHandler {
	registerMetrics()
	return &metricsHandler{
		path:    path,
		handler: promhttp.Handler(),
	}
}

func (m *metricsHandler) Matches(reqPath string) bool {
	return m.path != "" && reqPath == m.path
}

func (m *metricsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.handler.ServeHTTP(w, r)
}
