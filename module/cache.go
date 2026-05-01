package module

import (
	"fmt"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

// CachedDecision is the policy decision plus the time it was cached.
type CachedDecision struct {
	Allowed bool
	Reason  string
	Scope   string
	Mode    string
	Token   string // optional A2A JWT for agent: destinations
	StoredAt time.Time
}

// IsExpired returns true if the cached decision is older than ttl.
func (d *CachedDecision) IsExpired(ttl time.Duration) bool {
	return time.Since(d.StoredAt) > ttl
}

// decisionCache is an LRU cache of policy decisions keyed by
// "agent_id:destination". Entries also have a TTL applied at lookup time.
type decisionCache struct {
	lru *lru.Cache[string, *CachedDecision]
	ttl time.Duration
}

func newDecisionCache(size int, ttl time.Duration) (*decisionCache, error) {
	c, err := lru.New[string, *CachedDecision](size)
	if err != nil {
		return nil, err
	}
	return &decisionCache{lru: c, ttl: ttl}, nil
}

func cacheKey(agentID, destination string) string {
	return fmt.Sprintf("%s:%s", agentID, destination)
}

// Get returns the cached decision and whether it was a hit. A stale
// entry (older than TTL) is treated as a miss but not evicted, so it
// remains available to FailCachedOnly mode during a backend outage.
func (c *decisionCache) Get(agentID, destination string) (*CachedDecision, bool) {
	v, ok := c.lru.Get(cacheKey(agentID, destination))
	if !ok {
		return nil, false
	}
	if v.IsExpired(c.ttl) {
		return v, false
	}
	return v, true
}

// GetStale returns any cached decision regardless of TTL. Used by the
// cached_only fail mode when the backend is unreachable.
func (c *decisionCache) GetStale(agentID, destination string) (*CachedDecision, bool) {
	return c.lru.Get(cacheKey(agentID, destination))
}

// Put stores a decision. StoredAt is set to now.
func (c *decisionCache) Put(agentID, destination string, d *CachedDecision) {
	d.StoredAt = time.Now()
	c.lru.Add(cacheKey(agentID, destination), d)
}

// Len returns the current cache size.
func (c *decisionCache) Len() int {
	return c.lru.Len()
}
