package dnstools

import (
	"sync"
	"time"
)

type cachedCertNames struct {
	data      *CertNames
	expiresAt time.Time
}

// CTCache provides in-memory caching for Certificate Transparency domain lookups to minimize remote hits.
type CTCache struct {
	mu    sync.RWMutex
	items map[string]cachedCertNames
	ttl   time.Duration
}

// NewCTCache creates a thread-safe in-memory cache for CT domain results.
func NewCTCache(ttl time.Duration) *CTCache {
	return &CTCache{
		items: make(map[string]cachedCertNames),
		ttl:   ttl,
	}
}

// Get retrieves cached CT data if not expired.
func (c *CTCache) Get(domain string) (*CertNames, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, ok := c.items[domain]
	if !ok || time.Now().After(item.expiresAt) {
		return nil, false
	}
	return item.data, true
}

// Set stores CT data with configured TTL.
func (c *CTCache) Set(domain string, data *CertNames) {
	if c == nil || data == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	// Prune expired entries if map grows over 1000 items
	if len(c.items) > 1000 {
		now := time.Now()
		for k, v := range c.items {
			if now.After(v.expiresAt) {
				delete(c.items, k)
			}
		}
	}

	c.items[domain] = cachedCertNames{
		data:      data,
		expiresAt: time.Now().Add(c.ttl),
	}
}
