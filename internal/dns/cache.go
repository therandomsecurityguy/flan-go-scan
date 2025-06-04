package dns

import (
	"net"
	"sync"
	"time"
)

type DNSCache struct {
	entries map[string]cacheEntry
	mu      sync.RWMutex
	ttl     time.Duration
}

type cacheEntry struct {
	ips     []net.IP
	expires time.Time
}

func NewDNSCache(ttl time.Duration) *DNSCache {
	return &DNSCache{
		entries: make(map[string]cacheEntry),
		ttl:     ttl,
	}
}

func (c *DNSCache) Lookup(host string) ([]net.IP, error) {
	c.mu.RLock()
	entry, exists := c.entries[host]
	c.mu.RUnlock()
	if exists && time.Now().Before(entry.expires) {
		return entry.ips, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.entries[host] = cacheEntry{
		ips:     ips,
		expires: time.Now().Add(c.ttl),
	}
	c.mu.Unlock()
	return ips, nil
}
