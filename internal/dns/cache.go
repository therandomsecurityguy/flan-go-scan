package dns

import (
	"context"
	"errors"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

type DNSCache struct {
	entries       map[string]cacheEntry
	mu            sync.Mutex
	ttl           time.Duration
	lookupTimeout time.Duration
	resolvers     []resolverEndpoint
	stats         DNSStats
}

type cacheEntry struct {
	ips     []net.IP
	expires time.Time
}

type resolverEndpoint struct {
	name     string
	resolver *net.Resolver
}

type DNSStats struct {
	Lookups          int64 `json:"lookups"`
	CacheHits        int64 `json:"cache_hits"`
	CacheMisses      int64 `json:"cache_misses"`
	PrimaryFailures  int64 `json:"primary_failures"`
	FallbackAttempts int64 `json:"fallback_attempts"`
	FallbackSuccess  int64 `json:"fallback_success"`
	LookupFailures   int64 `json:"lookup_failures"`
}

const defaultLookupTimeout = 3 * time.Second

func NewDNSCache(ttl, lookupTimeout time.Duration, primaryResolver string, fallbackResolvers []string) *DNSCache {
	if lookupTimeout <= 0 {
		lookupTimeout = defaultLookupTimeout
	}
	return &DNSCache{
		entries:       make(map[string]cacheEntry),
		ttl:           ttl,
		lookupTimeout: lookupTimeout,
		resolvers:     buildResolverChain(primaryResolver, fallbackResolvers, lookupTimeout),
	}
}

func (c *DNSCache) Lookup(host string) ([]net.IP, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, &net.DNSError{Err: "empty host"}
	}

	c.mu.Lock()
	c.stats.Lookups++
	entry, exists := c.entries[host]
	if exists && time.Now().Before(entry.expires) {
		c.stats.CacheHits++
		c.mu.Unlock()
		return entry.ips, nil
	}
	if exists {
		delete(c.entries, host)
	}
	c.stats.CacheMisses++
	resolvers := append([]resolverEndpoint(nil), c.resolvers...)
	lookupTimeout := c.lookupTimeout
	c.mu.Unlock()

	var lastErr error
	for i, resolver := range resolvers {
		if i > 0 {
			c.mu.Lock()
			c.stats.FallbackAttempts++
			c.mu.Unlock()
		}

		lookupCtx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
		addrs, err := resolver.resolver.LookupIPAddr(lookupCtx, host)
		cancel()
		if err != nil {
			lastErr = err
			if i == 0 {
				c.mu.Lock()
				c.stats.PrimaryFailures++
				c.mu.Unlock()
			}
			if i == len(resolvers)-1 || !shouldFallback(err) {
				break
			}
			continue
		}

		ips := normalizeIPAddrs(addrs)
		if len(ips) == 0 {
			lastErr = &net.DNSError{Err: "no ips", Name: host}
			break
		}

		c.mu.Lock()
		if i > 0 {
			c.stats.FallbackSuccess++
		}
		c.entries[host] = cacheEntry{
			ips:     ips,
			expires: time.Now().Add(c.ttl),
		}
		c.mu.Unlock()
		return ips, nil
	}

	c.mu.Lock()
	c.stats.LookupFailures++
	c.mu.Unlock()
	if lastErr == nil {
		lastErr = &net.DNSError{
			Err:  "lookup failed",
			Name: host,
		}
	}
	return nil, lastErr
}

func (c *DNSCache) Stats() DNSStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats
}

func buildResolverChain(primaryResolver string, fallbackResolvers []string, timeout time.Duration) []resolverEndpoint {
	seen := make(map[string]struct{})
	var chain []resolverEndpoint

	add := func(raw string) {
		addr := normalizeResolverAddr(raw)
		if addr == "" {
			return
		}
		if _, exists := seen[addr]; exists {
			return
		}
		seen[addr] = struct{}{}
		if addr == "system" {
			chain = append(chain, resolverEndpoint{
				name:     "system",
				resolver: net.DefaultResolver,
			})
			return
		}
		chain = append(chain, resolverEndpoint{
			name:     addr,
			resolver: udpResolver(addr, timeout),
		})
	}

	if normalizeResolverAddr(primaryResolver) == "" {
		add("system")
	} else {
		add(primaryResolver)
	}
	for _, resolver := range fallbackResolvers {
		add(resolver)
	}
	if len(chain) == 0 {
		add("system")
	}
	return chain
}

func normalizeResolverAddr(resolver string) string {
	resolver = strings.TrimSpace(strings.ToLower(resolver))
	if resolver == "" {
		return ""
	}
	if resolver == "system" {
		return "system"
	}
	if _, _, err := net.SplitHostPort(resolver); err == nil {
		return resolver
	}
	if strings.Count(resolver, ":") > 1 && !strings.HasPrefix(resolver, "[") {
		return net.JoinHostPort(resolver, "53")
	}
	if !strings.Contains(resolver, ":") {
		return net.JoinHostPort(resolver, "53")
	}
	return resolver
}

func udpResolver(addr string, timeout time.Duration) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "udp", addr)
		},
	}
}

func normalizeIPAddrs(addrs []net.IPAddr) []net.IP {
	seen := make(map[string]struct{}, len(addrs))
	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		if addr.IP == nil {
			continue
		}
		ip := addr.IP.String()
		if _, exists := seen[ip]; exists {
			continue
		}
		seen[ip] = struct{}{}
		ips = append(ips, net.ParseIP(ip))
	}
	sort.Slice(ips, func(i, j int) bool {
		return ips[i].String() < ips[j].String()
	})
	return ips
}

func shouldFallback(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return false
	}
	return !strings.Contains(strings.ToLower(err.Error()), "no such host")
}
