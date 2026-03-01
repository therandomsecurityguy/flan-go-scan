package dns

import (
	"net"
	"testing"
	"time"
)

func TestNormalizeResolverAddr(t *testing.T) {
	tests := map[string]string{
		"":                     "",
		"system":               "system",
		"1.1.1.1":              "1.1.1.1:53",
		"1.1.1.1:5353":         "1.1.1.1:5353",
		"2606:4700:4700::1111": "[2606:4700:4700::1111]:53",
	}
	for input, want := range tests {
		if got := normalizeResolverAddr(input); got != want {
			t.Fatalf("normalizeResolverAddr(%q)=%q want %q", input, got, want)
		}
	}
}

func TestBuildResolverChain(t *testing.T) {
	chain := buildResolverChain("9.9.9.9:53", []string{"system", "1.1.1.1"}, 500*time.Millisecond)
	if len(chain) != 3 {
		t.Fatalf("expected 3 resolvers in chain, got %d", len(chain))
	}
	if chain[0].name != "9.9.9.9:53" {
		t.Fatalf("unexpected primary resolver: %s", chain[0].name)
	}
	if chain[1].name != "system" {
		t.Fatalf("expected system resolver as first fallback, got %s", chain[1].name)
	}
	if chain[2].name != "1.1.1.1:53" {
		t.Fatalf("unexpected fallback resolver: %s", chain[2].name)
	}
}

func TestDNSCacheCacheHit(t *testing.T) {
	cache := NewDNSCache(1*time.Minute, 250*time.Millisecond, "", nil)
	if _, err := cache.Lookup("localhost"); err != nil {
		t.Fatalf("Lookup localhost failed: %v", err)
	}
	if _, err := cache.Lookup("localhost"); err != nil {
		t.Fatalf("Lookup localhost failed on second call: %v", err)
	}
	stats := cache.Stats()
	if stats.CacheHits == 0 {
		t.Fatal("expected cache hit count to be greater than zero")
	}
}

func TestShouldFallback(t *testing.T) {
	if shouldFallback(&net.DNSError{IsNotFound: true}) {
		t.Fatal("expected not-found DNS errors to skip fallback")
	}
	if !shouldFallback(&net.DNSError{IsTimeout: true}) {
		t.Fatal("expected timeout DNS errors to use fallback")
	}
}
