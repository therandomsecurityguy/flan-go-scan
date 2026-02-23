package scanner

import (
	"net"
	"testing"
)

func TestCDNDetectorCloudflareIP(t *testing.T) {
	d := NewCDNDetector()
	if got := d.Detect("104.16.0.1"); got != "cloudflare" {
		t.Fatalf("expected cloudflare, got %q", got)
	}
}

func TestCDNDetectorNonCDNIP(t *testing.T) {
	d := NewCDNDetector()
	if got := d.Detect("8.8.8.8"); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

func TestCDNDetectorInvalidIP(t *testing.T) {
	d := NewCDNDetector()
	if got := d.Detect("not-an-ip"); got != "" {
		t.Fatalf("expected empty for invalid input, got %q", got)
	}
}

func TestCDNDetectorLoadAndDetect(t *testing.T) {
	d := &CDNDetector{networks: make(map[string][]*net.IPNet)}
	d.load("testcdn", []string{"10.0.0.0/8"})
	if got := d.Detect("10.1.2.3"); got != "testcdn" {
		t.Fatalf("expected testcdn, got %q", got)
	}
	if got := d.Detect("192.168.1.1"); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

func TestFetchCloudflareCIDRsFallback(t *testing.T) {
	if len(cloudflareCIDRsFallback) == 0 {
		t.Fatal("fallback list must not be empty")
	}
}

func TestFetchCloudflareCIDRsLive(t *testing.T) {
	cidrs := fetchCloudflareCIDRs()
	if len(cidrs) == 0 {
		t.Fatal("expected CIDRs from live fetch or fallback, got none")
	}
}
