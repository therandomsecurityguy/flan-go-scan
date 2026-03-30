package scanner

import (
	"net"
	"testing"
)

func TestCDNDetectorCloudflareIP(t *testing.T) {
	d := &CDNDetector{networks: make(map[string][]*net.IPNet)}
	d.load("cloudflare", cloudflareCIDRsFallback)
	if got := d.Detect("104.16.0.1"); got != "cloudflare" {
		t.Fatalf("expected cloudflare, got %q", got)
	}
}
