package scanner

import (
	"bufio"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

var cloudflareCIDRsFallback = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
}

func fetchCloudflareCIDRs() []string {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://www.cloudflare.com/ips-v4")
	if err != nil {
		slog.Warn("failed to fetch Cloudflare CIDRs, using fallback", "err", err)
		return cloudflareCIDRsFallback
	}
	defer resp.Body.Close()

	var cidrs []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			cidrs = append(cidrs, line)
		}
	}
	if len(cidrs) == 0 {
		slog.Warn("Cloudflare CIDR fetch returned empty, using fallback")
		return cloudflareCIDRsFallback
	}
	slog.Info("fetched Cloudflare CIDRs", "count", len(cidrs))
	return cidrs
}

type CDNDetector struct {
	networks map[string][]*net.IPNet
}

func NewCDNDetector() *CDNDetector {
	d := &CDNDetector{
		networks: make(map[string][]*net.IPNet),
	}
	d.load("cloudflare", fetchCloudflareCIDRs())
	return d
}

func (d *CDNDetector) load(name string, cidrs []string) {
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		d.networks[name] = append(d.networks[name], ipNet)
	}
}

func (d *CDNDetector) Detect(host string) string {
	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}
	for name, nets := range d.networks {
		for _, n := range nets {
			if n.Contains(ip) {
				return name
			}
		}
	}
	return ""
}
