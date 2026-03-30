package scanner

import (
	"bufio"
	"fmt"
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
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
	"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
}

func fetchCloudflareCIDRs() []string {
	client := &http.Client{Timeout: 5 * time.Second}
	var cidrs []string
	for _, endpoint := range []string{
		"https://www.cloudflare.com/ips-v4",
		"https://www.cloudflare.com/ips-v6",
	} {
		fetched, err := fetchCIDRsFromURL(client, endpoint)
		if err != nil {
			slog.Warn("failed to fetch Cloudflare CIDRs", "url", endpoint, "err", err)
			return cloudflareCIDRsFallback
		}
		cidrs = append(cidrs, fetched...)
	}
	if len(cidrs) == 0 {
		slog.Warn("Cloudflare CIDR fetch returned empty, using fallback")
		return cloudflareCIDRsFallback
	}
	slog.Info("fetched Cloudflare CIDRs", "count", len(cidrs))
	return cidrs
}

func fetchCIDRsFromURL(client *http.Client, endpoint string) ([]string, error) {
	resp, err := client.Get(endpoint)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s", resp.Status)
	}

	var cidrs []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			cidrs = append(cidrs, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return cidrs, nil
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
