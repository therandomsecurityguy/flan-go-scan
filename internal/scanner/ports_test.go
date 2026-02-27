package scanner

import (
	"testing"
)

func TestTopPortsSizes(t *testing.T) {
	if len(TopPorts100) < 95 || len(TopPorts100) > 105 {
		t.Errorf("TopPorts100 has %d entries, expected ~100", len(TopPorts100))
	}
	if len(TopPorts1000) < 950 || len(TopPorts1000) > 1050 {
		t.Errorf("TopPorts1000 has %d entries, expected ~1000", len(TopPorts1000))
	}
}

func TestTopPortsNoDuplicates(t *testing.T) {
	for name, ports := range map[string][]int{"top100": TopPorts100, "top1000": TopPorts1000, "subdomain-web": SubdomainWebPorts} {
		seen := make(map[int]bool)
		for _, p := range ports {
			if seen[p] {
				t.Errorf("%s: duplicate port %d", name, p)
			}
			seen[p] = true
		}
	}
}

func TestSubdomainWebPortsBaseline(t *testing.T) {
	if len(SubdomainWebPorts) < 2 {
		t.Fatalf("unexpected subdomain web ports length: %d", len(SubdomainWebPorts))
	}
	seen := make(map[int]bool, len(SubdomainWebPorts))
	for _, p := range SubdomainWebPorts {
		seen[p] = true
	}
	if !seen[80] || !seen[443] {
		t.Fatalf("expected subdomain web ports to include 80 and 443: %v", SubdomainWebPorts)
	}
}
