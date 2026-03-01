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
	if len(TopPorts2000) != 2000 {
		t.Errorf("TopPorts2000 has %d entries, expected 2000", len(TopPorts2000))
	}
	if len(TopPorts5000) != 5000 {
		t.Errorf("TopPorts5000 has %d entries, expected 5000", len(TopPorts5000))
	}
}

func TestTopPortsNoDuplicates(t *testing.T) {
	for name, ports := range map[string][]int{
		"top100":        TopPorts100,
		"top1000":       TopPorts1000,
		"top2000":       TopPorts2000,
		"top5000":       TopPorts5000,
		"subdomain-web": SubdomainWebPorts,
	} {
		seen := make(map[int]bool)
		for _, p := range ports {
			if seen[p] {
				t.Errorf("%s: duplicate port %d", name, p)
			}
			seen[p] = true
		}
	}
}

func TestExpandedTopPortsStartsWithTop1000(t *testing.T) {
	for i, port := range TopPorts1000 {
		if TopPorts2000[i] != port {
			t.Fatalf("TopPorts2000 diverges at index %d: got %d want %d", i, TopPorts2000[i], port)
		}
		if TopPorts5000[i] != port {
			t.Fatalf("TopPorts5000 diverges at index %d: got %d want %d", i, TopPorts5000[i], port)
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
