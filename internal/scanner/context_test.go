package scanner

import "testing"

func TestCheckPoliciesDedupesViolations(t *testing.T) {
	passwordsDisabled := false
	sc := &ScanContext{}
	sc.Policies.AllowedPorts = []int{80, 443}
	sc.Policies.SSHPasswordAuth = &passwordsDisabled

	results := []ScanResult{
		{
			Host:     "1.1.1.1",
			Hostname: "api.together.ai",
			Port:     22,
			Service:  "ssh",
			Metadata: []byte(`{"passwordAuthEnabled":true}`),
		},
		{
			Host:     "1.1.1.2",
			Hostname: "api.together.ai",
			Port:     22,
			Service:  "ssh",
			Metadata: []byte(`{"passwordAuthEnabled":true}`),
		},
	}

	violations := CheckPolicies(results, sc)
	if len(violations) != 2 {
		t.Fatalf("expected 2 unique violations, got %d: %#v", len(violations), violations)
	}
	if violations[0].Detail != "port 22 not in allowed_ports policy" {
		t.Fatalf("unexpected first violation: %#v", violations[0])
	}
	if violations[1].Detail != "SSH password authentication enabled; policy requires key-based auth only" {
		t.Fatalf("unexpected second violation: %#v", violations[1])
	}
}
