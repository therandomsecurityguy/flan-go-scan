package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/therandomsecurityguy/flan-go-scan/internal/config"
	"github.com/therandomsecurityguy/flan-go-scan/internal/output"
	"github.com/therandomsecurityguy/flan-go-scan/internal/scanner"
)

func TestParsePorts(t *testing.T) {
	ports, err := parsePorts("80,443,1000-1002")
	if err != nil {
		t.Fatalf("parsePorts returned error: %v", err)
	}
	if len(ports) != 5 {
		t.Fatalf("expected 5 ports, got %d (%v)", len(ports), ports)
	}
	if ports[0] != 80 || ports[1] != 443 || ports[2] != 1000 || ports[4] != 1002 {
		t.Fatalf("unexpected parsed ports: %v", ports)
	}
}

func TestParsePortsRejectsInvalidRange(t *testing.T) {
	if _, err := parsePorts("0-10"); err == nil {
		t.Fatal("expected invalid range to return an error")
	}
}

func TestParsePortsRejectsInvalidCharacters(t *testing.T) {
	if _, err := parsePorts("80,abc"); err == nil {
		t.Fatal("expected invalid characters to return an error")
	}
	if _, err := parsePorts("80-90-100"); err == nil {
		t.Fatal("expected malformed range to return an error")
	}
}

func TestPickHonorsExplicitFlags(t *testing.T) {
	long := "long"
	short := "short"
	def := "default"

	val := pick(map[string]bool{"config": true}, "config", &long, "c", &short, def)
	if val != "long" {
		t.Fatalf("expected long value, got %q", val)
	}
	val = pick(map[string]bool{"c": true}, "config", &long, "c", &short, def)
	if val != "short" {
		t.Fatalf("expected short value, got %q", val)
	}
	val = pick(map[string]bool{}, "config", &long, "c", &short, def)
	if val != def {
		t.Fatalf("expected default value, got %q", val)
	}
}

func TestSplitCSV(t *testing.T) {
	values := splitCSV(" crtsh,ANUBIS,crtsh , ,digitorus ")
	want := []string{"crtsh", "ANUBIS", "digitorus"}
	if !reflect.DeepEqual(values, want) {
		t.Fatalf("unexpected parsed CSV values: got %v want %v", values, want)
	}
}

func TestNormalizeDiscoveredHosts(t *testing.T) {
	in := []string{"Example.com", "example.com.", "127.0.0.1", " 127.0.0.1 ", "", " api.example.com "}
	got := normalizeDiscoveredHosts(in)
	want := []string{"example.com", "127.0.0.1", "api.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected normalized hosts: got %v want %v", got, want)
	}
}

func TestSelectScanPortsDomainProfileDefault(t *testing.T) {
	cfg := &config.Config{}
	cfg.Scan.Ports = "22,80"
	cfg.Subdomain.PortProfile = "web"

	ports, err := selectScanPorts(true, map[string]bool{}, "", "", cfg)
	if err != nil {
		t.Fatalf("selectScanPorts returned error: %v", err)
	}
	if !reflect.DeepEqual(ports, scanner.SubdomainWebPorts) {
		t.Fatalf("unexpected web profile ports: got %v want %v", ports, scanner.SubdomainWebPorts)
	}
}

func TestSelectScanPortsDomainProfileOverrideByTopPorts(t *testing.T) {
	cfg := &config.Config{}
	cfg.Scan.Ports = "22,80"
	cfg.Subdomain.PortProfile = "web"

	ports, err := selectScanPorts(true, map[string]bool{"top-ports": true}, "100", "", cfg)
	if err != nil {
		t.Fatalf("selectScanPorts returned error: %v", err)
	}
	if len(ports) != len(scanner.TopPorts100) {
		t.Fatalf("unexpected top-ports selection length: got %d want %d", len(ports), len(scanner.TopPorts100))
	}
}

func TestSelectScanPortsTopPortsProfiles(t *testing.T) {
	cfg := &config.Config{}
	cfg.Scan.Ports = "22,80"
	cfg.Subdomain.PortProfile = "web"

	tests := map[string]int{
		"1000": len(scanner.TopPorts1000),
		"2000": len(scanner.TopPorts2000),
		"5000": len(scanner.TopPorts5000),
	}

	for value, expected := range tests {
		ports, err := selectScanPorts(true, map[string]bool{"top-ports": true}, value, "", cfg)
		if err != nil {
			t.Fatalf("selectScanPorts(%s) returned error: %v", value, err)
		}
		if len(ports) != expected {
			t.Fatalf("unexpected top-ports selection length for %s: got %d want %d", value, len(ports), expected)
		}
	}
}

func TestSelectScanPortsInvalidDomainProfile(t *testing.T) {
	cfg := &config.Config{}
	cfg.Scan.Ports = "22,80"
	cfg.Subdomain.PortProfile = "invalid-profile"

	if _, err := selectScanPorts(true, map[string]bool{}, "", "", cfg); err == nil {
		t.Fatal("expected invalid subdomain profile to return an error")
	}
}

func TestHeaderInspectionEligible(t *testing.T) {
	okMeta, err := json.Marshal(map[string]any{"statusCode": 200})
	if err != nil {
		t.Fatalf("marshal ok meta: %v", err)
	}
	notFoundMeta, err := json.Marshal(map[string]any{"statusCode": 404})
	if err != nil {
		t.Fatalf("marshal 404 meta: %v", err)
	}

	eligible, status := headerInspectionEligible(scanner.ScanResult{Metadata: okMeta})
	if !eligible || status != 200 {
		t.Fatalf("expected eligible for 200, got eligible=%v status=%d", eligible, status)
	}

	eligible, status = headerInspectionEligible(scanner.ScanResult{Metadata: notFoundMeta})
	if eligible || status != 404 {
		t.Fatalf("expected ineligible for 404, got eligible=%v status=%d", eligible, status)
	}
}

func TestEnforceScanGuardrails(t *testing.T) {
	cfg := &config.Config{}
	cfg.Scan.MaxTargets = 10
	cfg.Scan.MaxPortsHost = 100
	cfg.Scan.MaxDuration = 5 * time.Minute

	if err := enforceScanGuardrails(5, 80, cfg); err != nil {
		t.Fatalf("expected guardrails pass, got %v", err)
	}
	if err := enforceScanGuardrails(11, 80, cfg); err == nil {
		t.Fatal("expected target guardrail violation")
	}
	if err := enforceScanGuardrails(5, 101, cfg); err == nil {
		t.Fatal("expected port guardrail violation")
	}
}

func TestShouldStoreResults(t *testing.T) {
	if !shouldStoreResults(nil, false, false, nil, "") {
		t.Fatal("expected storing results when no jsonl writer is used")
	}
	if !shouldStoreResults(&output.JSONLWriter{}, true, false, nil, "") {
		t.Fatal("expected storing results when --analyze is enabled")
	}
	if !shouldStoreResults(&output.JSONLWriter{}, false, false, &scanner.ScanContext{}, "") {
		t.Fatal("expected storing results when policy context is loaded")
	}
	if shouldStoreResults(&output.JSONLWriter{}, false, true, nil, "") {
		t.Fatal("did not expect storing results in pretty mode without Together API key")
	}
	if !shouldStoreResults(&output.JSONLWriter{}, false, true, nil, "key-set") {
		t.Fatal("expected storing results in pretty mode with Together API key")
	}
}

func TestIsTransientAPIValidationError(t *testing.T) {
	if !isTransientAPIValidationError(fmt.Errorf("failed: context deadline exceeded")) {
		t.Fatal("expected deadline errors to be transient")
	}
	if !isTransientAPIValidationError(fmt.Errorf("dial tcp: connection refused")) {
		t.Fatal("expected connection errors to be transient")
	}
	if isTransientAPIValidationError(fmt.Errorf("failed to validate TOGETHER_API_KEY: unauthorized")) {
		t.Fatal("did not expect authorization failures to be transient")
	}
}

func TestSummarizeAnalysisError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "payment required", err: fmt.Errorf("together API call failed: 402 Payment Required"), want: "Together API billing or credit limit issue"},
		{name: "unauthorized", err: fmt.Errorf("together API call failed: 401 Unauthorized"), want: "Together API authentication failed"},
		{name: "forbidden", err: fmt.Errorf("together API call failed: 403 Forbidden"), want: "Together API access denied"},
		{name: "rate limited", err: fmt.Errorf("together API call failed: 429 Too Many Requests"), want: "Together API rate limited the request"},
		{name: "generic", err: fmt.Errorf("dial tcp timeout"), want: "Together AI request failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := summarizeAnalysisError(tt.err); got != tt.want {
				t.Fatalf("unexpected summary: got %q want %q", got, tt.want)
			}
		})
	}
}

func TestDisplaySecurityHeaderFindingsSuppressesInternalProbeNoise(t *testing.T) {
	res := scanner.ScanResult{
		Hostname: "internal-api.example.net",
		Service:  "http",
		Version:  "awselb/2.0",
		SecurityHeaders: []scanner.HeaderFinding{
			{Header: "HTTP Probe", Severity: "LOW", Detail: "header inspection failed: read tcp 1.2.3.4:123->5.6.7.8:443: read: connection reset by peer"},
			{Header: "Content-Security-Policy", Severity: "MEDIUM", Detail: "missing CSP"},
		},
	}

	findings := displaySecurityHeaderFindings(res)
	if len(findings) != 1 {
		t.Fatalf("expected one visible finding, got %d: %#v", len(findings), findings)
	}
	if findings[0].Header != "Content-Security-Policy" {
		t.Fatalf("unexpected visible finding: %#v", findings[0])
	}
}

func TestDisplaySecurityHeaderFindingsKeepsPublicProbeNoise(t *testing.T) {
	res := scanner.ScanResult{
		Hostname: "api.example.net",
		Service:  "http",
		SecurityHeaders: []scanner.HeaderFinding{
			{Header: "HTTP Probe", Severity: "LOW", Detail: "header inspection failed: Get \"http://1.2.3.4:80/\": context deadline exceeded"},
		},
	}

	findings := displaySecurityHeaderFindings(res)
	if len(findings) != 1 {
		t.Fatalf("expected public probe failure to remain visible, got %#v", findings)
	}
}

func TestDiscoveryOutputTargetsUsesDeltaSelection(t *testing.T) {
	allHosts := []string{"api.example.net", "admin.example.net"}
	selectedHosts := []string{"api.example.net"}

	got := discoveryOutputTargets(allHosts, selectedHosts, true)
	if !reflect.DeepEqual(got, selectedHosts) {
		t.Fatalf("unexpected delta hosts: got %v want %v", got, selectedHosts)
	}

	got = discoveryOutputTargets(allHosts, selectedHosts, false)
	if !reflect.DeepEqual(got, allHosts) {
		t.Fatalf("unexpected full hosts: got %v want %v", got, allHosts)
	}
}
