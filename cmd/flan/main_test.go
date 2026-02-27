package main

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/therandomsecurityguy/flan-go-scan/internal/config"
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
	want := []string{"crtsh", "anubis", "digitorus"}
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
