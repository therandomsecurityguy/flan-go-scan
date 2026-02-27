package main

import (
	"testing"
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
