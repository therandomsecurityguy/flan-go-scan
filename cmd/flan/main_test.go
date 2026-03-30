package main

import (
	"net"
	"testing"
	"time"

	"github.com/therandomsecurityguy/flan-go-scan/internal/config"
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

func TestSelectKubernetesOptions(t *testing.T) {
	cfg := &config.Config{}

	opts, enabled := selectKubernetesOptions(map[string]bool{}, cfg, "", "", false, "", "", false)
	if enabled {
		t.Fatal("did not expect kubernetes mode enabled by default")
	}
	if opts.kubeconfig != "" || opts.context != "" || opts.inventory || opts.inventoryOut != "" || opts.diffAgainst != "" || opts.deltaOnly {
		t.Fatalf("unexpected default kube opts: %+v", opts)
	}

	cfg.Kubernetes.Enabled = true
	cfg.Kubernetes.Kubeconfig = "/tmp/config"
	cfg.Kubernetes.Context = "prod"
	cfg.Kubernetes.Inventory = true
	opts, enabled = selectKubernetesOptions(map[string]bool{}, cfg, "", "", false, "", "", false)
	if !enabled {
		t.Fatal("expected kubernetes mode enabled from config")
	}
	if opts.kubeconfig != "/tmp/config" || opts.context != "prod" || !opts.inventory {
		t.Fatalf("unexpected config kube opts: %+v", opts)
	}
}

func TestDiscoverAliveTargetsUsesExactPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	targets := []scanTarget{{
		IP:            "127.0.0.1",
		Port:          port,
		ExactPort:     true,
		CheckpointKey: "127.0.0.1",
	}}

	alive := discoverAliveTargets(t.Context(), targets, []int{1}, 1, time.Second)
	if len(alive) != 1 {
		t.Fatalf("expected exact-port target to remain alive, got %d targets", len(alive))
	}
	<-done
}
