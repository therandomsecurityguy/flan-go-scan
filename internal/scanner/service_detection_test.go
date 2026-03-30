package scanner

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestDetectServiceClosedPort(t *testing.T) {
	result := DetectService("127.0.0.1", 1, 100*time.Millisecond)
	if result.Name != "closed" {
		t.Fatalf("expected closed, got %s", result.Name)
	}
}

func TestIsTCPPortOpen(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if !IsTCPPortOpen(ctx, "127.0.0.1", addr.Port, 200*time.Millisecond) {
		t.Fatal("expected open port")
	}
}

func TestProbeTCPPortCanceledContextIsNotDefinitive(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	open, definitive := ProbeTCPPort(ctx, "127.0.0.1", 1, 200*time.Millisecond)
	if open {
		t.Fatal("did not expect canceled probe to report open")
	}
	if definitive {
		t.Fatal("did not expect canceled probe to be treated as definitive")
	}
}
