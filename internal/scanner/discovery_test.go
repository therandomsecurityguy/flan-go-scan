package scanner

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestIsHostAliveUsesScanPorts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	defer func() {
		ln.Close()
		<-done
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	if !IsHostAlive(context.Background(), "127.0.0.1", []int{port}, 200*time.Millisecond) {
		t.Fatalf("expected host to be alive on port %d", port)
	}
}

func TestIsHostAliveRespectsContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if IsHostAlive(ctx, "127.0.0.1", []int{65535}, 2*time.Second) {
		t.Fatal("expected canceled context to short-circuit discovery")
	}
}
