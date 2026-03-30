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
			_ = conn.Close()
		}
	}()
	defer func() {
		_ = ln.Close()
		<-done
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	if !IsHostAlive(context.Background(), "127.0.0.1", []int{port}, 200*time.Millisecond) {
		t.Fatalf("expected host to be alive on port %d", port)
	}
}
