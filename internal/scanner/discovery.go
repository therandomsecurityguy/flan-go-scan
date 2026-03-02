package scanner

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

func IsHostAlive(ctx context.Context, host string, ports []int, timeout time.Duration) bool {
	seen := make(map[int]struct{})
	candidatePorts := make([]int, 0, 12)
	addPort := func(port int) {
		if port < 1 || port > 65535 {
			return
		}
		if _, ok := seen[port]; ok {
			return
		}
		seen[port] = struct{}{}
		candidatePorts = append(candidatePorts, port)
	}

	addPort(80)
	addPort(443)
	for _, port := range ports {
		addPort(port)
		if len(candidatePorts) >= 12 {
			break
		}
	}

	const maxParallel = 6
	sem := make(chan struct{}, maxParallel)
	var wg sync.WaitGroup
	found := make(chan struct{})
	done := make(chan struct{})
	var once sync.Once

	for _, port := range candidatePorts {
		wg.Add(1)
		go func(port int) {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				wg.Done()
				return
			}
			defer func() {
				<-sem
				wg.Done()
			}()

			select {
			case <-ctx.Done():
				return
			default:
			}

			addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
			dialer := net.Dialer{Timeout: timeout}
			conn, err := dialer.DialContext(ctx, "tcp", addr)
			if err == nil {
				conn.Close()
				once.Do(func() { close(found) })
			}
		}(port)
	}

	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-found:
		return true
	case <-done:
		return false
	case <-ctx.Done():
		return false
	}
}
