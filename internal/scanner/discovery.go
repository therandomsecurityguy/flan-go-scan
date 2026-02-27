package scanner

import (
	"context"
	"fmt"
	"net"
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

	for _, port := range candidatePorts {
		if ctx.Err() != nil {
			return false
		}
		addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
		dialer := net.Dialer{Timeout: timeout}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			conn.Close()
			return true
		}
	}

	return false
}
