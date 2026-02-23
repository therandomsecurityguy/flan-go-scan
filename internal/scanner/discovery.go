package scanner

import (
	"fmt"
	"net"
	"time"
)

func IsHostAlive(host string, timeout time.Duration) bool {
	for _, port := range []int{80, 443} {
		addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}
