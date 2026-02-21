package scanner

import (
	"fmt"
	"net"
	"time"
)

type ScanResult struct {
	Host            string     `json:"host"`
	Port            int        `json:"port"`
	Protocol        string     `json:"protocol"`
	Service         string     `json:"service"`
	Banner          string     `json:"banner"`
	TLS             *TLSResult `json:"tls,omitempty"`
	Vulnerabilities []string   `json:"vulnerabilities,omitempty"`
}

func ScanTCP(host string, port int, timeout time.Duration) (bool, string) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false, ""
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	return true, string(buf[:n])
}

func ScanUDP(host string, port int, timeout time.Duration) (bool, string) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return false, ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	conn.Write([]byte("PROBE"))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return false, ""
	}
	return true, string(buf[:n])
}
