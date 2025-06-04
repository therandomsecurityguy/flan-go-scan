package scanner

import (
	"fmt"
	"net"
	"strings"
	"time"
)

type ScanResult struct {
	Host            string
	Port            int
	Protocol        string
	Service         string
	Banner          string
	TLS             bool
	Vulnerabilities []string
}

func ScanTCP(host string, port int, timeout time.Duration) (bool, string) {
	addr := fmt.Sprintf("%s:%d", host, port)
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
	addr := fmt.Sprintf("%s:%d", host, port)
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

func DetectService(port int, banner string, tls bool) string {
	if tls {
		return "https"
	}
	switch port {
	case 22:
		return "ssh"
	case 80:
		return "http"
	case 443:
		return "https"
	case 53:
		return "dns"
	}
	if strings.Contains(strings.ToLower(banner), "ftp") {
		return "ftp"
	}
	if strings.Contains(strings.ToLower(banner), "ssh") {
		return "ssh"
	}
	return "unknown"
}
