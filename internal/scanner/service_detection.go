package scanner

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// DetectProtocol tries to identify the service running on a port using protocol handshakes.
func DetectProtocol(host string, port int, timeout time.Duration, results chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		results <- "closed"
		return
	}
	defer conn.Close()

	var service string
	switch port {
	case 21:
		service = detectFTP(conn, timeout)
	case 22:
		service = "ssh"
	case 23:
		service = detectTelnet(conn, timeout)
	case 25, 465, 587:
		service = detectSMTP(conn, timeout)
	case 53:
		service = detectDNS(conn, timeout)
	case 80, 8080:
		service = detectHTTP(conn, timeout)
	case 110:
		service = detectPOP3(conn, timeout)
	case 143, 993:
		service = detectIMAP(conn, timeout)
	case 3306:
		service = detectMySQL(conn, timeout)
	case 5432:
		service = detectPostgres(conn, timeout)
	case 6379:
		service = detectRedis(conn, timeout)
	case 3389:
		service = detectRDP(conn, timeout)
	default:
		service = detectByBanner(conn, timeout)
	}
	results <- service
}

// --- Protocol-specific detection functions ---

func detectFTP(conn net.Conn, timeout time.Duration) string {
	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err == nil && strings.HasPrefix(string(buf[:n]), "220") {
		return "ftp"
	}
	return "unknown"
}

func detectTelnet(conn net.Conn, timeout time.Duration) string {
	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err == nil && n > 0 && buf[0] == 0xFF {
		return "telnet"
	}
	return "unknown"
}

func detectSMTP(conn net.Conn, timeout time.Duration) string {
	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err == nil && strings.HasPrefix(string(buf[:n]), "220") {
		return "smtp"
	}
	return "unknown"
}

func detectDNS(conn net.Conn, timeout time.Duration) string {
	// TCP DNS detection: send a standard DNS query
	query := []byte{
		0x00, 0x1c, // Length
		0x12, 0x34, // ID
		0x01, 0x00, // Standard query
		0x00, 0x01, // QDCOUNT
		0x00, 0x00, // ANCOUNT
		0x00, 0x00, // NSCOUNT
		0x00, 0x00, // ARCOUNT
		0x03, 'w', 'w', 'w',
		0x06, 'g', 'o', 'o', 'g', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,       // null terminator
		0x00, 0x01, // Type A
		0x00, 0x01, // Class IN
	}
	conn.Write(query)
	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err == nil && n > 0 && buf[2] == 0x12 && buf[3] == 0x34 {
		return "dns"
	}
	return "unknown"
}

func detectHTTP(conn net.Conn, timeout time.Duration) string {
	fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\n\r\n")
	conn.SetReadDeadline(time.Now().Add(timeout))
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "HTTP/") {
			return "http"
		}
	}
	return "unknown"
}

func detectPOP3(conn net.Conn, timeout time.Duration) string {
	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err == nil && strings.HasPrefix(string(buf[:n]), "+OK") {
		return "pop3"
	}
	return "unknown"
}

func detectIMAP(conn net.Conn, timeout time.Duration) string {
	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err == nil && strings.Contains(string(buf[:n]), "* OK") {
		return "imap"
	}
	return "unknown"
}

func detectMySQL(conn net.Conn, timeout time.Duration) string {
	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err == nil && n > 0 && buf[0] == 0x0a {
		return "mysql"
	}
	return "unknown"
}

func detectPostgres(conn net.Conn, timeout time.Duration) string {
	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err == nil && strings.Contains(string(buf[:n]), "PostgreSQL") {
		return "postgresql"
	}
	return "unknown"
}

func detectRedis(conn net.Conn, timeout time.Duration) string {
	conn.SetDeadline(time.Now().Add(timeout))
	conn.Write([]byte("PING\r\n"))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err == nil && strings.HasPrefix(string(buf[:n]), "+PONG") {
		return "redis"
	}
	return "unknown"
}

func detectRDP(conn net.Conn, timeout time.Duration) string {
	conn.SetDeadline(time.Now().Add(timeout))
	rdpNegReq := []byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00}
	conn.Write(rdpNegReq)
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err == nil && n > 0 && buf[0] == 0x03 {
		return "rdp"
	}
	return "unknown"
}

func detectByBanner(conn net.Conn, timeout time.Duration) string {
	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	banner := string(buf[:n])
	if err == nil {
		if strings.Contains(strings.ToLower(banner), "ftp") {
			return "ftp"
		}
		if strings.Contains(strings.ToLower(banner), "ssh") {
			return "ssh"
		}
		if strings.Contains(strings.ToLower(banner), "smtp") {
			return "smtp"
		}
		if strings.Contains(strings.ToLower(banner), "http") {
			return "http"
		}
	}
	return "unknown"
}
