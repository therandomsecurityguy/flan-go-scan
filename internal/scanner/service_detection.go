package scanner

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"syscall"
	"time"
)

type ServiceResult struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Banner  string `json:"banner,omitempty"`
}

func IsTCPPortOpen(ctx context.Context, host string, port int, timeout time.Duration) bool {
	open, _ := ProbeTCPPort(ctx, host, port, timeout)
	return open
}

func ProbeTCPPort(ctx context.Context, host string, port int, timeout time.Duration) (bool, bool) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	probeTimeout := timeout
	if probeTimeout <= 0 || probeTimeout > time.Second {
		probeTimeout = time.Second
	}
	conn, outcome := dialTCPPort(ctx, addr, probeTimeout)
	if conn != nil {
		_ = conn.Close()
		return true, true
	}
	return false, outcome == tcpDialClosed
}

func DetectService(host string, port int, timeout time.Duration) ServiceResult {
	return DetectServiceContext(context.Background(), host, port, timeout)
}

func DetectServiceContext(ctx context.Context, host string, port int, timeout time.Duration) ServiceResult {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, outcome := dialTCPPort(ctx, addr, timeout)
	if conn == nil {
		if outcome == tcpDialClosed {
			return ServiceResult{Name: "closed"}
		}
		return ServiceResult{Name: "unknown"}
	}
	defer conn.Close()

	switch port {
	case 21:
		return detectFTP(conn, timeout)
	case 22:
		return detectSSH(conn, timeout)
	case 23:
		return detectTelnet(conn, timeout)
	case 25, 465, 587:
		return detectSMTP(conn, timeout)
	case 53:
		return detectDNS(conn, timeout)
	case 80, 443, 8080, 8443:
		return detectHTTP(conn, host, timeout)
	case 110:
		return detectPOP3(conn, timeout)
	case 143, 993:
		return detectIMAP(conn, timeout)
	case 3306:
		return detectMySQL(conn, timeout)
	case 5432:
		return detectPostgres(conn, timeout)
	case 6379:
		return detectRedis(conn, timeout)
	case 3389:
		return detectRDP(conn, timeout)
	default:
		return detectByBanner(conn, timeout)
	}
}

type tcpDialOutcome uint8

const (
	tcpDialUnknown tcpDialOutcome = iota
	tcpDialClosed
	tcpDialOpen
)

func dialTCPPort(ctx context.Context, addr string, timeout time.Duration) (net.Conn, tcpDialOutcome) {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, classifyTCPDialError(err)
	}
	return conn, tcpDialOpen
}

func classifyTCPDialError(err error) tcpDialOutcome {
	if err == nil {
		return tcpDialOpen
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return tcpDialUnknown
	}
	var netErr net.Error
	if errors.As(err, &netErr) && (netErr.Timeout() || netErr.Temporary()) {
		return tcpDialUnknown
	}
	var errno syscall.Errno
	if errors.As(err, &errno) && errno == syscall.ECONNREFUSED {
		return tcpDialClosed
	}
	if strings.Contains(strings.ToLower(err.Error()), "connection refused") {
		return tcpDialClosed
	}
	return tcpDialUnknown
}

func readBanner(conn net.Conn, timeout time.Duration) string {
	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	return string(buf[:n])
}

var sshVersionRe = regexp.MustCompile(`SSH-[\d.]+-(\S+)`)
var smtpVersionRe = regexp.MustCompile(`220\s+\S+\s+(?:ESMTP\s+)?(\S+)`)
var ftpVersionRe = regexp.MustCompile(`220.*?(\S+\s+\d+\.\d+\S*)`)

func detectFTP(conn net.Conn, timeout time.Duration) ServiceResult {
	banner := readBanner(conn, timeout)
	if !strings.HasPrefix(banner, "220") {
		return ServiceResult{Name: "unknown", Banner: banner}
	}
	version := ""
	if m := ftpVersionRe.FindStringSubmatch(banner); len(m) > 1 {
		version = m[1]
	}
	return ServiceResult{Name: "ftp", Version: version, Banner: banner}
}

func detectSSH(conn net.Conn, timeout time.Duration) ServiceResult {
	banner := readBanner(conn, timeout)
	version := ""
	if m := sshVersionRe.FindStringSubmatch(banner); len(m) > 1 {
		version = m[1]
	}
	return ServiceResult{Name: "ssh", Version: version, Banner: strings.TrimSpace(banner)}
}

func detectTelnet(conn net.Conn, timeout time.Duration) ServiceResult {
	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err == nil && n > 0 && buf[0] == 0xFF {
		return ServiceResult{Name: "telnet"}
	}
	return ServiceResult{Name: "unknown"}
}

func detectSMTP(conn net.Conn, timeout time.Duration) ServiceResult {
	banner := readBanner(conn, timeout)
	if !strings.HasPrefix(banner, "220") {
		return ServiceResult{Name: "unknown", Banner: banner}
	}
	version := ""
	if m := smtpVersionRe.FindStringSubmatch(banner); len(m) > 1 {
		version = m[1]
	}
	return ServiceResult{Name: "smtp", Version: version, Banner: banner}
}

func detectDNS(conn net.Conn, timeout time.Duration) ServiceResult {
	query := []byte{
		0x00, 0x1c,
		0x12, 0x34,
		0x01, 0x00,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x03, 'w', 'w', 'w',
		0x06, 'g', 'o', 'o', 'g', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
		0x00, 0x01,
		0x00, 0x01,
	}
	conn.Write(query)
	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err == nil && n > 3 && buf[2] == 0x12 && buf[3] == 0x34 {
		return ServiceResult{Name: "dns"}
	}
	return ServiceResult{Name: "unknown"}
}

func detectHTTP(conn net.Conn, host string, timeout time.Duration) ServiceResult {
	fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", host)
	conn.SetReadDeadline(time.Now().Add(timeout))
	s := bufio.NewScanner(conn)
	var serverVersion string
	for s.Scan() {
		line := s.Text()
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "server:") {
			serverVersion = strings.TrimSpace(line[7:])
		}
	}
	return ServiceResult{Name: "http", Version: serverVersion}
}

func detectPOP3(conn net.Conn, timeout time.Duration) ServiceResult {
	banner := readBanner(conn, timeout)
	if strings.HasPrefix(banner, "+OK") {
		return ServiceResult{Name: "pop3", Banner: banner}
	}
	return ServiceResult{Name: "unknown", Banner: banner}
}

func detectIMAP(conn net.Conn, timeout time.Duration) ServiceResult {
	banner := readBanner(conn, timeout)
	if strings.Contains(banner, "* OK") {
		return ServiceResult{Name: "imap", Banner: banner}
	}
	return ServiceResult{Name: "unknown", Banner: banner}
}

func detectMySQL(conn net.Conn, timeout time.Duration) ServiceResult {
	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n == 0 || buf[0] != 0x0a {
		return ServiceResult{Name: "unknown"}
	}
	version := ""
	if n > 1 {
		end := 1
		for end < n && buf[end] != 0x00 {
			end++
		}
		version = string(buf[1:end])
	}
	return ServiceResult{Name: "mysql", Version: version}
}

func detectPostgres(conn net.Conn, timeout time.Duration) ServiceResult {
	banner := readBanner(conn, timeout)
	if strings.Contains(banner, "PostgreSQL") {
		return ServiceResult{Name: "postgresql", Banner: banner}
	}
	return ServiceResult{Name: "unknown", Banner: banner}
}

func detectRedis(conn net.Conn, timeout time.Duration) ServiceResult {
	conn.SetDeadline(time.Now().Add(timeout))
	conn.Write([]byte("INFO server\r\n"))
	banner := readBanner(conn, timeout)
	if strings.Contains(banner, "redis") {
		version := ""
		for _, line := range strings.Split(banner, "\n") {
			if strings.HasPrefix(line, "redis_version:") {
				version = strings.TrimSpace(strings.TrimPrefix(line, "redis_version:"))
			}
		}
		return ServiceResult{Name: "redis", Version: version}
	}
	conn.Write([]byte("PING\r\n"))
	banner = readBanner(conn, timeout)
	if strings.HasPrefix(banner, "+PONG") {
		return ServiceResult{Name: "redis"}
	}
	return ServiceResult{Name: "unknown"}
}

func detectRDP(conn net.Conn, timeout time.Duration) ServiceResult {
	conn.SetDeadline(time.Now().Add(timeout))
	rdpNegReq := []byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00}
	conn.Write(rdpNegReq)
	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err == nil && n > 0 && buf[0] == 0x03 {
		return ServiceResult{Name: "rdp"}
	}
	return ServiceResult{Name: "unknown"}
}

func detectByBanner(conn net.Conn, timeout time.Duration) ServiceResult {
	banner := readBanner(conn, timeout)
	lower := strings.ToLower(banner)

	switch {
	case strings.Contains(lower, "ssh"):
		version := ""
		if m := sshVersionRe.FindStringSubmatch(banner); len(m) > 1 {
			version = m[1]
		}
		return ServiceResult{Name: "ssh", Version: version, Banner: banner}
	case strings.Contains(lower, "ftp"):
		return ServiceResult{Name: "ftp", Banner: banner}
	case strings.Contains(lower, "smtp"):
		return ServiceResult{Name: "smtp", Banner: banner}
	case strings.Contains(lower, "http"):
		return ServiceResult{Name: "http", Banner: banner}
	}

	return ServiceResult{Name: "unknown", Banner: banner}
}
