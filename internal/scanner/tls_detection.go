package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

type TLSResult struct {
	Enabled           bool      `json:"enabled"`
	Version           string    `json:"version,omitempty"`
	CipherSuite       string    `json:"cipher_suite,omitempty"`
	Subject           string    `json:"subject,omitempty"`
	Issuer            string    `json:"issuer,omitempty"`
	NotBefore         time.Time `json:"not_before,omitempty"`
	NotAfter          time.Time `json:"not_after,omitempty"`
	SANs              []string  `json:"sans,omitempty"`
	Expired           bool      `json:"expired,omitempty"`
	SelfSigned        bool      `json:"self_signed,omitempty"`
	VerificationError string    `json:"verification_error,omitempty"`
}

func InspectTLS(ctx context.Context, host, hostname string, port int, timeout time.Duration, verify bool) *TLSResult {
	serverName := tlsServerName(host, hostname)
	result, err := inspectTLS(ctx, host, port, timeout, serverName, verify)
	if err == nil {
		return result
	}
	if !verify {
		return nil
	}
	result, insecureErr := inspectTLS(ctx, host, port, timeout, serverName, false)
	if insecureErr != nil {
		return nil
	}
	result.VerificationError = err.Error()
	return result
}

func inspectTLS(ctx context.Context, host string, port int, timeout time.Duration, serverName string, verify bool) (*TLSResult, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	tlsCfg := &tls.Config{InsecureSkipVerify: !verify}
	if serverName != "" {
		tlsCfg.ServerName = serverName
	}
	tlsConn := tls.Client(conn, tlsCfg)
	tlsConn.SetDeadline(time.Now().Add(timeout))
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}

	state := tlsConn.ConnectionState()
	result := &TLSResult{
		Enabled:     true,
		Version:     tlsVersionString(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
	}

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.Subject = cert.Subject.String()
		result.Issuer = cert.Issuer.String()
		result.NotBefore = cert.NotBefore
		result.NotAfter = cert.NotAfter
		result.SANs = cert.DNSNames
		result.Expired = time.Now().After(cert.NotAfter)
		result.SelfSigned = cert.Issuer.String() == cert.Subject.String()
	}

	return result, nil
}

func tlsServerName(host, hostname string) string {
	if value := strings.TrimSpace(hostname); value != "" {
		return strings.TrimSuffix(value, ".")
	}
	return strings.TrimSpace(host)
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
