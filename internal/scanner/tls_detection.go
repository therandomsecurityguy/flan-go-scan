package scanner

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

type TLSResult struct {
	Enabled     bool      `json:"enabled"`
	Version     string    `json:"version,omitempty"`
	CipherSuite string    `json:"cipher_suite,omitempty"`
	Subject     string    `json:"subject,omitempty"`
	Issuer      string    `json:"issuer,omitempty"`
	NotBefore   time.Time `json:"not_before,omitempty"`
	NotAfter    time.Time `json:"not_after,omitempty"`
	SANs        []string  `json:"sans,omitempty"`
	Expired     bool      `json:"expired,omitempty"`
	SelfSigned  bool      `json:"self_signed,omitempty"`
}

func InspectTLS(host string, port int, timeout time.Duration) *TLSResult {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	tlsConn.SetDeadline(time.Now().Add(timeout))
	if err := tlsConn.Handshake(); err != nil {
		return nil
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

	return result
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
