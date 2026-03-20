package scanner

import (
	"encoding/json"
	"net/netip"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/scan"
)

type FingerprintResult struct {
	Service   string          `json:"service"`
	Version   string          `json:"version,omitempty"`
	Transport string          `json:"transport"`
	TLS       bool            `json:"tls"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
}

func Fingerprint(host string, port int, timeout time.Duration) *FingerprintResult {
	return fingerprint(host, port, timeout, false)
}

func FingerprintUDP(host string, port int, timeout time.Duration) *FingerprintResult {
	return fingerprint(host, port, timeout, true)
}

func fingerprint(host string, port int, timeout time.Duration, udp bool) *FingerprintResult {
	addr, err := fingerprintAddr(host, port)
	if err != nil {
		return nil
	}

	target := plugins.Target{
		Address: addr,
		Host:    host,
	}

	cfg := scan.Config{
		DefaultTimeout: timeout,
		FastMode:       false,
		Verbose:        false,
		UDP:            udp,
	}

	result, err := cfg.SimpleScanTarget(target)
	if err != nil || result == nil {
		return nil
	}

	return &FingerprintResult{
		Service:   result.Protocol,
		Version:   result.Version,
		Transport: result.Transport,
		TLS:       result.TLS,
		Metadata:  result.Raw,
	}
}

func fingerprintAddr(host string, port int) (netip.AddrPort, error) {
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(ip, uint16(port)), nil
}
