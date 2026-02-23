package scanner

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/scan"
)

type FingerprintResult struct {
	Service   string            `json:"service"`
	Version   string            `json:"version,omitempty"`
	Transport string            `json:"transport"`
	TLS       bool              `json:"tls"`
	Metadata  json.RawMessage   `json:"metadata,omitempty"`
}

func Fingerprint(host string, port int, timeout time.Duration) *FingerprintResult {
	addr, err := netip.ParseAddrPort(fmt.Sprintf("%s:%d", host, port))
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
