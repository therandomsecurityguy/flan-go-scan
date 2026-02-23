package scanner

import "encoding/json"

type ScanResult struct {
	Host            string          `json:"host"`
	Port            int             `json:"port"`
	Protocol        string          `json:"protocol"`
	Service         string          `json:"service"`
	Version         string          `json:"version,omitempty"`
	Banner          string          `json:"banner,omitempty"`
	CDN             string          `json:"cdn,omitempty"`
	TLS             *TLSResult      `json:"tls,omitempty"`
	Metadata        json.RawMessage `json:"metadata,omitempty"`
	Vulnerabilities []string        `json:"vulnerabilities,omitempty"`
}
