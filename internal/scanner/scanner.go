package scanner

type ScanResult struct {
	Host            string     `json:"host"`
	Port            int        `json:"port"`
	Protocol        string     `json:"protocol"`
	Service         string     `json:"service"`
	Version         string     `json:"version,omitempty"`
	Banner          string     `json:"banner,omitempty"`
	TLS             *TLSResult `json:"tls,omitempty"`
	Vulnerabilities []string   `json:"vulnerabilities,omitempty"`
}
