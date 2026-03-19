package scanner

import "encoding/json"

type ProductFingerprint struct {
	Name       string `json:"name"`
	Confidence string `json:"confidence"`
}

type ScanResult struct {
	Host            string               `json:"host"`
	Port            int                  `json:"port"`
	Protocol        string               `json:"protocol"`
	Service         string               `json:"service"`
	Version         string               `json:"version,omitempty"`
	Banner          string               `json:"banner,omitempty"`
	CDN             string               `json:"cdn,omitempty"`
	TLS             *TLSResult           `json:"tls,omitempty"`
	Metadata        json.RawMessage      `json:"metadata,omitempty"`
	Vulnerabilities []string             `json:"vulnerabilities,omitempty"`
	Endpoints       []CrawlResult        `json:"endpoints,omitempty"`
	App             *AppFingerprint      `json:"app,omitempty"`
	Products        []ProductFingerprint `json:"products,omitempty"`
	SecurityHeaders []HeaderFinding      `json:"security_headers,omitempty"`
	TLSEnum         *TLSEnum             `json:"tls_enum,omitempty"`
	Hostname        string               `json:"hostname,omitempty"`
	PTR             string               `json:"ptr,omitempty"`
	ASN             string               `json:"asn,omitempty"`
	Org             string               `json:"org,omitempty"`
}
