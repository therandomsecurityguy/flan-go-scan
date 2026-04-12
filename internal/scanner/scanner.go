package scanner

import "encoding/json"

type ProductFingerprint struct {
	Name       string `json:"name"`
	Confidence string `json:"confidence"`
}

type ExternalAsset struct {
	URL        string `json:"url"`
	Kind       string `json:"kind,omitempty"`
	SourceURL  string `json:"source_url,omitempty"`
	SourcePath string `json:"source_path,omitempty"`
}

type KubernetesOrigin struct {
	Cluster   string `json:"cluster,omitempty"`
	Context   string `json:"context,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Kind      string `json:"kind,omitempty"`
	Name      string `json:"name,omitempty"`
	Exposure  string `json:"exposure,omitempty"`
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
	Kubernetes      []KubernetesOrigin   `json:"kubernetes,omitempty"`
}
