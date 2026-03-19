package scanner

import "testing"

func TestDetectServiceProducts(t *testing.T) {
	tests := []struct {
		name     string
		service  string
		version  string
		banner   string
		metadata []byte
		port     int
		protocol string
		product  string
	}{
		{
			name:     "postgres service",
			service:  "postgresql",
			port:     5432,
			protocol: "tcp",
			product:  "PostgreSQL",
		},
		{
			name:     "mysql banner",
			service:  "unknown",
			banner:   "5.7.42 MySQL Community Server",
			port:     3306,
			protocol: "tcp",
			product:  "MySQL",
		},
		{
			name:     "mongodb metadata",
			service:  "unknown",
			metadata: []byte(`{"cpes":["cpe:2.3:a:mongodb:mongodb:7.0:*:*:*:*:*:*:*"]}`),
			port:     27017,
			protocol: "tcp",
			product:  "MongoDB",
		},
		{
			name:     "redis version",
			service:  "unknown",
			version:  "redis 7.2",
			port:     6379,
			protocol: "tcp",
			product:  "Redis",
		},
		{
			name:     "ipsec udp",
			service:  "ike",
			metadata: []byte(`{"protocol":"ikev2"}`),
			port:     500,
			protocol: "udp",
			product:  "IPsec",
		},
		{
			name:     "ldap service",
			service:  "ldap",
			port:     389,
			protocol: "tcp",
			product:  "LDAP",
		},
		{
			name:     "vnc banner",
			service:  "unknown",
			banner:   "RFB 003.008\n",
			port:     5900,
			protocol: "tcp",
			product:  "VNC",
		},
		{
			name:     "smtp service",
			service:  "smtp",
			port:     25,
			protocol: "tcp",
			product:  "SMTP",
		},
		{
			name:     "pop3 banner",
			service:  "unknown",
			banner:   "+OK Dovecot ready.\n",
			port:     110,
			protocol: "tcp",
			product:  "POP3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			products := DetectServiceProducts(tt.service, tt.version, tt.banner, tt.metadata, tt.port, tt.protocol)
			got := false
			for _, product := range products {
				if product.Name == tt.product {
					got = true
					break
				}
			}
			if !got {
				t.Fatalf("expected %s in %+v", tt.product, products)
			}
		})
	}
}

func TestMergeProductFingerprints(t *testing.T) {
	got := MergeProductFingerprints(
		[]ProductFingerprint{{Name: "Grafana", Confidence: "medium"}},
		[]ProductFingerprint{{Name: "Grafana", Confidence: "high"}, {Name: "Redis", Confidence: "high"}},
	)

	products := make(map[string]string, len(got))
	for _, product := range got {
		products[product.Name] = product.Confidence
	}
	if products["Grafana"] != "high" {
		t.Fatalf("expected Grafana high confidence, got %+v", got)
	}
	if products["Redis"] != "high" {
		t.Fatalf("expected Redis merge, got %+v", got)
	}
}
