package scanner

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type AssetContext struct {
	Role        string `yaml:"role"`
	Criticality string `yaml:"criticality"`
	Data        string `yaml:"data"`
}

type ScanContext struct {
	Assets   map[string]AssetContext `yaml:"assets"`
	Policies struct {
		TLSMinVersion   string `yaml:"tls_min_version"`
		SSHPasswordAuth *bool  `yaml:"ssh_password_auth"`
		AllowedPorts    []int  `yaml:"allowed_ports"`
	} `yaml:"policies"`
}

type PolicyViolation struct {
	Host     string `json:"host"`
	Port     int    `json:"port,omitempty"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

func LoadContext(path string) (*ScanContext, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read context file: %w", err)
	}
	var sc ScanContext
	if err := yaml.Unmarshal(data, &sc); err != nil {
		return nil, fmt.Errorf("parse context file: %w", err)
	}
	return &sc, nil
}

func CheckPolicies(results []ScanResult, sc *ScanContext) []PolicyViolation {
	if sc == nil {
		return nil
	}

	tlsOrder := map[string]int{
		"TLS1.0": 0, "TLS1.1": 1, "TLS1.2": 2, "TLS1.3": 3,
	}
	minRequired := tlsOrder[sc.Policies.TLSMinVersion]

	allowedSet := make(map[int]bool, len(sc.Policies.AllowedPorts))
	for _, p := range sc.Policies.AllowedPorts {
		allowedSet[p] = true
	}

	var violations []PolicyViolation
	seen := make(map[string]struct{})

	for _, r := range results {
		host := r.Host
		if r.Hostname != "" {
			host = r.Hostname
		}
		if len(sc.Policies.AllowedPorts) > 0 && !allowedSet[r.Port] {
			violations = appendUniqueViolation(violations, seen, PolicyViolation{
				Host:     host,
				Port:     r.Port,
				Severity: "HIGH",
				Detail:   fmt.Sprintf("port %d not in allowed_ports policy", r.Port),
			})
		}

		if r.TLS != nil && sc.Policies.TLSMinVersion != "" {
			if v, ok := tlsOrder[r.TLS.Version]; ok && v < minRequired {
				violations = appendUniqueViolation(violations, seen, PolicyViolation{
					Host:     host,
					Port:     r.Port,
					Severity: "HIGH",
					Detail:   fmt.Sprintf("TLS %s below policy minimum %s", r.TLS.Version, sc.Policies.TLSMinVersion),
				})
			}
		}

		if sc.Policies.SSHPasswordAuth != nil && !*sc.Policies.SSHPasswordAuth {
			if strings.EqualFold(r.Service, "ssh") && r.Metadata != nil {
				if strings.Contains(string(r.Metadata), `"passwordAuthEnabled":true`) {
					violations = appendUniqueViolation(violations, seen, PolicyViolation{
						Host:     host,
						Port:     r.Port,
						Severity: "CRITICAL",
						Detail:   "SSH password authentication enabled; policy requires key-based auth only",
					})
				}
			}
		}
	}

	return violations
}

func appendUniqueViolation(violations []PolicyViolation, seen map[string]struct{}, violation PolicyViolation) []PolicyViolation {
	key := fmt.Sprintf("%s|%d|%s|%s", violation.Host, violation.Port, violation.Severity, violation.Detail)
	if _, exists := seen[key]; exists {
		return violations
	}
	seen[key] = struct{}{}
	return append(violations, violation)
}

func BuildContextSummary(sc *ScanContext) string {
	if sc == nil {
		return ""
	}
	var b strings.Builder
	if len(sc.Assets) > 0 {
		b.WriteString("Asset context:\n")
		for host, a := range sc.Assets {
			b.WriteString(fmt.Sprintf("  %s: role=%s criticality=%s", host, a.Role, a.Criticality))
			if a.Data != "" {
				b.WriteString(fmt.Sprintf(" data=%s", a.Data))
			}
			b.WriteString("\n")
		}
	}
	p := sc.Policies
	if p.TLSMinVersion != "" || p.SSHPasswordAuth != nil || len(p.AllowedPorts) > 0 {
		b.WriteString("Policies:\n")
		if p.TLSMinVersion != "" {
			b.WriteString(fmt.Sprintf("  tls_min_version: %s\n", p.TLSMinVersion))
		}
		if p.SSHPasswordAuth != nil {
			b.WriteString(fmt.Sprintf("  ssh_password_auth: %v\n", *p.SSHPasswordAuth))
		}
		if len(p.AllowedPorts) > 0 {
			ports := make([]string, len(p.AllowedPorts))
			for i, port := range p.AllowedPorts {
				ports[i] = fmt.Sprintf("%d", port)
			}
			b.WriteString(fmt.Sprintf("  allowed_ports: [%s]\n", strings.Join(ports, ", ")))
		}
	}
	return b.String()
}
