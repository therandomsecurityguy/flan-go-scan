package findings

import (
	"bufio"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/therandomsecurityguy/flan-go-scan/internal/scanner"
	verifymodel "github.com/therandomsecurityguy/flan-go-scan/internal/verify"
)

type Finding struct {
	ID          string   `json:"id"`
	Source      string   `json:"source"`
	Severity    string   `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Confidence  string   `json:"confidence,omitempty"`
	Host        string   `json:"host"`
	Hostname    string   `json:"hostname,omitempty"`
	Port        int      `json:"port"`
	Service     string   `json:"service,omitempty"`
	AssetID     string   `json:"asset_id,omitempty"`
	URL         string   `json:"url,omitempty"`
	Path        string   `json:"path,omitempty"`
	TemplateID  string   `json:"template_id,omitempty"`
	MatcherName string   `json:"matcher_name,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Evidence    []string `json:"evidence,omitempty"`
}

func FromScanResults(results []scanner.ScanResult) []Finding {
	findings := make([]Finding, 0, len(results)*2)
	for _, result := range results {
		findings = append(findings, nativeFindingsFromScanResult(result)...)
	}
	return findings
}

func FromNucleiBundles(bundles []*verifymodel.NucleiRunBundle) ([]Finding, error) {
	findings := make([]Finding, 0, len(bundles))
	for _, bundle := range bundles {
		if bundle == nil {
			continue
		}
		targetIndex, err := loadNucleiTargetIndex(bundle.TargetMapPath)
		if err != nil {
			return nil, err
		}
		bundleFindings, err := loadNucleiBundleFindings(bundle, targetIndex)
		if err != nil {
			return nil, err
		}
		findings = append(findings, bundleFindings...)
	}
	return dedupeFindings(findings), nil
}

func nativeFindingsFromScanResult(result scanner.ScanResult) []Finding {
	findings := make([]Finding, 0, 4)

	if result.TLS != nil && strings.TrimSpace(result.TLS.VerificationError) != "" {
		findings = append(findings, newFinding(result, "high", "TLS Verification Failed", "", []string{
			result.TLS.VerificationError,
		}))
	}
	if result.TLSEnum != nil && len(result.TLSEnum.WeakVersions) > 0 {
		findings = append(findings, newFinding(result, "medium", "Weak TLS Versions Enabled", "", []string{
			"Supported deprecated versions: " + strings.Join(result.TLSEnum.WeakVersions, ", "),
		}))
	}

	for _, endpoint := range result.Endpoints {
		path := strings.TrimSpace(endpoint.Path)
		switch {
		case endpoint.StatusCode >= 200 && endpoint.StatusCode < 400 && path == "/metrics":
			findings = append(findings, newFinding(result, "medium", "Metrics Endpoint Exposed", path, []string{
				fmt.Sprintf("HTTP %d", endpoint.StatusCode),
				strings.TrimSpace(endpoint.ContentType),
			}))
		case endpoint.StatusCode >= 200 && endpoint.StatusCode < 400 && strings.HasPrefix(path, "/debug/pprof"):
			findings = append(findings, newFinding(result, "high", "Pprof Debug Endpoint Exposed", path, []string{
				fmt.Sprintf("HTTP %d", endpoint.StatusCode),
			}))
		}
		for _, asset := range endpoint.ExternalAssets {
			if strings.TrimSpace(asset.Kind) != "sourcemap" || strings.TrimSpace(asset.URL) == "" {
				continue
			}
			findings = append(findings, Finding{
				ID:          fmt.Sprintf("%x", sha1.Sum([]byte(strings.Join([]string{"external-sourcemap", result.Host, asset.URL}, "|")))),
				Source:      "native",
				Severity:    "medium",
				Title:       "External Sourcemap Reference Exposed",
				Confidence:  "medium",
				Host:        result.Host,
				Hostname:    result.Hostname,
				Port:        result.Port,
				Service:     result.Service,
				URL:         asset.URL,
				Path:        asset.SourcePath,
				Description: "A linked asset exposed a sourcemap reference outside the scanned origin.",
				Evidence:    compactEvidence([]string{asset.SourceURL, asset.URL}),
			})
		}
	}

	return dedupeFindings(findings)
}

func newFinding(result scanner.ScanResult, severity, title, path string, evidence []string) Finding {
	url := ""
	if path != "" && scanner.IsHTTPService(result.Service, result.Port, result.TLS != nil) {
		url = fmt.Sprintf("%s://%s:%d%s", scanner.HTTPScheme(result.TLS != nil), result.Host, result.Port, path)
	}
	base := strings.Join([]string{
		title,
		result.Host,
		fmt.Sprintf("%d", result.Port),
		path,
	}, "|")
	return Finding{
		ID:         fmt.Sprintf("%x", sha1.Sum([]byte(base))),
		Source:     "native",
		Severity:   severity,
		Title:      title,
		Confidence: "high",
		Host:       result.Host,
		Hostname:   result.Hostname,
		Port:       result.Port,
		Service:    result.Service,
		URL:        url,
		Path:       path,
		Evidence:   compactEvidence(evidence),
	}
}

type nucleiJSONLInfo struct {
	Name     string   `json:"name"`
	Severity string   `json:"severity"`
	Tags     []string `json:"tags"`
}

type nucleiJSONLRecord struct {
	TemplateID  string          `json:"template-id"`
	MatcherName string          `json:"matcher-name"`
	MatchedAt   string          `json:"matched-at"`
	Host        string          `json:"host"`
	Type        string          `json:"type"`
	Info        nucleiJSONLInfo `json:"info"`
}

func loadNucleiBundleFindings(bundle *verifymodel.NucleiRunBundle, targetIndex map[string]verifymodel.NucleiTarget) ([]Finding, error) {
	file, err := os.Open(bundle.NucleiJSONLPath)
	if err != nil {
		return nil, fmt.Errorf("open nuclei jsonl: %w", err)
	}
	defer file.Close()

	findings := make([]Finding, 0, 8)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var record nucleiJSONLRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			return nil, fmt.Errorf("parse nuclei jsonl: %w", err)
		}
		findings = append(findings, findingFromNucleiRecord(record, targetIndex))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan nuclei jsonl: %w", err)
	}
	return findings, nil
}

func findingFromNucleiRecord(record nucleiJSONLRecord, targetIndex map[string]verifymodel.NucleiTarget) Finding {
	matchedURL := firstNonEmpty(record.MatchedAt, record.Host)
	normalizedURL := normalizeFindingURL(matchedURL)
	target := lookupNucleiTarget(targetIndex, normalizedURL)
	title := strings.TrimSpace(record.Info.Name)
	if title == "" {
		title = strings.TrimSpace(record.TemplateID)
	}
	base := strings.Join([]string{
		"nuclei",
		record.TemplateID,
		record.MatcherName,
		normalizedURL,
	}, "|")
	return Finding{
		ID:          fmt.Sprintf("%x", sha1.Sum([]byte(base))),
		Source:      "nuclei",
		Severity:    strings.ToLower(strings.TrimSpace(record.Info.Severity)),
		Title:       title,
		Confidence:  "high",
		Host:        firstNonEmpty(target.Host, extractHostFromURL(normalizedURL)),
		Port:        target.Port,
		Service:     target.Service,
		AssetID:     target.AssetID,
		URL:         normalizedURL,
		Path:        firstNonEmpty(target.Path, extractPathFromURL(normalizedURL)),
		TemplateID:  strings.TrimSpace(record.TemplateID),
		MatcherName: strings.TrimSpace(record.MatcherName),
		Tags:        compactEvidence(record.Info.Tags),
		Evidence:    compactEvidence([]string{normalizedURL}),
	}
}

func loadNucleiTargetIndex(path string) (map[string]verifymodel.NucleiTarget, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read nuclei target map: %w", err)
	}
	var targets []verifymodel.NucleiTarget
	if err := json.Unmarshal(body, &targets); err != nil {
		return nil, fmt.Errorf("parse nuclei target map: %w", err)
	}
	index := make(map[string]verifymodel.NucleiTarget, len(targets))
	for _, target := range targets {
		for _, key := range nucleiTargetLookupKeys(target.URL) {
			index[key] = target
		}
	}
	return index, nil
}

func normalizeFindingURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return trimmed
	}
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	parsed.Path = path.Clean(parsed.Path)
	if !strings.HasPrefix(parsed.Path, "/") {
		parsed.Path = "/" + parsed.Path
	}
	return parsed.String()
}

func lookupNucleiTarget(index map[string]verifymodel.NucleiTarget, rawURL string) verifymodel.NucleiTarget {
	for _, key := range nucleiTargetLookupKeys(rawURL) {
		if target, ok := index[key]; ok {
			return target
		}
	}
	return verifymodel.NucleiTarget{}
}

func nucleiTargetLookupKeys(rawURL string) []string {
	normalized := normalizeFindingURL(rawURL)
	if normalized == "" {
		return nil
	}
	keys := []string{normalized}
	trimmedDefaultPort := trimDefaultPort(normalized)
	if trimmedDefaultPort != normalized {
		keys = append(keys, trimmedDefaultPort)
	}
	return keys
}

func trimDefaultPort(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	switch {
	case parsed.Scheme == "https" && parsed.Port() == "443":
		parsed.Host = parsed.Hostname()
	case parsed.Scheme == "http" && parsed.Port() == "80":
		parsed.Host = parsed.Hostname()
	default:
		return rawURL
	}
	return parsed.String()
}

func extractHostFromURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

func extractPathFromURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if parsed.Path == "" {
		return "/"
	}
	return parsed.Path
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func compactEvidence(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func dedupeFindings(findings []Finding) []Finding {
	out := make([]Finding, 0, len(findings))
	seen := make(map[string]struct{}, len(findings))
	for _, finding := range findings {
		if _, ok := seen[finding.ID]; ok {
			continue
		}
		seen[finding.ID] = struct{}{}
		out = append(out, finding)
	}
	return out
}
