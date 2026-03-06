package cloudflare

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"
)

const defaultBaseURL = "https://api.cloudflare.com/client/v4"

type Client struct {
	token      string
	baseURL    string
	httpClient *http.Client
}

type Zone struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Paused bool   `json:"paused"`
	Type   string `json:"type"`
}

type DNSRecord struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
}

type Asset struct {
	Zone       string `json:"zone"`
	Hostname   string `json:"hostname"`
	RecordType string `json:"record_type"`
	Value      string `json:"value"`
	Proxied    bool   `json:"proxied"`
	Source     string `json:"source"`
}

type DiscoverOptions struct {
	Zones    []string
	Include  []string
	Exclude  []string
	PageSize int
}

type apiEnvelope[T any] struct {
	Success bool `json:"success"`
	Errors  []struct {
		Message string `json:"message"`
	} `json:"errors"`
	Result     []T `json:"result"`
	ResultInfo struct {
		Page       int `json:"page"`
		PerPage    int `json:"per_page"`
		Count      int `json:"count"`
		TotalPages int `json:"total_pages"`
		TotalCount int `json:"total_count"`
	} `json:"result_info"`
}

func NewClient(token string, timeout time.Duration) (*Client, error) {
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("cloudflare token is required")
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &Client{
		token:      token,
		baseURL:    defaultBaseURL,
		httpClient: &http.Client{Timeout: timeout},
	}, nil
}

func NewClientForTesting(token string, baseURL string, httpClient *http.Client) (*Client, error) {
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("cloudflare token is required")
	}
	if strings.TrimSpace(baseURL) == "" {
		return nil, fmt.Errorf("cloudflare base url is required")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &Client{
		token:      token,
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: httpClient,
	}, nil
}

func (c *Client) Discover(ctx context.Context, opts DiscoverOptions) ([]Asset, error) {
	zones, err := c.ListZones(ctx, opts)
	if err != nil {
		return nil, err
	}

	zoneFilter := normalizeSet(opts.Zones)
	include := normalizePatterns(opts.Include)
	exclude := normalizePatterns(opts.Exclude)
	pageSize := opts.PageSize
	if pageSize <= 0 {
		pageSize = 500
	}

	seen := make(map[string]struct{})
	var assets []Asset
	for _, zone := range zones {
		if len(zoneFilter) > 0 {
			if _, ok := zoneFilter[normalizeHost(zone.Name)]; !ok {
				continue
			}
		}
		records, err := c.ListDNSRecords(ctx, zone.ID, pageSize)
		if err != nil {
			return nil, fmt.Errorf("list dns records for zone %s: %w", zone.Name, err)
		}
		for _, record := range records {
			asset, ok := normalizeAsset(zone, record, include, exclude)
			if !ok {
				continue
			}
			key := asset.Zone + "|" + asset.Hostname + "|" + asset.RecordType + "|" + asset.Value
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			assets = append(assets, asset)
		}
	}

	sort.Slice(assets, func(i, j int) bool {
		if assets[i].Zone != assets[j].Zone {
			return assets[i].Zone < assets[j].Zone
		}
		if assets[i].Hostname != assets[j].Hostname {
			return assets[i].Hostname < assets[j].Hostname
		}
		if assets[i].RecordType != assets[j].RecordType {
			return assets[i].RecordType < assets[j].RecordType
		}
		return assets[i].Value < assets[j].Value
	})
	return assets, nil
}

func (c *Client) ListZones(ctx context.Context, opts DiscoverOptions) ([]Zone, error) {
	pageSize := opts.PageSize
	if pageSize <= 0 {
		pageSize = 50
	}
	var zones []Zone
	for page := 1; ; page++ {
		var env apiEnvelope[Zone]
		if err := c.get(ctx, "/zones", url.Values{
			"page":     []string{fmt.Sprintf("%d", page)},
			"per_page": []string{fmt.Sprintf("%d", pageSize)},
		}, &env); err != nil {
			return nil, fmt.Errorf("list zones page %d: %w", page, err)
		}
		zones = append(zones, env.Result...)
		if env.ResultInfo.TotalPages <= page || len(env.Result) == 0 {
			break
		}
	}
	sort.Slice(zones, func(i, j int) bool {
		return normalizeHost(zones[i].Name) < normalizeHost(zones[j].Name)
	})
	return zones, nil
}

func (c *Client) ListDNSRecords(ctx context.Context, zoneID string, pageSize int) ([]DNSRecord, error) {
	if strings.TrimSpace(zoneID) == "" {
		return nil, fmt.Errorf("zone id is required")
	}
	if pageSize <= 0 {
		pageSize = 500
	}
	var records []DNSRecord
	for page := 1; ; page++ {
		var env apiEnvelope[DNSRecord]
		if err := c.get(ctx, path.Join("/zones", zoneID, "dns_records"), url.Values{
			"page":     []string{fmt.Sprintf("%d", page)},
			"per_page": []string{fmt.Sprintf("%d", pageSize)},
		}, &env); err != nil {
			return nil, fmt.Errorf("list dns records page %d: %w", page, err)
		}
		records = append(records, env.Result...)
		if env.ResultInfo.TotalPages <= page || len(env.Result) == 0 {
			break
		}
	}
	return records, nil
}

func normalizeAsset(zone Zone, record DNSRecord, include, exclude []string) (Asset, bool) {
	recordType := strings.ToUpper(strings.TrimSpace(record.Type))
	if !isScannableRecordType(recordType) {
		return Asset{}, false
	}

	hostname := normalizeHost(record.Name)
	if hostname == "" || isValidationRecordName(hostname) {
		return Asset{}, false
	}
	if !matchesAny(hostname, include, true) || matchesAny(hostname, exclude, false) {
		return Asset{}, false
	}

	value := strings.TrimSpace(record.Content)
	if recordType == "A" || recordType == "AAAA" {
		if !isPublicIP(value) {
			return Asset{}, false
		}
	}

	return Asset{
		Zone:       normalizeHost(zone.Name),
		Hostname:   hostname,
		RecordType: recordType,
		Value:      value,
		Proxied:    record.Proxied,
		Source:     "cloudflare",
	}, true
}

func Hostnames(assets []Asset) []string {
	seen := make(map[string]struct{}, len(assets))
	hostnames := make([]string, 0, len(assets))
	for _, asset := range assets {
		hostname := normalizeHost(asset.Hostname)
		if hostname == "" {
			continue
		}
		if _, ok := seen[hostname]; ok {
			continue
		}
		seen[hostname] = struct{}{}
		hostnames = append(hostnames, hostname)
	}
	sort.Strings(hostnames)
	return hostnames
}

func (c *Client) get(ctx context.Context, endpoint string, query url.Values, dst any) error {
	u, err := url.Parse(c.baseURL)
	if err != nil {
		return fmt.Errorf("parse base url: %w", err)
	}
	u.Path = strings.TrimRight(u.Path, "/") + endpoint
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status: %s", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	switch v := dst.(type) {
	case *apiEnvelope[Zone]:
		if !v.Success {
			return fmt.Errorf("cloudflare api error: %s", joinErrors(v.Errors))
		}
	case *apiEnvelope[DNSRecord]:
		if !v.Success {
			return fmt.Errorf("cloudflare api error: %s", joinErrors(v.Errors))
		}
	}

	return nil
}

func joinErrors(errs []struct {
	Message string `json:"message"`
}) string {
	if len(errs) == 0 {
		return "unknown error"
	}
	parts := make([]string, 0, len(errs))
	for _, err := range errs {
		if strings.TrimSpace(err.Message) != "" {
			parts = append(parts, err.Message)
		}
	}
	if len(parts) == 0 {
		return "unknown error"
	}
	return strings.Join(parts, "; ")
}

func normalizeSet(values []string) map[string]struct{} {
	if len(values) == 0 {
		return nil
	}
	normalized := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = normalizeHost(value)
		if value == "" {
			continue
		}
		normalized[value] = struct{}{}
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func normalizePatterns(values []string) []string {
	patterns := make([]string, 0, len(values))
	for _, value := range values {
		value = normalizeHost(value)
		if value == "" {
			continue
		}
		patterns = append(patterns, value)
	}
	return patterns
}

func normalizeHost(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}

func isScannableRecordType(recordType string) bool {
	switch recordType {
	case "A", "AAAA", "CNAME":
		return true
	default:
		return false
	}
}

func isValidationRecordName(name string) bool {
	labels := strings.Split(normalizeHost(name), ".")
	if len(labels) == 0 {
		return true
	}
	if labels[0] == "*" {
		return true
	}
	for _, label := range labels {
		if strings.HasPrefix(label, "_") {
			return true
		}
	}
	return false
}

func matchesAny(host string, patterns []string, emptyDefault bool) bool {
	if len(patterns) == 0 {
		return emptyDefault
	}
	for _, pattern := range patterns {
		if patternMatches(host, pattern) {
			return true
		}
	}
	return false
}

func patternMatches(host, pattern string) bool {
	if strings.ContainsAny(pattern, "*?[") {
		ok, err := path.Match(pattern, host)
		return err == nil && ok
	}
	return host == pattern || strings.HasSuffix(host, "."+pattern)
}

func isPublicIP(value string) bool {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return false
	}
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 0 || (ip4[0] == 169 && ip4[1] == 254) {
			return false
		}
	}
	return true
}
