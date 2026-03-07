package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestDiscoverFiltersAndNormalizesAssets(t *testing.T) {
	client, err := NewClientForTesting("token", "https://example.test", newMockHTTPClient(t, func(r *http.Request) (*http.Response, error) {
		if got := r.Header.Get("Authorization"); got != "Bearer token" {
			t.Fatalf("unexpected auth header: %q", got)
		}
		switch r.URL.Path {
		case "/zones":
			return jsonResponse(t, map[string]any{
				"success": true,
				"result": []map[string]any{
					{"id": "zone-1", "name": "together.ai", "status": "active", "paused": false, "type": "full"},
					{"id": "zone-2", "name": "openchatkit.ai", "status": "active", "paused": false, "type": "full"},
				},
				"result_info": map[string]any{"page": 1, "per_page": 50, "count": 2, "total_pages": 1, "total_count": 2},
			}), nil
		case "/zones/zone-1/dns_records":
			return jsonResponse(t, map[string]any{
				"success": true,
				"result": []map[string]any{
					{"id": "1", "name": "api.together.ai", "type": "CNAME", "content": "svc.example.net", "proxied": true},
					{"id": "2", "name": "internal.together.ai", "type": "A", "content": "10.0.0.4", "proxied": false},
					{"id": "3", "name": "_acme-challenge.together.ai", "type": "CNAME", "content": "validation.example.net", "proxied": false},
					{"id": "4", "name": "*.together.ai", "type": "CNAME", "content": "wildcard.example.net", "proxied": false},
					{"id": "5", "name": "mail.together.ai", "type": "MX", "content": "mx.example.net", "proxied": false},
					{"id": "6", "name": "www.together.ai", "type": "A", "content": "8.8.8.8", "proxied": false},
				},
				"result_info": map[string]any{"page": 1, "per_page": 500, "count": 6, "total_pages": 1, "total_count": 6},
			}), nil
		case "/zones/zone-2/dns_records":
			return jsonResponse(t, map[string]any{
				"success": true,
				"result": []map[string]any{
					{"id": "7", "name": "openchatkit.ai", "type": "CNAME", "content": "api.together.xyz", "proxied": true},
				},
				"result_info": map[string]any{"page": 1, "per_page": 500, "count": 1, "total_pages": 1, "total_count": 1},
			}), nil
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
			return nil, nil
		}
	}))
	if err != nil {
		t.Fatalf("NewClientForTesting returned error: %v", err)
	}

	assets, err := client.Discover(context.Background(), DiscoverOptions{
		Zones:   []string{"together.ai", "openchatkit.ai"},
		Include: []string{"*.together.ai", "openchatkit.ai"},
		Exclude: []string{"internal.together.ai"},
	})
	if err != nil {
		t.Fatalf("Discover returned error: %v", err)
	}

	if len(assets) != 3 {
		t.Fatalf("expected 3 assets, got %d: %#v", len(assets), assets)
	}
	if assets[0].Zone != "openchatkit.ai" || assets[0].Hostname != "openchatkit.ai" {
		t.Fatalf("unexpected first asset ordering: %#v", assets[0])
	}
	if assets[1].Hostname != "api.together.ai" || !assets[1].Proxied {
		t.Fatalf("expected proxied api.together.ai asset, got %#v", assets[1])
	}
	if assets[2].Hostname != "www.together.ai" {
		t.Fatalf("expected www.together.ai asset, got %#v", assets[2])
	}

	hostnames := Hostnames(assets)
	if strings.Join(hostnames, ",") != "api.together.ai,openchatkit.ai,www.together.ai" {
		t.Fatalf("unexpected hostnames: %v", hostnames)
	}
}

func TestListDNSRecordsPaginates(t *testing.T) {
	client, err := NewClientForTesting("token", "https://example.test", newMockHTTPClient(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/zones/zone-1/dns_records" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		switch r.URL.Query().Get("page") {
		case "1":
			return jsonResponse(t, map[string]any{
				"success": true,
				"result": []map[string]any{
					{"id": "1", "name": "a.example.com", "type": "CNAME", "content": "one.example.net", "proxied": false},
				},
				"result_info": map[string]any{"page": 1, "per_page": 1, "count": 1, "total_pages": 2, "total_count": 2},
			}), nil
		case "2":
			return jsonResponse(t, map[string]any{
				"success": true,
				"result": []map[string]any{
					{"id": "2", "name": "b.example.com", "type": "CNAME", "content": "two.example.net", "proxied": false},
				},
				"result_info": map[string]any{"page": 2, "per_page": 1, "count": 1, "total_pages": 2, "total_count": 2},
			}), nil
		default:
			t.Fatalf("unexpected page query: %q", r.URL.Query().Get("page"))
			return nil, nil
		}
	}))
	if err != nil {
		t.Fatalf("NewClientForTesting returned error: %v", err)
	}

	records, err := client.ListDNSRecords(context.Background(), "zone-1", 1)
	if err != nil {
		t.Fatalf("ListDNSRecords returned error: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
}

func TestPatternMatches(t *testing.T) {
	tests := []struct {
		host    string
		pattern string
		match   bool
	}{
		{host: "api.together.ai", pattern: "*.together.ai", match: true},
		{host: "api.together.ai", pattern: "together.ai", match: true},
		{host: "api.together.ai", pattern: "api.together.ai", match: true},
		{host: "api.together.ai", pattern: "admin.together.ai", match: false},
	}

	for _, test := range tests {
		if got := patternMatches(test.host, test.pattern); got != test.match {
			t.Fatalf("patternMatches(%q, %q) = %v, want %v", test.host, test.pattern, got, test.match)
		}
	}
}

func TestIsPublicIP(t *testing.T) {
	if isPublicIP("10.0.0.1") {
		t.Fatal("expected private ip to be filtered")
	}
	if isPublicIP("127.0.0.1") {
		t.Fatal("expected loopback ip to be filtered")
	}
	if !isPublicIP("8.8.8.8") {
		t.Fatal("expected public ip to pass")
	}
}

func TestNewClientRejectsEmptyToken(t *testing.T) {
	if _, err := NewClient("", time.Second); err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestBuildInventorySnapshot(t *testing.T) {
	snapshot := BuildInventorySnapshot(time.Date(2026, 3, 7, 12, 0, 0, 0, time.UTC), []Asset{
		{Zone: "together.ai", Hostname: "api.together.ai", RecordType: "CNAME", Value: "svc.example.net", Proxied: true, Source: "cloudflare"},
		{Zone: "together.ai", Hostname: "www.together.ai", RecordType: "A", Value: "8.8.8.8", Proxied: false, Source: "cloudflare"},
	}, DiscoverOptions{
		Zones:   []string{"together.ai", "together.ai"},
		Include: []string{"*.together.ai"},
		Exclude: []string{"internal.together.ai"},
	})

	if snapshot.GeneratedAt != "2026-03-07T12:00:00Z" {
		t.Fatalf("unexpected generated_at: %s", snapshot.GeneratedAt)
	}
	if snapshot.AssetCount != 2 {
		t.Fatalf("unexpected asset_count: %d", snapshot.AssetCount)
	}
	if len(snapshot.Zones) != 1 || snapshot.Zones[0] != "together.ai" {
		t.Fatalf("unexpected zones: %v", snapshot.Zones)
	}
	if len(snapshot.ZoneFilters) != 1 || snapshot.ZoneFilters[0] != "together.ai" {
		t.Fatalf("unexpected zone filters: %v", snapshot.ZoneFilters)
	}
}

func TestDiffInventory(t *testing.T) {
	previous := InventorySnapshot{
		GeneratedAt: "2026-03-06T10:00:00Z",
		Assets: []Asset{
			{Zone: "together.ai", Hostname: "api.together.ai", RecordType: "CNAME", Value: "old.example.net", Proxied: true, Source: "cloudflare"},
			{Zone: "together.ai", Hostname: "legacy.together.ai", RecordType: "A", Value: "8.8.8.8", Proxied: false, Source: "cloudflare"},
			{Zone: "together.ai", Hostname: "app.together.ai", RecordType: "CNAME", Value: "svc.example.net", Proxied: false, Source: "cloudflare"},
		},
	}
	current := InventorySnapshot{
		GeneratedAt: "2026-03-07T10:00:00Z",
		Assets: []Asset{
			{Zone: "together.ai", Hostname: "api.together.ai", RecordType: "CNAME", Value: "new.example.net", Proxied: true, Source: "cloudflare"},
			{Zone: "together.ai", Hostname: "app.together.ai", RecordType: "CNAME", Value: "svc.example.net", Proxied: true, Source: "cloudflare"},
			{Zone: "together.ai", Hostname: "new.together.ai", RecordType: "A", Value: "1.1.1.1", Proxied: false, Source: "cloudflare"},
		},
	}

	diff := DiffInventory(time.Date(2026, 3, 7, 12, 0, 0, 0, time.UTC), previous, current)

	if diff.AddedCount != 2 {
		t.Fatalf("unexpected added count: %d", diff.AddedCount)
	}
	if diff.RemovedCount != 2 {
		t.Fatalf("unexpected removed count: %d", diff.RemovedCount)
	}
	if diff.ChangedCount != 1 {
		t.Fatalf("unexpected changed count: %d", diff.ChangedCount)
	}
	if len(diff.Changed) != 1 || diff.Changed[0].After.Hostname != "app.together.ai" {
		t.Fatalf("unexpected changed assets: %#v", diff.Changed)
	}
}

func TestHostnamesFromDiff(t *testing.T) {
	diff := InventoryDiff{
		Added: []Asset{
			{Zone: "together.ai", Hostname: "new.together.ai", RecordType: "A", Value: "1.1.1.1", Source: "cloudflare"},
			{Zone: "together.ai", Hostname: "new.together.ai", RecordType: "AAAA", Value: "2606:4700::1111", Source: "cloudflare"},
		},
		Changed: []AssetChange{
			{
				Before: Asset{Zone: "together.ai", Hostname: "app.together.ai", RecordType: "CNAME", Value: "old.example.net", Source: "cloudflare"},
				After:  Asset{Zone: "together.ai", Hostname: "app.together.ai", RecordType: "CNAME", Value: "new.example.net", Source: "cloudflare"},
			},
		},
	}

	got := HostnamesFromDiff(diff)
	want := []string{"app.together.ai", "new.together.ai"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("unexpected diff hostnames: got %v want %v", got, want)
	}
}

func TestGetIncludesQuery(t *testing.T) {
	client, err := NewClientForTesting("token", "https://example.test", newMockHTTPClient(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/zones" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		values, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			t.Fatalf("parse query: %v", err)
		}
		if values.Get("page") != "1" || values.Get("per_page") != "5" {
			t.Fatalf("unexpected query values: %v", values)
		}
		return jsonResponse(t, map[string]any{
			"success":     true,
			"result":      []map[string]any{},
			"result_info": map[string]any{"page": 1, "per_page": 5, "count": 0, "total_pages": 1, "total_count": 0},
		}), nil
	}))
	if err != nil {
		t.Fatalf("NewClientForTesting returned error: %v", err)
	}
	_, err = client.ListZones(context.Background(), DiscoverOptions{PageSize: 5})
	if err != nil {
		t.Fatalf("ListZones returned error: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func newMockHTTPClient(t *testing.T, fn roundTripFunc) *http.Client {
	t.Helper()
	return &http.Client{Transport: fn}
}

func jsonResponse(t *testing.T, body map[string]any) *http.Response {
	t.Helper()
	buf := bytes.NewBuffer(nil)
	if err := json.NewEncoder(buf).Encode(body); err != nil {
		t.Fatalf("encode response: %v", err)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(buf),
	}
}
