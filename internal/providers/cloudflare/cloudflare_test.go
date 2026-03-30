package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
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
					{"id": "zone-1", "name": "example.net", "status": "active", "paused": false, "type": "full"},
					{"id": "zone-2", "name": "example.org", "status": "active", "paused": false, "type": "full"},
				},
				"result_info": map[string]any{"page": 1, "per_page": 50, "count": 2, "total_pages": 1, "total_count": 2},
			}), nil
		case "/zones/zone-1/dns_records":
			return jsonResponse(t, map[string]any{
				"success": true,
				"result": []map[string]any{
					{"id": "1", "name": "api.example.net", "type": "CNAME", "content": "svc.example.net", "proxied": true},
					{"id": "2", "name": "internal.example.net", "type": "A", "content": "10.0.0.4", "proxied": false},
					{"id": "3", "name": "_acme-challenge.example.net", "type": "CNAME", "content": "validation.example.net", "proxied": false},
					{"id": "4", "name": "*.example.net", "type": "CNAME", "content": "wildcard.example.net", "proxied": false},
					{"id": "5", "name": "admin.example.net", "type": "A", "content": "8.8.8.8", "proxied": false},
				},
				"result_info": map[string]any{"page": 1, "per_page": 500, "count": 5, "total_pages": 1, "total_count": 5},
			}), nil
		case "/zones/zone-2/dns_records":
			return jsonResponse(t, map[string]any{
				"success": true,
				"result": []map[string]any{
					{"id": "6", "name": "example.org", "type": "CNAME", "content": "api.example.net", "proxied": true},
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
		Zones:   []string{"example.net", "example.org"},
		Include: []string{"*.example.net", "example.org"},
		Exclude: []string{"internal.example.net"},
	})
	if err != nil {
		t.Fatalf("Discover returned error: %v", err)
	}
	if len(assets) != 3 {
		t.Fatalf("expected 3 assets, got %d: %#v", len(assets), assets)
	}
	if assets[0].Hostname != "admin.example.net" || assets[1].Hostname != "api.example.net" || assets[2].Hostname != "example.org" {
		t.Fatalf("unexpected asset ordering: %#v", assets)
	}

	hostnames := Hostnames(assets)
	if strings.Join(hostnames, ",") != "admin.example.net,api.example.net,example.org" {
		t.Fatalf("unexpected hostnames: %v", hostnames)
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
