package scanner

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseRobotsTxt(t *testing.T) {
	body := "User-agent: *\nDisallow: /admin\nDisallow: /private/\nDisallow: /\nAllow: /public\nDisallow:\n"
	paths := parseRobotsTxt(body)
	want := map[string]bool{"/admin": true, "/private/": true}
	if len(paths) != len(want) {
		t.Fatalf("expected %d paths, got %d: %v", len(want), len(paths), paths)
	}
	for _, p := range paths {
		if !want[p] {
			t.Errorf("unexpected path %q", p)
		}
	}
}

func TestExtractLinks(t *testing.T) {
	body := `<html>
<a href="/about">About</a>
<a href="/contact">Contact</a>
<a href="https://external.com/page">External</a>
<a href="javascript:void(0)">JS</a>
<a href="#section">Fragment</a>
<script src="/static/app.js"></script>
<form action="/submit"></form>
</html>`

	links := extractLinks(body, "http://example.com:80")
	want := map[string]bool{
		"/about":         true,
		"/contact":       true,
		"/static/app.js": true,
		"/submit":        true,
	}
	for _, l := range links {
		if !want[l] {
			t.Errorf("unexpected link %q", l)
		}
		delete(want, l)
	}
	for missing := range want {
		t.Errorf("expected link %q not found", missing)
	}
}

func TestExtractLinksExternalFiltered(t *testing.T) {
	body := `<a href="https://attacker.com/evil">bad</a><a href="/good">good</a>`
	links := extractLinks(body, "http://target.com:80")
	for _, l := range links {
		if strings.Contains(l, "attacker") {
			t.Errorf("external link not filtered: %q", l)
		}
	}
	if len(links) != 1 || links[0] != "/good" {
		t.Errorf("expected [/good], got %v", links)
	}
}

func TestIsHTTPService(t *testing.T) {
	cases := []struct {
		service string
		port    int
		tls     bool
		want    bool
	}{
		{"http", 8080, false, true},
		{"https", 443, true, true},
		{"HTTP", 9000, false, true},
		{"ssh", 22, false, false},
		{"", 80, false, true},
		{"", 443, true, true},
		{"", 8080, false, true},
		{"mysql", 3306, false, false},
	}
	for _, c := range cases {
		got := IsHTTPService(c.service, c.port, c.tls)
		if got != c.want {
			t.Errorf("IsHTTPService(%q, %d, %v) = %v, want %v", c.service, c.port, c.tls, got, c.want)
		}
	}
}

func TestHTTPScheme(t *testing.T) {
	if HTTPScheme(true) != "https" {
		t.Error("expected https for tls=true")
	}
	if HTTPScheme(false) != "http" {
		t.Error("expected http for tls=false")
	}
}

func TestCrawlSensitivePaths(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin":
			w.WriteHeader(http.StatusForbidden)
		case "/.env":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("DB_PASSWORD=secret"))
		case "/robots.txt":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("User-agent: *\nDisallow: /hidden\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	results, _ := Crawl(context.Background(), "http", "127.0.0.1", "", srv.Listener.Addr().(*net.TCPAddr).Port, 0, 5*time.Second, 0, false)

	byPath := make(map[string]CrawlResult)
	for _, r := range results {
		byPath[r.Path] = r
	}

	if r, ok := byPath["/admin"]; !ok || r.StatusCode != http.StatusForbidden {
		t.Errorf("/admin: expected 403, got %+v", byPath["/admin"])
	}
	if r, ok := byPath["/.env"]; !ok || r.StatusCode != http.StatusOK {
		t.Errorf("/.env: expected 200, got %+v", r)
	}
	if _, ok := byPath["/hidden"]; !ok {
		t.Error("robots.txt Disallow /hidden should be crawled as a finding")
	}
}

func TestCrawlUsesProvidedHostHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "testphp.vulnweb.com" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><title>ok</title></html>"))
	}))
	defer srv.Close()

	port := srv.Listener.Addr().(*net.TCPAddr).Port
	results, _ := Crawl(context.Background(), "http", "127.0.0.1", "testphp.vulnweb.com", port, 0, 5*time.Second, 0, false)
	if len(results) == 0 {
		t.Fatal("expected at least one crawl result")
	}
	for _, r := range results {
		if r.Path == "/" && r.StatusCode == http.StatusOK {
			return
		}
	}
	t.Fatalf("expected / to be fetched with status 200, got %+v", results)
}

func TestDetectDeeperProduct(t *testing.T) {
	fp := &AppFingerprint{}
	products := make(map[string]string)

	detectDeeperProduct(
		"/",
		&CrawlResult{Path: "/", StatusCode: http.StatusOK, Title: "Grafana"},
		http.Header{},
		"<html>grafana</html>",
		fp,
		products,
	)
	detectDeeperProduct(
		"/_cat/health",
		&CrawlResult{Path: "/_cat/health", StatusCode: http.StatusOK},
		http.Header{"X-Elastic-Product": []string{"Elasticsearch"}},
		`{"cluster_name":"prod-search"}`,
		fp,
		products,
	)

	got := make(map[string]string, len(fp.Products))
	for _, product := range fp.Products {
		got[product.Name] = product.Confidence
	}
	if got["Grafana"] != "high" {
		t.Fatalf("expected Grafana high confidence, got %+v", fp.Products)
	}
	if got["Elasticsearch"] != "high" {
		t.Fatalf("expected Elasticsearch high confidence, got %+v", fp.Products)
	}
}

func TestDetectDeeperProductKubernetesAPIServer(t *testing.T) {
	fp := &AppFingerprint{}
	products := make(map[string]string)

	detectDeeperProduct(
		"/version",
		&CrawlResult{Path: "/version", StatusCode: http.StatusOK},
		http.Header{"Audit-Id": []string{"1234"}},
		`{"major":"1","minor":"31","gitVersion":"v1.31.0"}`,
		fp,
		products,
	)

	got := make(map[string]string, len(fp.Products))
	for _, product := range fp.Products {
		got[product.Name] = product.Confidence
	}
	if got["Kubernetes API Server"] != "high" {
		t.Fatalf("expected Kubernetes API Server high confidence, got %+v", fp.Products)
	}
	if got["Kubernetes"] == "" {
		t.Fatalf("expected Kubernetes umbrella product, got %+v", fp.Products)
	}
}

func TestDetectDeeperProductKubernetesIngress(t *testing.T) {
	fp := &AppFingerprint{}
	products := make(map[string]string)

	detectDeeperProduct(
		"/",
		&CrawlResult{Path: "/", StatusCode: http.StatusNotFound},
		http.Header{},
		`default backend - 404`,
		fp,
		products,
	)

	got := make(map[string]string, len(fp.Products))
	for _, product := range fp.Products {
		got[product.Name] = product.Confidence
	}
	if got["Kubernetes Ingress"] != "high" {
		t.Fatalf("expected Kubernetes Ingress high confidence, got %+v", fp.Products)
	}
}

func TestDetectDeeperProductKubernetesDashboard(t *testing.T) {
	fp := &AppFingerprint{}
	products := make(map[string]string)

	detectDeeperProduct(
		"/",
		&CrawlResult{Path: "/", StatusCode: http.StatusOK, Title: "Kubernetes Dashboard"},
		http.Header{},
		`<html>Kubernetes Dashboard</html>`,
		fp,
		products,
	)

	for _, product := range fp.Products {
		if product.Name == "Kubernetes Dashboard" {
			return
		}
	}
	t.Fatalf("expected Kubernetes Dashboard product, got %+v", fp.Products)
}

func TestDetectDeeperProductGraphQL(t *testing.T) {
	fp := &AppFingerprint{}
	products := make(map[string]string)

	detectDeeperProduct(
		"/graphql",
		&CrawlResult{Path: "/graphql", StatusCode: http.StatusBadRequest},
		http.Header{"Content-Type": []string{"application/graphql-response+json"}},
		`{"errors":[{"message":"must provide query string"}]}`,
		fp,
		products,
	)

	for _, product := range fp.Products {
		if product.Name == "GraphQL" {
			return
		}
	}
	t.Fatalf("expected GraphQL product, got %+v", fp.Products)
}

func TestMergeAppFingerprints(t *testing.T) {
	base := &AppFingerprint{
		Server:   "nginx",
		Apps:     []string{"Grafana"},
		Products: []ProductFingerprint{{Name: "Grafana", Confidence: "medium"}},
	}
	extra := &AppFingerprint{
		PoweredBy: "Go",
		Apps:      []string{"Prometheus"},
		Products: []ProductFingerprint{
			{Name: "Grafana", Confidence: "high"},
			{Name: "Prometheus", Confidence: "high"},
		},
	}

	got := MergeAppFingerprints(base, extra)
	if got.PoweredBy != "Go" {
		t.Fatalf("expected powered_by merge, got %+v", got)
	}
	if len(got.Apps) != 2 {
		t.Fatalf("expected merged apps, got %+v", got.Apps)
	}

	products := make(map[string]string, len(got.Products))
	for _, product := range got.Products {
		products[product.Name] = product.Confidence
	}
	if products["Grafana"] != "high" {
		t.Fatalf("expected Grafana confidence upgrade, got %+v", got.Products)
	}
	if products["Prometheus"] != "high" {
		t.Fatalf("expected Prometheus merge, got %+v", got.Products)
	}
}
