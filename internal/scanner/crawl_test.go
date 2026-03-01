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
