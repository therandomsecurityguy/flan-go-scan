package scanner

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCrawlSensitivePaths(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin":
			w.WriteHeader(http.StatusForbidden)
		case "/.env":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("DB_PASSWORD=secret"))
		case "/robots.txt":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /hidden\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	results, _ := Crawl(context.Background(), "http", "127.0.0.1", "", srv.Listener.Addr().(*net.TCPAddr).Port, 0, 5*time.Second, 0, false)

	byPath := make(map[string]CrawlResult)
	for _, result := range results {
		byPath[result.Path] = result
	}
	if byPath["/admin"].StatusCode != http.StatusForbidden {
		t.Fatalf("expected /admin 403, got %+v", byPath["/admin"])
	}
	if byPath["/.env"].StatusCode != http.StatusOK {
		t.Fatalf("expected /.env 200, got %+v", byPath["/.env"])
	}
	if _, ok := byPath["/hidden"]; !ok {
		t.Fatal("expected robots.txt disallow entry to be crawled")
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
}
