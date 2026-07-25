package scanner

import (
	"net/http"
	"testing"
)

func productNames(fp *AppFingerprint) []string {
	out := make([]string, 0, len(fp.Products))
	for _, p := range fp.Products {
		out = append(out, p.Name)
	}
	return out
}

func hasProduct(fp *AppFingerprint, name string) bool {
	for _, p := range fp.Products {
		if p.Name == name {
			return true
		}
	}
	return false
}

func TestDetectDeeperProduct_ScanmeStyle404PathsDoNotFingerprint(t *testing.T) {
	apache404 := `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN"><html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1></body></html>`
	paths := []string{
		"/graphql",
		"/graphiql",
		"/grafana/",
		"/grafana/login",
		"/prometheus/",
		"/metrics",
		"/-/healthy",
		"/artifactory/",
		"/jfrog/",
		"/_cat/health",
		"/_nodes",
	}
	fp := &AppFingerprint{Server: "Apache/2.4.7 (Ubuntu)"}
	found := map[string]string{}
	for _, path := range paths {
		cr := &CrawlResult{Path: path, StatusCode: 404, ContentType: "text/html; charset=iso-8859-1", Title: "404 Not Found"}
		detectDeeperProduct(path, cr, http.Header{}, apache404, fp, found)
	}
	if len(fp.Products) != 0 {
		t.Fatalf("404 probe paths produced products %v, want none", productNames(fp))
	}
}

func TestDetectDeeperProduct_EvidenceBasedMatches(t *testing.T) {
	cases := []struct {
		name       string
		path       string
		status     int
		title      string
		body       string
		headers    http.Header
		want       string
		wantAbsent string
	}{
		{
			name:   "grafana login page",
			path:   "/grafana/login",
			status: 200,
			title:  "Grafana",
			body:   `<html><body class="grafana-app">window.grafanaBootData={}</body></html>`,
			want:   "Grafana",
		},
		{
			name:       "grafana path alone on 404",
			path:       "/grafana/",
			status:     404,
			title:      "404 Not Found",
			body:       "404 Not Found",
			wantAbsent: "Grafana",
		},
		{
			name:   "prometheus healthy",
			path:   "/-/healthy",
			status: 200,
			body:   "Prometheus Server is Healthy.",
			want:   "Prometheus",
		},
		{
			name:       "prometheus path alone on 404",
			path:       "/-/healthy",
			status:     404,
			body:       "404 Not Found",
			wantAbsent: "Prometheus",
		},
		{
			name:   "prometheus metrics exposition",
			path:   "/metrics",
			status: 200,
			body:   "# HELP go_goroutines Number of goroutines\n# TYPE go_goroutines gauge\ngo_goroutines 10\n",
			want:   "Prometheus",
		},
		{
			name:   "artifactory header",
			path:   "/artifactory/",
			status: 200,
			headers: func() http.Header {
				h := http.Header{}
				h.Set("X-JFrog-Version", "7.0")
				return h
			}(),
			want: "Artifactory",
		},
		{
			name:   "elasticsearch header",
			path:   "/",
			status: 200,
			headers: func() http.Header {
				h := http.Header{}
				h.Set("X-Elastic-Product", "Elasticsearch")
				return h
			}(),
			body: `{"name":"node"}`,
			want: "Elasticsearch",
		},
		{
			name:       "elasticsearch path alone on 404",
			path:       "/_nodes",
			status:     404,
			body:       "404 Not Found",
			wantAbsent: "Elasticsearch",
		},
		{
			name:       "artifactory substring in 404 html",
			path:       "/artifactory/",
			status:     404,
			body:       `<html>404 Not Found artifactory path missing</html>`,
			wantAbsent: "Artifactory",
		},
		{
			name:   "graphql errors json",
			path:   "/graphql",
			status: 200,
			headers: func() http.Header {
				h := http.Header{}
				h.Set("Content-Type", "application/json")
				return h
			}(),
			body: `{"errors":[{"message":"Must provide query string."}]}`,
			want: "GraphQL",
		},
		{
			name:       "graphql path alone on 404",
			path:       "/graphql",
			status:     404,
			body:       "404 Not Found",
			wantAbsent: "GraphQL",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fp := &AppFingerprint{}
			found := map[string]string{}
			hdr := tc.headers
			if hdr == nil {
				hdr = http.Header{}
			}
			cr := &CrawlResult{Path: tc.path, StatusCode: tc.status, Title: tc.title, ContentType: hdr.Get("Content-Type")}
			detectDeeperProduct(tc.path, cr, hdr, tc.body, fp, found)
			if tc.want != "" && !hasProduct(fp, tc.want) {
				t.Fatalf("products = %v, want %q", productNames(fp), tc.want)
			}
			if tc.wantAbsent != "" && hasProduct(fp, tc.wantAbsent) {
				t.Fatalf("products = %v, must not include %q", productNames(fp), tc.wantAbsent)
			}
		})
	}
}
