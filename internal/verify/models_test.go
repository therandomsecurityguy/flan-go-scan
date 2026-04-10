package verify

import (
	"testing"

	"github.com/therandomsecurityguy/flan-go-scan/internal/scanner"
)

func TestNormalizeSurfacePathURLWithoutPath(t *testing.T) {
	if got, want := normalizeSurfacePath("https://example.com"), "/"; got != want {
		t.Fatalf("normalizeSurfacePath returned %q, want %q", got, want)
	}
}

func TestSurfaceFromCrawlResultNormalizesPathAndParams(t *testing.T) {
	surface := SurfaceFromCrawlResult(scanner.CrawlResult{
		Path:        "login?Next=%2Fdashboard&redirect=https://evil.example&next=/foo",
		StatusCode:  302,
		ContentType: "text/html",
		Title:       "  Login  ",
		RedirectTo:  "https://evil.example",
	})

	if got, want := surface.Path, "/login?Next=%2Fdashboard&redirect=https://evil.example&next=/foo"; got != want {
		t.Fatalf("surface.Path = %q, want %q", got, want)
	}
	if got, want := surface.MethodHints, []string{"GET"}; len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("surface.MethodHints = %v, want %v", got, want)
	}
	wantParams := []string{"next", "redirect"}
	if len(surface.Params) != len(wantParams) {
		t.Fatalf("len(surface.Params) = %d, want %d", len(surface.Params), len(wantParams))
	}
	for i := range wantParams {
		if surface.Params[i] != wantParams[i] {
			t.Fatalf("surface.Params[%d] = %q, want %q", i, surface.Params[i], wantParams[i])
		}
	}
	if got, want := surface.Title, "Login"; got != want {
		t.Fatalf("surface.Title = %q, want %q", got, want)
	}
}

func TestSurfacesFromScanResultAddsFallbackRootForHTTPService(t *testing.T) {
	result := scanner.ScanResult{
		Host:     "192.0.2.20",
		Port:     443,
		Protocol: "tcp",
		Service:  "https",
		TLS:      &scanner.TLSResult{Version: "TLS 1.3"},
	}

	surfaces := SurfacesFromScanResult(result)

	if got, want := len(surfaces), 1; got != want {
		t.Fatalf("len(surfaces) = %d, want %d", got, want)
	}
	if got, want := surfaces[0].Source, "service"; got != want {
		t.Fatalf("surfaces[0].Source = %q, want %q", got, want)
	}
	if got, want := surfaces[0].Path, "/"; got != want {
		t.Fatalf("surfaces[0].Path = %q, want %q", got, want)
	}
}

func TestSurfacesFromScanResultAddsInferredProductPaths(t *testing.T) {
	result := scanner.ScanResult{
		Host:     "192.0.2.21",
		Port:     8200,
		Protocol: "tcp",
		Service:  "http",
		Products: []scanner.ProductFingerprint{
			{Name: "HashiCorp Vault", Confidence: "high"},
		},
	}

	surfaces := SurfacesFromScanResult(result)

	assertSurfacePaths(t, surfaces, []string{"/", "/v1/sys/health"})
}

func TestSurfacesFromScanResultAddsKubernetesPaths(t *testing.T) {
	result := scanner.ScanResult{
		Host:     "192.0.2.22",
		Port:     6443,
		Protocol: "tcp",
		Service:  "https",
		TLS:      &scanner.TLSResult{Version: "TLS 1.3"},
		Kubernetes: []scanner.KubernetesOrigin{{
			Cluster: "prod",
		}},
	}

	surfaces := SurfacesFromScanResult(result)

	assertSurfacePaths(t, surfaces, []string{"/", "/api", "/apis", "/version"})
}

func assertStrings(t *testing.T, name string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s length = %d, want %d (%v)", name, len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s[%d] = %q, want %q", name, i, got[i], want[i])
		}
	}
}

func assertSurfacePaths(t *testing.T, surfaces []Surface, want []string) {
	t.Helper()
	got := make([]string, 0, len(surfaces))
	for _, surface := range surfaces {
		got = append(got, surface.Path)
	}
	assertStrings(t, "SurfacePaths", got, want)
}
