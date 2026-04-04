package verify

import (
	"testing"

	"github.com/therandomsecurityguy/flan-go-scan/internal/scanner"
)

func TestAssetFromScanResultMergesProducts(t *testing.T) {
	result := scanner.ScanResult{
		Host:     "10.0.0.1",
		Hostname: "grafana.example.com",
		Port:     443,
		Protocol: "tcp",
		Service:  "https",
		Products: []scanner.ProductFingerprint{
			{Name: "Grafana", Confidence: "low"},
		},
		App: &scanner.AppFingerprint{
			Products: []scanner.ProductFingerprint{
				{Name: "Grafana", Confidence: "high"},
				{Name: "Vault", Confidence: "medium"},
			},
		},
	}

	asset := AssetFromScanResult(result)

	if got, want := len(asset.Products), 2; got != want {
		t.Fatalf("len(asset.Products) = %d, want %d", got, want)
	}
	if got, want := asset.Products[0].Name, "Grafana"; got != want {
		t.Fatalf("asset.Products[0].Name = %q, want %q", got, want)
	}
	if got, want := asset.Products[0].Confidence, "high"; got != want {
		t.Fatalf("asset.Products[0].Confidence = %q, want %q", got, want)
	}
	if got, want := asset.Products[1].Name, "Vault"; got != want {
		t.Fatalf("asset.Products[1].Name = %q, want %q", got, want)
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

func TestSelectorContextFromScanResultBuildsHints(t *testing.T) {
	result := scanner.ScanResult{
		Host:     "192.0.2.10",
		Hostname: "app.example.com",
		Port:     443,
		Protocol: "tcp",
		Service:  "https",
		Products: []scanner.ProductFingerprint{
			{Name: "Grafana", Confidence: "high"},
		},
		App: &scanner.AppFingerprint{
			Server:    "nginx/1.27.0",
			PoweredBy: "Grafana",
			Apps:      []string{"Grafana", "Grafana"},
		},
		Endpoints: []scanner.CrawlResult{
			{Path: "/login?redirect=/", Title: "Login"},
			{Path: "/login?redirect=/", Title: "Login"},
			{Path: "/api/health", Title: "Health"},
		},
		SecurityHeaders: []scanner.HeaderFinding{
			{Header: "Content-Security-Policy"},
			{Header: "Content-Security-Policy"},
			{Header: "Server"},
		},
		Vulnerabilities: []string{"CVE-2025-1234", "CVE-2025-1234", "CWE-601"},
	}

	ctx := SelectorContextFromScanResult(result)

	if got, want := len(ctx.Surfaces), 2; got != want {
		t.Fatalf("len(ctx.Surfaces) = %d, want %d", got, want)
	}
	assertStrings(t, "ProductHints", ctx.ProductHints, []string{"grafana"})
	assertStrings(t, "AppHints", ctx.AppHints, []string{"grafana", "nginx/1.27.0"})
	assertStrings(t, "PathHints", ctx.PathHints, []string{"/api/health", "/login?redirect=/"})
	assertStrings(t, "TitleHints", ctx.TitleHints, []string{"health", "login"})
	assertStrings(t, "HeaderHints", ctx.HeaderHints, []string{"content-security-policy", "server"})
	assertStrings(t, "Vulnerabilities", ctx.Vulnerabilities, []string{"CVE-2025-1234", "CWE-601"})
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
