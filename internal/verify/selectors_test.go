package verify

import "testing"

func TestSelectCandidateChecksOpenRedirect(t *testing.T) {
	ctx := SelectorContext{
		Asset: Asset{Host: "192.0.2.10", Port: 443, Service: "https"},
		Surfaces: []Surface{{
			Source:      "crawl",
			Path:        "/login?redirect=/",
			Params:      []string{"redirect"},
			StatusCode:  302,
			RedirectTo:  "https://example.com",
			MethodHints: []string{"GET"},
		}},
	}

	candidates := SelectCandidateChecks(ctx)

	if got, want := len(candidates), 1; got != want {
		t.Fatalf("len(candidates) = %d, want %d", got, want)
	}
	if got, want := candidates[0].Family, "open-redirect"; got != want {
		t.Fatalf("candidates[0].Family = %q, want %q", got, want)
	}
	if got, want := candidates[0].Adapter, "generic-web"; got != want {
		t.Fatalf("candidates[0].Adapter = %q, want %q", got, want)
	}
	assertStrings(t, "Reasons", candidates[0].Reasons, []string{
		"redirect parameter: redirect",
		"redirect status: 302",
		"redirect target observed",
	})
}

func TestSelectCandidateChecksGrafanaTraversal(t *testing.T) {
	ctx := SelectorContext{
		Asset:        Asset{Host: "192.0.2.11", Port: 3000, Service: "http"},
		ProductHints: []string{"grafana"},
		Surfaces: []Surface{{
			Source:      "crawl",
			Path:        "/public/plugins/alertlist/",
			MethodHints: []string{"GET"},
		}},
	}

	candidates := SelectCandidateChecks(ctx)

	if got, want := len(candidates), 1; got != want {
		t.Fatalf("len(candidates) = %d, want %d", got, want)
	}
	if got, want := candidates[0].Family, "traversal-read"; got != want {
		t.Fatalf("candidates[0].Family = %q, want %q", got, want)
	}
	if got, want := candidates[0].Adapter, "grafana"; got != want {
		t.Fatalf("candidates[0].Adapter = %q, want %q", got, want)
	}
}

func TestSelectCandidateChecksKubernetesUnauthAPI(t *testing.T) {
	ctx := SelectorContext{
		Asset:        Asset{Host: "192.0.2.12", Port: 6443, Service: "https"},
		ProductHints: []string{"kubernetes"},
		Surfaces: []Surface{{
			Source:      "inferred",
			Path:        "/api",
			MethodHints: []string{"GET"},
		}},
	}

	candidates := SelectCandidateChecks(ctx)

	if got, want := len(candidates), 1; got != want {
		t.Fatalf("len(candidates) = %d, want %d", got, want)
	}
	if got, want := candidates[0].Family, "unauth-api"; got != want {
		t.Fatalf("candidates[0].Family = %q, want %q", got, want)
	}
	if got, want := candidates[0].Adapter, "kubernetes"; got != want {
		t.Fatalf("candidates[0].Adapter = %q, want %q", got, want)
	}
	assertStrings(t, "Reasons", candidates[0].Reasons, []string{
		"path anchor: /api",
		"product hint: kubernetes",
	})
}
