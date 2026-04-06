package verify

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

var redirectParams = map[string]struct{}{
	"callback":     {},
	"continue":     {},
	"dest":         {},
	"destination":  {},
	"next":         {},
	"redirect":     {},
	"redirect_uri": {},
	"return":       {},
	"returnto":     {},
	"target":       {},
	"url":          {},
}

var fileParams = map[string]struct{}{
	"dir":       {},
	"directory": {},
	"doc":       {},
	"document":  {},
	"download":  {},
	"file":      {},
	"filename":  {},
	"filepath":  {},
	"folder":    {},
	"page":      {},
	"path":      {},
	"template":  {},
	"view":      {},
}

func SelectCandidateChecks(ctx SelectorContext) []CandidateCheck {
	if len(ctx.Surfaces) == 0 {
		return nil
	}

	candidates := make([]CandidateCheck, 0, len(ctx.Surfaces))
	seen := make(map[string]struct{}, len(ctx.Surfaces)*2)
	addCandidate := func(candidate CandidateCheck) {
		key := candidateKey(candidate)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		candidate.Reasons = dedupeStrings(candidate.Reasons)
		candidates = append(candidates, candidate)
	}

	for i := range ctx.Surfaces {
		surface := &ctx.Surfaces[i]
		if candidate, ok := selectOpenRedirectCandidate(ctx, surface); ok {
			addCandidate(candidate)
		}
		if candidate, ok := selectTraversalCandidate(ctx, surface); ok {
			addCandidate(candidate)
		}
		if candidate, ok := selectUnauthAPICandidate(ctx, surface); ok {
			addCandidate(candidate)
		}
	}

	return candidates
}

func selectOpenRedirectCandidate(ctx SelectorContext, surface *Surface) (CandidateCheck, bool) {
	reasons := make([]string, 0, 4)
	for _, param := range surface.Params {
		if _, ok := redirectParams[param]; ok {
			reasons = append(reasons, "redirect parameter: "+param)
		}
	}
	if surface.StatusCode >= 300 && surface.StatusCode < 400 {
		reasons = append(reasons, "redirect status: "+strconv.Itoa(surface.StatusCode))
	}
	if surface.RedirectTo != "" {
		reasons = append(reasons, "redirect target observed")
	}
	if pathHasAny(surface.Path, []string{"/redirect", "/continue", "/callback", "/return", "/logout", "/out", "/jump"}) {
		reasons = append(reasons, "redirect path anchor")
	}
	if slices.Contains(surface.AuthHints, "oauth") {
		reasons = append(reasons, "oauth auth hint")
	}
	if len(reasons) == 0 {
		return CandidateCheck{}, false
	}

	return CandidateCheck{
		CheckID: "generic-web/open-redirect",
		Family:  "open-redirect",
		Adapter: "generic-web",
		Asset:   ctx.Asset,
		Surface: surface,
		Reasons: reasons,
	}, true
}

func selectTraversalCandidate(ctx SelectorContext, surface *Surface) (CandidateCheck, bool) {
	reasons := make([]string, 0, 4)
	adapter := "generic-web"

	for _, param := range surface.Params {
		if _, ok := fileParams[param]; ok {
			reasons = append(reasons, "file parameter: "+param)
		}
	}
	if pathHasAny(surface.Path, []string{"/download", "/export", "/file", "/files", "/render", "/template", "/view"}) {
		reasons = append(reasons, "file path anchor")
	}
	if hasHint(ctx.ProductHints, "grafana") && pathHasAny(surface.Path, []string{"/public/", "/public/plugins/"}) {
		adapter = "grafana"
		reasons = append(reasons, "product hint: grafana")
		reasons = append(reasons, "grafana public path anchor")
	}
	if len(reasons) == 0 {
		return CandidateCheck{}, false
	}

	return CandidateCheck{
		CheckID: adapter + "/traversal-read",
		Family:  "traversal-read",
		Adapter: adapter,
		Asset:   ctx.Asset,
		Surface: surface,
		Reasons: reasons,
	}, true
}

func selectUnauthAPICandidate(ctx SelectorContext, surface *Surface) (CandidateCheck, bool) {
	type platformRule struct {
		product string
		adapter string
		paths   []string
	}

	rules := []platformRule{
		{product: "kubernetes", adapter: "kubernetes", paths: []string{"/api", "/apis", "/version"}},
		{product: "hashicorp vault", adapter: "vault", paths: []string{"/v1/"}},
		{product: "vault", adapter: "vault", paths: []string{"/v1/"}},
		{product: "hashicorp consul", adapter: "consul", paths: []string{"/v1/"}},
		{product: "consul", adapter: "consul", paths: []string{"/v1/"}},
	}

	for _, rule := range rules {
		if !hasHint(ctx.ProductHints, rule.product) {
			continue
		}
		if !pathHasAny(surface.Path, rule.paths) {
			continue
		}
		return CandidateCheck{
			CheckID: rule.adapter + "/unauth-api",
			Family:  "unauth-api",
			Adapter: rule.adapter,
			Asset:   ctx.Asset,
			Surface: surface,
			Reasons: []string{
				"product hint: " + rule.product,
				"path anchor: " + normalizeSurfacePath(surface.Path),
			},
		}, true
	}

	return CandidateCheck{}, false
}

func hasHint(values []string, want string) bool {
	want = strings.ToLower(strings.TrimSpace(want))
	for _, value := range values {
		if strings.ToLower(strings.TrimSpace(value)) == want {
			return true
		}
	}
	return false
}

func pathHasAny(path string, patterns []string) bool {
	normalized := strings.ToLower(normalizeSurfacePath(path))
	for _, pattern := range patterns {
		if strings.Contains(normalized, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

func candidateKey(candidate CandidateCheck) string {
	path := ""
	if candidate.Surface != nil {
		path = normalizeSurfacePath(candidate.Surface.Path)
	}
	return fmt.Sprintf("%s\x00%s\x00%d\x00%s\x00%s", candidate.Family, candidate.Adapter, candidate.Asset.Port, candidate.Asset.Host, path)
}
