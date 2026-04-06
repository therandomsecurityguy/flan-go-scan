package verify

import (
	"strconv"
	"strings"

	"github.com/therandomsecurityguy/flan-go-scan/internal/scanner"
)

var inferredProductSurfacePaths = map[string][]string{
	"graphql":          {"/graphql"},
	"kubernetes":       {"/version", "/api", "/apis"},
	"hashicorp vault":  {"/v1/sys/health"},
	"vault":            {"/v1/sys/health"},
	"hashicorp consul": {"/v1/agent/self"},
	"consul":           {"/v1/agent/self"},
}

func inferredSurfacesFromScanResult(result scanner.ScanResult, existing []Surface) []Surface {
	if !scanner.IsHTTPService(result.Service, result.Port, result.TLS != nil) {
		return nil
	}

	pathsSeen := make(map[string]struct{}, len(existing))
	for _, surface := range existing {
		pathsSeen[normalizeSurfacePath(surface.Path)] = struct{}{}
	}

	inferred := make([]Surface, 0, 4)
	if _, ok := pathsSeen["/"]; !ok {
		inferred = append(inferred, newSurface("service", "/"))
		pathsSeen["/"] = struct{}{}
	}

	for _, path := range inferredProductPaths(result) {
		normalized := normalizeSurfacePath(path)
		if _, ok := pathsSeen[normalized]; ok {
			continue
		}
		inferred = append(inferred, newSurface("inferred", normalized))
		pathsSeen[normalized] = struct{}{}
	}

	return inferred
}

func inferredProductPaths(result scanner.ScanResult) []string {
	keys := make([]string, 0, len(result.Products)+len(result.Kubernetes)+1)
	for _, product := range result.Products {
		if product.Name == "" {
			continue
		}
		keys = append(keys, strings.ToLower(strings.TrimSpace(product.Name)))
	}
	if result.App != nil {
		for _, product := range result.App.Products {
			if product.Name == "" {
				continue
			}
			keys = append(keys, strings.ToLower(strings.TrimSpace(product.Name)))
		}
	}
	if len(result.Kubernetes) > 0 {
		keys = append(keys, "kubernetes")
	}

	paths := make([]string, 0, 4)
	for _, key := range dedupeStrings(keys) {
		paths = append(paths, inferredProductSurfacePaths[key]...)
	}
	return dedupeStrings(paths)
}

func newSurface(source, path string) Surface {
	surface := Surface{
		Source:      source,
		Path:        normalizeSurfacePath(path),
		MethodHints: []string{"GET"},
		Params:      pathParamNames(path),
	}
	surface.AuthHints = authHintsForSurface(surface)
	return surface
}

func authHintsForSurface(surface Surface) []string {
	textParts := []string{
		strings.ToLower(surface.Path),
		strings.ToLower(surface.Title),
		strings.ToLower(surface.RedirectTo),
	}
	textParts = append(textParts, surface.Params...)
	text := strings.Join(textParts, " ")

	hints := make([]string, 0, 3)
	if containsAnyHint(text, []string{"login", "signin", "sign-in", "auth", "logout"}) {
		hints = append(hints, "login")
	}
	if containsAnyHint(text, []string{"admin", "dashboard", "console", "backoffice"}) {
		hints = append(hints, "admin")
	}
	if containsAnyHint(text, []string{"redirect_uri", "client_id", "response_type", "scope", "state", "oauth"}) {
		hints = append(hints, "oauth")
	}
	return dedupeStrings(hints)
}

func containsAnyHint(text string, patterns []string) bool {
	for _, pattern := range patterns {
		if strings.Contains(text, pattern) {
			return true
		}
	}
	return false
}

func surfaceKey(surface Surface) string {
	return strings.Join([]string{
		surface.Source,
		normalizeSurfacePath(surface.Path),
		strings.Join(surface.MethodHints, ","),
		strings.Join(surface.Params, ","),
		strings.Join(surface.AuthHints, ","),
		strconv.Itoa(surface.StatusCode),
		surface.ContentType,
		surface.Title,
		surface.RedirectTo,
	}, "\x00")
}
