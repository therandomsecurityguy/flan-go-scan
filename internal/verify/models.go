package verify

import (
	"net/url"
	"slices"
	"strings"

	"github.com/therandomsecurityguy/flan-go-scan/internal/scanner"
)

type Surface struct {
	Source      string   `json:"source"`
	Path        string   `json:"path"`
	MethodHints []string `json:"method_hints,omitempty"`
	Params      []string `json:"params,omitempty"`
	AuthHints   []string `json:"auth_hints,omitempty"`
	StatusCode  int      `json:"status_code,omitempty"`
	ContentType string   `json:"content_type,omitempty"`
	Title       string   `json:"title,omitempty"`
	RedirectTo  string   `json:"redirect_to,omitempty"`
}

// maxSurfacesPerResult bounds how many HTTP surfaces a single scan result can
// contribute to nuclei verification runs.
const maxSurfacesPerResult = 25

func SurfacesFromScanResult(result scanner.ScanResult) []Surface {
	crawl := make([]Surface, 0, len(result.Endpoints))
	for _, endpoint := range result.Endpoints {
		if !crawlEndpointAlive(endpoint) {
			continue
		}
		crawl = append(crawl, SurfaceFromCrawlResult(endpoint))
	}

	surfaces := make([]Surface, 0, len(crawl)+4)
	seen := make(map[string]struct{}, len(crawl)+4)
	addSurface := func(surface Surface) bool {
		if len(surfaces) >= maxSurfacesPerResult {
			return false
		}
		key := surfaceKey(surface)
		if _, ok := seen[key]; ok {
			return true
		}
		seen[key] = struct{}{}
		surfaces = append(surfaces, surface)
		return true
	}

	for _, surface := range inferredSurfacesFromScanResult(result, crawl) {
		if !addSurface(surface) {
			break
		}
	}
	for _, surface := range crawl {
		if !addSurface(surface) {
			break
		}
	}

	if len(surfaces) == 0 {
		return nil
	}
	return surfaces
}

// crawlEndpointAlive reports whether a crawled endpoint is worth verifying.
// Dead probe paths (404/5xx) are dropped; auth gates (401/403) are kept.
func crawlEndpointAlive(result scanner.CrawlResult) bool {
	switch result.StatusCode {
	case 401, 403:
		return true
	}
	return result.StatusCode >= 200 && result.StatusCode < 400
}

func SurfaceFromCrawlResult(result scanner.CrawlResult) Surface {
	surface := Surface{
		Source:      "crawl",
		Path:        normalizeSurfacePath(result.Path),
		MethodHints: []string{"GET"},
		Params:      pathParamNames(result.Path),
		StatusCode:  result.StatusCode,
		ContentType: result.ContentType,
		Title:       strings.TrimSpace(result.Title),
		RedirectTo:  strings.TrimSpace(result.RedirectTo),
	}
	surface.AuthHints = authHintsForSurface(surface)
	return surface
}

func normalizeSurfacePath(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "/"
	}
	if parsed, err := url.Parse(trimmed); err == nil {
		if parsed.Scheme != "" || parsed.Host != "" || parsed.Path != "" || parsed.RawQuery != "" {
			path := parsed.Path
			if path == "" {
				path = "/"
			} else if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
			if parsed.RawQuery == "" {
				return path
			}
			return path + "?" + parsed.RawQuery
		}
	}
	if strings.HasPrefix(trimmed, "/") {
		return trimmed
	}
	return "/" + trimmed
}

func pathParamNames(raw string) []string {
	parsed, err := url.Parse(normalizeSurfacePath(raw))
	if err != nil {
		return nil
	}
	keys := make([]string, 0, len(parsed.Query()))
	for key := range parsed.Query() {
		if key == "" {
			continue
		}
		keys = append(keys, strings.ToLower(key))
	}
	slices.Sort(keys)
	return dedupeStrings(keys)
}

func dedupeStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	slices.Sort(out)
	return out
}
