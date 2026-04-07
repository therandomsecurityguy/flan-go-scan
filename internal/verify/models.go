package verify

import (
	"encoding/json"
	"net/url"
	"slices"
	"strings"

	"github.com/therandomsecurityguy/flan-go-scan/internal/scanner"
)

type Asset struct {
	Host       string                       `json:"host"`
	Hostname   string                       `json:"hostname,omitempty"`
	Port       int                          `json:"port"`
	Protocol   string                       `json:"protocol"`
	Service    string                       `json:"service,omitempty"`
	Version    string                       `json:"version,omitempty"`
	Banner     string                       `json:"banner,omitempty"`
	CDN        string                       `json:"cdn,omitempty"`
	PTR        string                       `json:"ptr,omitempty"`
	ASN        string                       `json:"asn,omitempty"`
	Org        string                       `json:"org,omitempty"`
	TLS        *scanner.TLSResult           `json:"tls,omitempty"`
	Metadata   json.RawMessage              `json:"metadata,omitempty"`
	App        *scanner.AppFingerprint      `json:"app,omitempty"`
	Products   []scanner.ProductFingerprint `json:"products,omitempty"`
	Kubernetes []scanner.KubernetesOrigin   `json:"kubernetes,omitempty"`
}

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

type SelectorContext struct {
	Asset           Asset                   `json:"asset"`
	Surfaces        []Surface               `json:"surfaces,omitempty"`
	ProductHints    []string                `json:"product_hints,omitempty"`
	AppHints        []string                `json:"app_hints,omitempty"`
	PathHints       []string                `json:"path_hints,omitempty"`
	AuthHints       []string                `json:"auth_hints,omitempty"`
	TitleHints      []string                `json:"title_hints,omitempty"`
	HeaderHints     []string                `json:"header_hints,omitempty"`
	Vulnerabilities []string                `json:"vulnerabilities,omitempty"`
	SecurityHeaders []scanner.HeaderFinding `json:"security_headers,omitempty"`
}

type CandidateCheck struct {
	CheckID string   `json:"check_id"`
	Family  string   `json:"family"`
	Adapter string   `json:"adapter,omitempty"`
	Asset   Asset    `json:"asset"`
	Surface *Surface `json:"surface,omitempty"`
	Reasons []string `json:"reasons,omitempty"`
}

type HTTPRequestEvidence struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

type HTTPResponseEvidence struct {
	StatusCode int                 `json:"status_code"`
	Headers    map[string][]string `json:"headers,omitempty"`
	Body       string              `json:"body,omitempty"`
}

type MatchResult struct {
	Name   string `json:"name"`
	Detail string `json:"detail,omitempty"`
}

type Evidence struct {
	Matcher  string                `json:"matcher,omitempty"`
	Detail   string                `json:"detail,omitempty"`
	Curl     string                `json:"curl,omitempty"`
	Request  *HTTPRequestEvidence  `json:"request,omitempty"`
	Response *HTTPResponseEvidence `json:"response,omitempty"`
	Matches  []MatchResult         `json:"matches,omitempty"`
}

type Finding struct {
	ID          string   `json:"id"`
	CheckID     string   `json:"check_id"`
	Family      string   `json:"family"`
	Adapter     string   `json:"adapter,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	Confidence  string   `json:"confidence,omitempty"`
	Asset       Asset    `json:"asset"`
	Surface     *Surface `json:"surface,omitempty"`
	Reasons     []string `json:"reasons,omitempty"`
	References  []string `json:"references,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Evidence    Evidence `json:"evidence"`
}

func AssetFromScanResult(result scanner.ScanResult) Asset {
	return Asset{
		Host:       result.Host,
		Hostname:   result.Hostname,
		Port:       result.Port,
		Protocol:   result.Protocol,
		Service:    result.Service,
		Version:    result.Version,
		Banner:     result.Banner,
		CDN:        result.CDN,
		PTR:        result.PTR,
		ASN:        result.ASN,
		Org:        result.Org,
		TLS:        result.TLS,
		Metadata:   result.Metadata,
		App:        result.App,
		Products:   scanner.MergeProductFingerprints(result.Products, appProducts(result.App)),
		Kubernetes: slices.Clone(result.Kubernetes),
	}
}

func SurfacesFromScanResult(result scanner.ScanResult) []Surface {
	seen := make(map[string]struct{}, len(result.Endpoints)+4)
	surfaces := make([]Surface, 0, len(result.Endpoints)+4)
	addSurface := func(surface Surface) {
		key := surfaceKey(surface)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		surfaces = append(surfaces, surface)
	}

	for _, endpoint := range result.Endpoints {
		addSurface(SurfaceFromCrawlResult(endpoint))
	}
	for _, surface := range inferredSurfacesFromScanResult(result, surfaces) {
		addSurface(surface)
	}

	if len(surfaces) == 0 {
		return nil
	}
	return surfaces
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

func SelectorContextFromScanResult(result scanner.ScanResult) SelectorContext {
	asset := AssetFromScanResult(result)
	surfaces := SurfacesFromScanResult(result)

	return SelectorContext{
		Asset:           asset,
		Surfaces:        surfaces,
		ProductHints:    selectorProductHints(asset),
		AppHints:        appHints(result.App),
		PathHints:       surfacePaths(surfaces),
		AuthHints:       surfaceAuthHints(surfaces),
		TitleHints:      surfaceTitles(surfaces),
		HeaderHints:     headerHints(result.SecurityHeaders),
		Vulnerabilities: dedupeStrings(result.Vulnerabilities),
		SecurityHeaders: slices.Clone(result.SecurityHeaders),
	}
}

func selectorProductHints(asset Asset) []string {
	hints := productHints(asset.Products)
	if len(asset.Kubernetes) > 0 {
		hints = append(hints, "kubernetes")
	}
	return dedupeStrings(hints)
}

func normalizeSurfacePath(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "/"
	}
	if parsed, err := url.Parse(trimmed); err == nil {
		if parsed.Path != "" || parsed.RawQuery != "" {
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

func appProducts(app *scanner.AppFingerprint) []scanner.ProductFingerprint {
	if app == nil {
		return nil
	}
	return app.Products
}

func productHints(products []scanner.ProductFingerprint) []string {
	hints := make([]string, 0, len(products))
	for _, product := range products {
		if product.Name == "" {
			continue
		}
		hints = append(hints, strings.ToLower(product.Name))
	}
	return dedupeStrings(hints)
}

func appHints(app *scanner.AppFingerprint) []string {
	if app == nil {
		return nil
	}
	hints := append([]string{}, app.Apps...)
	for _, value := range []string{app.Server, app.PoweredBy, app.Generator} {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		hints = append(hints, value)
	}
	for _, product := range app.Products {
		if product.Name == "" {
			continue
		}
		hints = append(hints, product.Name)
	}
	for i := range hints {
		hints[i] = strings.ToLower(strings.TrimSpace(hints[i]))
	}
	return dedupeStrings(hints)
}

func surfacePaths(surfaces []Surface) []string {
	paths := make([]string, 0, len(surfaces))
	for _, surface := range surfaces {
		if surface.Path == "" {
			continue
		}
		paths = append(paths, surface.Path)
	}
	return dedupeStrings(paths)
}

func surfaceTitles(surfaces []Surface) []string {
	titles := make([]string, 0, len(surfaces))
	for _, surface := range surfaces {
		if surface.Title == "" {
			continue
		}
		titles = append(titles, strings.ToLower(surface.Title))
	}
	return dedupeStrings(titles)
}

func headerHints(findings []scanner.HeaderFinding) []string {
	hints := make([]string, 0, len(findings))
	for _, finding := range findings {
		detail := strings.ToLower(strings.TrimSpace(finding.Detail))
		if strings.HasPrefix(detail, "missing ") {
			continue
		}
		header := strings.ToLower(strings.TrimSpace(finding.Header))
		if header == "" || header == "http probe" {
			continue
		}
		hints = append(hints, header)
	}
	return dedupeStrings(hints)
}

func surfaceAuthHints(surfaces []Surface) []string {
	hints := make([]string, 0, len(surfaces))
	for _, surface := range surfaces {
		hints = append(hints, surface.AuthHints...)
	}
	return dedupeStrings(hints)
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
