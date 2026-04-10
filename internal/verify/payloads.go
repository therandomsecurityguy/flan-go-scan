package verify

import (
	"net/http"
	"net/url"
	"strings"
)

const defaultExternalRedirectTarget = "https://verify.invalid/flan"
const openRedirectControlLabel = "baseline-control"

type PayloadConfig struct {
	MaxPayloadsPerCandidate int
	ExternalRedirectTarget  string
}

type GeneratedRequest struct {
	Label   string            `json:"label"`
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

func DefaultPayloadConfig() PayloadConfig {
	return PayloadConfig{
		MaxPayloadsPerCandidate: 4,
		ExternalRedirectTarget:  defaultExternalRedirectTarget,
	}
}

func ExpandCandidateRequests(candidate CandidateCheck, cfg PayloadConfig) []GeneratedRequest {
	cfg = normalizePayloadConfig(cfg)
	switch candidate.Family {
	case "open-redirect":
		if requests := expandOpenRedirectRequests(candidate, cfg); len(requests) > 0 {
			return requests
		}
	case "traversal-read":
		if requests := expandTraversalRequests(candidate, cfg); len(requests) > 0 {
			return requests
		}
	}
	return []GeneratedRequest{baselineGeneratedRequest(candidate)}
}

func normalizePayloadConfig(cfg PayloadConfig) PayloadConfig {
	if cfg.MaxPayloadsPerCandidate <= 0 {
		cfg.MaxPayloadsPerCandidate = 4
	}
	if strings.TrimSpace(cfg.ExternalRedirectTarget) == "" {
		cfg.ExternalRedirectTarget = defaultExternalRedirectTarget
	}
	return cfg
}

func baselineGeneratedRequest(candidate CandidateCheck) GeneratedRequest {
	method := http.MethodGet
	if candidate.Surface != nil && len(candidate.Surface.MethodHints) > 0 {
		method = strings.ToUpper(strings.TrimSpace(candidate.Surface.MethodHints[0]))
	}
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
	default:
		method = http.MethodGet
	}
	path := "/"
	if candidate.Surface != nil {
		path = normalizeSurfacePath(candidate.Surface.Path)
	}
	return GeneratedRequest{
		Label:  "baseline",
		Method: method,
		Path:   path,
	}
}

func expandOpenRedirectRequests(candidate CandidateCheck, cfg PayloadConfig) []GeneratedRequest {
	if candidate.Surface == nil {
		return nil
	}
	redirectParams := openRedirectSinkParams(candidate.Surface)
	if len(redirectParams) == 0 {
		return nil
	}

	payloads := openRedirectPayloads(cfg)
	baseline := baselineGeneratedRequest(candidate)
	requests := make([]GeneratedRequest, 0, cfg.MaxPayloadsPerCandidate)
	if cfg.MaxPayloadsPerCandidate > 1 {
		requests = append(requests, GeneratedRequest{
			Label:  openRedirectControlLabel,
			Method: baseline.Method,
			Path:   baseline.Path,
		})
	}
	for _, param := range redirectParams {
		for _, payload := range payloads {
			if len(requests) >= cfg.MaxPayloadsPerCandidate {
				return requests
			}
			mutatedPath, ok := upsertQueryParam(candidate.Surface.Path, param, payload.value, payload.preEncoded)
			if !ok {
				continue
			}
			requests = append(requests, GeneratedRequest{
				Label:  payload.label + ":" + param,
				Method: baseline.Method,
				Path:   mutatedPath,
			})
		}
	}
	return requests
}

func openRedirectPayloads(cfg PayloadConfig) []struct {
	label      string
	value      string
	preEncoded bool
} {
	target := strings.TrimSpace(cfg.ExternalRedirectTarget)
	if target == "" {
		target = defaultExternalRedirectTarget
	}
	parsed, err := url.Parse(target)
	if err != nil || strings.TrimSpace(parsed.Host) == "" {
		target = defaultExternalRedirectTarget
		parsed, _ = url.Parse(target)
	}
	targetPath := parsed.EscapedPath()
	if targetPath == "" {
		targetPath = "/"
	}
	if parsed.RawQuery != "" {
		targetPath += "?" + parsed.RawQuery
	}
	schemeRelative := "//" + parsed.Host + targetPath
	pathConfusion := "/\\" + parsed.Host + targetPath
	encodedExternal := strings.ToLower(url.QueryEscape(target))
	return []struct {
		label      string
		value      string
		preEncoded bool
	}{
		{label: "absolute-external", value: target},
		{label: "scheme-relative", value: schemeRelative},
		{label: "encoded-external", value: encodedExternal, preEncoded: true},
		{label: "path-confusion", value: pathConfusion},
	}
}

func openRedirectSinkParams(surface *Surface) []string {
	if surface == nil {
		return nil
	}
	params := findParams(surface.Params, redirectParams)
	if len(params) > 0 {
		return params
	}

	inferred := make([]string, 0, 4)
	if hasHint(surface.AuthHints, "oauth") {
		inferred = append(inferred, "redirect_uri", "next")
	}
	if pathHasAny(surface.Path, []string{"/redirect", "/continue", "/callback", "/return", "/logout", "/out", "/jump"}) {
		inferred = append(inferred, "redirect", "next", "url")
	}
	if surface.StatusCode >= 300 && surface.StatusCode < 400 {
		inferred = append(inferred, "next", "redirect")
	}
	if strings.TrimSpace(surface.RedirectTo) != "" {
		inferred = append(inferred, "redirect", "url")
	}
	inferred = dedupeStringsInOrder(inferred)
	if len(inferred) > 3 {
		return inferred[:3]
	}
	return inferred
}

func expandTraversalRequests(candidate CandidateCheck, cfg PayloadConfig) []GeneratedRequest {
	if candidate.Surface == nil {
		return nil
	}
	fileParams := findParams(candidate.Surface.Params, fileParams)
	if len(fileParams) == 0 {
		return nil
	}

	payloads := []struct {
		label      string
		value      string
		preEncoded bool
	}{
		{label: "unix-passwd", value: "../../../../etc/passwd"},
		{label: "encoded-unix-passwd", value: "..%2f..%2f..%2f..%2fetc/passwd", preEncoded: true},
		{label: "windows-ini", value: `..\..\..\..\windows\win.ini`},
	}

	requests := make([]GeneratedRequest, 0, cfg.MaxPayloadsPerCandidate)
	for _, param := range fileParams {
		for _, payload := range payloads {
			if len(requests) >= cfg.MaxPayloadsPerCandidate {
				return requests
			}
			mutatedPath, ok := mutateQueryParam(candidate.Surface.Path, param, payload.value, payload.preEncoded)
			if !ok {
				continue
			}
			requests = append(requests, GeneratedRequest{
				Label:  payload.label + ":" + param,
				Method: baselineGeneratedRequest(candidate).Method,
				Path:   mutatedPath,
			})
		}
	}
	return requests
}

func findParams(params []string, familyParams map[string]struct{}) []string {
	out := make([]string, 0, len(params))
	for _, param := range params {
		if _, ok := familyParams[strings.ToLower(strings.TrimSpace(param))]; ok {
			out = append(out, strings.ToLower(strings.TrimSpace(param)))
		}
	}
	return dedupeStrings(out)
}

func mutateQueryParam(rawPath, param, value string, preEncoded bool) (string, bool) {
	parsed, err := url.Parse(normalizeSurfacePath(rawPath))
	if err != nil {
		return "", false
	}
	if parsed.RawQuery == "" {
		return "", false
	}
	parts := strings.Split(parsed.RawQuery, "&")
	mutated := false
	for i, part := range parts {
		if part == "" {
			continue
		}
		key, _, _ := strings.Cut(part, "=")
		decodedKey, err := url.QueryUnescape(key)
		if err != nil {
			decodedKey = key
		}
		if !strings.EqualFold(decodedKey, param) {
			continue
		}
		encodedValue := url.QueryEscape(value)
		if preEncoded {
			encodedValue = value
		}
		parts[i] = key + "=" + encodedValue
		mutated = true
	}
	if !mutated {
		return "", false
	}
	parsed.RawQuery = strings.Join(parts, "&")
	return normalizeSurfacePath(parsed.Path + "?" + parsed.RawQuery), true
}

func upsertQueryParam(rawPath, param, value string, preEncoded bool) (string, bool) {
	if mutated, ok := mutateQueryParam(rawPath, param, value, preEncoded); ok {
		return mutated, true
	}
	parsed, err := url.Parse(normalizeSurfacePath(rawPath))
	if err != nil {
		return "", false
	}
	encodedValue := url.QueryEscape(value)
	if preEncoded {
		encodedValue = value
	}
	fragment := url.QueryEscape(param) + "=" + encodedValue
	if parsed.RawQuery == "" {
		parsed.RawQuery = fragment
	} else {
		parsed.RawQuery += "&" + fragment
	}
	return normalizeSurfacePath(parsed.Path + "?" + parsed.RawQuery), true
}

func dedupeStringsInOrder(values []string) []string {
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
	return out
}
