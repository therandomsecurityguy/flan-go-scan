package verify

import (
	"net/http"
	"net/url"
	"strings"
)

const defaultExternalRedirectTarget = "https://verify.invalid/flan"

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
	redirectParams := findParams(candidate.Surface.Params, redirectParams)
	if len(redirectParams) == 0 {
		return nil
	}

	payloads := []struct {
		label      string
		value      string
		preEncoded bool
	}{
		{label: "absolute-external", value: cfg.ExternalRedirectTarget},
		{label: "scheme-relative", value: "//verify.invalid/flan"},
		{label: "encoded-external", value: "https:%2f%2fverify.invalid%2fflan", preEncoded: true},
		{label: "path-confusion", value: "/\\verify.invalid/flan"},
	}

	requests := make([]GeneratedRequest, 0, cfg.MaxPayloadsPerCandidate)
	for _, param := range redirectParams {
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
