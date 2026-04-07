package verify

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/therandomsecurityguy/flan-go-scan/internal/scanner"
)

const defaultMaxBodyBytes int64 = 8192

type RuntimeConfig struct {
	Timeout      time.Duration
	Workers      int
	MaxBodyBytes int64
	MaxRedirects int
	VerifyTLS    bool
	Payloads     PayloadConfig
}

type ExecutionResult struct {
	Candidate  CandidateCheck   `json:"candidate"`
	Request    GeneratedRequest `json:"request"`
	Executed   bool             `json:"executed"`
	DurationMS int64            `json:"duration_ms,omitempty"`
	Error      string           `json:"error,omitempty"`
	Evidence   Evidence         `json:"evidence,omitempty"`
}

func DefaultRuntimeConfig() RuntimeConfig {
	return RuntimeConfig{
		Timeout:      5 * time.Second,
		Workers:      4,
		MaxBodyBytes: defaultMaxBodyBytes,
		MaxRedirects: 0,
		Payloads:     DefaultPayloadConfig(),
	}
}

func ExecuteCandidateChecks(ctx context.Context, candidates []CandidateCheck, cfg RuntimeConfig) []ExecutionResult {
	if len(candidates) == 0 {
		return nil
	}
	cfg = normalizeRuntimeConfig(cfg)

	type job struct {
		index     int
		candidate CandidateCheck
		request   GeneratedRequest
	}

	jobsList := expandExecutionJobs(candidates, cfg.Payloads)
	results := make([]ExecutionResult, len(jobsList))
	jobs := make(chan job)
	var wg sync.WaitGroup

	for range cfg.Workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				results[job.index] = executeCandidateCheck(ctx, job.candidate, job.request, cfg)
			}
		}()
	}

	for i, jobItem := range jobsList {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			for j := i; j < len(jobsList); j++ {
				results[j] = ExecutionResult{
					Candidate: jobsList[j].candidate,
					Request:   jobsList[j].request,
					Error:     ctx.Err().Error(),
				}
			}
			return results
		case jobs <- job{index: i, candidate: jobItem.candidate, request: jobItem.request}:
		}
	}
	close(jobs)
	wg.Wait()
	return results
}

func normalizeRuntimeConfig(cfg RuntimeConfig) RuntimeConfig {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 4
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = defaultMaxBodyBytes
	}
	if cfg.MaxRedirects < 0 {
		cfg.MaxRedirects = 0
	}
	cfg.Payloads = normalizePayloadConfig(cfg.Payloads)
	return cfg
}

func expandExecutionJobs(candidates []CandidateCheck, cfg PayloadConfig) []struct {
	candidate CandidateCheck
	request   GeneratedRequest
} {
	jobs := make([]struct {
		candidate CandidateCheck
		request   GeneratedRequest
	}, 0, len(candidates))
	for _, candidate := range candidates {
		for _, request := range ExpandCandidateRequests(candidate, cfg) {
			jobs = append(jobs, struct {
				candidate CandidateCheck
				request   GeneratedRequest
			}{
				candidate: candidate,
				request:   request,
			})
		}
	}
	return jobs
}

func executeCandidateCheck(parent context.Context, candidate CandidateCheck, request GeneratedRequest, cfg RuntimeConfig) ExecutionResult {
	result := ExecutionResult{Candidate: candidate, Request: request}
	if candidate.Surface == nil {
		result.Error = "candidate has no surface"
		return result
	}
	if !scanner.IsHTTPService(candidate.Asset.Service, candidate.Asset.Port, candidate.Asset.TLS != nil) {
		result.Error = "candidate service is not HTTP"
		return result
	}

	reqURL, err := candidateURL(candidate, request)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	reqCtx, cancel := context.WithTimeout(parent, cfg.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, request.Method, reqURL, strings.NewReader(request.Body))
	if err != nil {
		result.Error = fmt.Sprintf("build request: %v", err)
		return result
	}
	req.Header.Set("User-Agent", "flan-verify/1.0")
	for key, value := range request.Headers {
		req.Header.Set(key, value)
	}
	if candidate.Asset.Hostname != "" {
		req.Host = candidate.Asset.Hostname
	}

	client := &http.Client{
		Timeout:   cfg.Timeout,
		Transport: runtimeHTTPTransport(candidate.Asset, cfg),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if cfg.MaxRedirects == 0 || len(via) >= cfg.MaxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	start := time.Now()
	resp, err := client.Do(req)
	result.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		result.Error = classifyExecutionError(err)
		return result
	}
	defer resp.Body.Close()

	body, truncated, readErr := readLimitedBody(resp.Body, cfg.MaxBodyBytes)
	if readErr != nil {
		result.Error = fmt.Sprintf("read response body: %v", readErr)
		return result
	}

	result.Executed = true
	result.Evidence = Evidence{
		Detail: baselineDetail(resp.StatusCode, truncated),
		Curl:   curlForRequest(req),
		Request: &HTTPRequestEvidence{
			Method:  req.Method,
			URL:     req.URL.String(),
			Headers: requestHeaders(req.Header),
			Body:    request.Body,
		},
		Response: &HTTPResponseEvidence{
			StatusCode: resp.StatusCode,
			Headers:    cloneHeader(resp.Header),
			Body:       body,
		},
	}
	if req.Host != "" {
		result.Evidence.Request.Headers["Host"] = req.Host
	}
	result.Evidence.Matches = evaluateExecution(candidate, request, result.Evidence)
	if len(result.Evidence.Matches) > 0 {
		result.Evidence.Matcher = result.Evidence.Matches[0].Name
	}
	return result
}

func candidateURL(candidate CandidateCheck, request GeneratedRequest) (string, error) {
	if candidate.Surface == nil {
		return "", errors.New("candidate has no surface")
	}
	host := strings.TrimSpace(candidate.Asset.Host)
	if host == "" {
		return "", errors.New("candidate asset has no host")
	}
	urlHost := host
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		urlHost = "[" + host + "]"
	}
	scheme := scanner.HTTPScheme(candidate.Asset.TLS != nil || strings.Contains(strings.ToLower(candidate.Asset.Service), "https"))
	return fmt.Sprintf("%s://%s:%d%s", scheme, urlHost, candidate.Asset.Port, normalizeSurfacePath(request.Path)), nil
}

func runtimeHTTPTransport(asset Asset, cfg RuntimeConfig) *http.Transport {
	tlsCfg := &tls.Config{InsecureSkipVerify: !cfg.VerifyTLS}
	if serverName := runtimeTLSServerName(asset.Host, asset.Hostname); serverName != "" {
		tlsCfg.ServerName = serverName
	}
	return &http.Transport{
		TLSClientConfig: tlsCfg,
	}
}

func runtimeTLSServerName(host, hostname string) string {
	if value := strings.TrimSpace(hostname); value != "" {
		return strings.TrimSuffix(value, ".")
	}
	return strings.TrimSpace(host)
}

func readLimitedBody(body io.Reader, limit int64) (string, bool, error) {
	reader := io.LimitReader(body, limit+1)
	data, err := io.ReadAll(reader)
	if err != nil {
		return "", false, err
	}
	truncated := int64(len(data)) > limit
	if truncated {
		data = data[:limit]
	}
	return string(data), truncated, nil
}

func cloneHeader(header http.Header) map[string][]string {
	if len(header) == 0 {
		return nil
	}
	out := make(map[string][]string, len(header))
	for key, values := range header {
		out[key] = append([]string(nil), values...)
	}
	return out
}

func requestHeaders(header http.Header) map[string]string {
	if len(header) == 0 {
		return nil
	}
	out := make(map[string]string, len(header))
	for key, values := range header {
		if len(values) == 0 {
			continue
		}
		out[key] = values[0]
	}
	return out
}

func baselineDetail(statusCode int, truncated bool) string {
	detail := "http response captured: status " + strconv.Itoa(statusCode)
	if truncated {
		return detail + " (body truncated)"
	}
	return detail
}

func classifyExecutionError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "request timed out"
	}
	return err.Error()
}

func curlForRequest(req *http.Request) string {
	parts := []string{"curl", "-i", "-X", req.Method, strconv.Quote(req.URL.String())}
	for key, value := range req.Header {
		for _, headerValue := range value {
			parts = append(parts, "-H", strconv.Quote(key+": "+headerValue))
		}
	}
	if req.Host != "" {
		parts = append(parts, "-H", strconv.Quote("Host: "+req.Host))
	}
	return strings.Join(parts, " ")
}

func evaluateExecution(candidate CandidateCheck, request GeneratedRequest, evidence Evidence) []MatchResult {
	if evidence.Response == nil {
		return nil
	}
	switch candidate.Family {
	case "open-redirect":
		return evaluateOpenRedirectMatch(request, evidence.Response)
	case "unauth-api":
		return evaluateUnauthAPIMatch(candidate, evidence.Response)
	default:
		return nil
	}
}

func evaluateOpenRedirectMatch(request GeneratedRequest, response *HTTPResponseEvidence) []MatchResult {
	location := firstHeaderValue(response.Headers, "Location")
	if response.StatusCode >= 300 && response.StatusCode < 400 && isExternalRedirectMatch(location, request.Path) {
		return []MatchResult{{
			Name:   "redirect-location",
			Detail: "redirect status and Location header observed: " + location,
		}}
	}
	return nil
}

func evaluateUnauthAPIMatch(candidate CandidateCheck, response *HTTPResponseEvidence) []MatchResult {
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil
	}
	if !isVerifiedUnauthAPIResponse(candidate, response) {
		return nil
	}
	detail := "reachable API response observed"
	if candidate.Surface != nil && candidate.Surface.Path != "" {
		detail = "reachable API response observed at " + normalizeSurfacePath(candidate.Surface.Path)
	}
	if contentType := firstHeaderValue(response.Headers, "Content-Type"); strings.Contains(strings.ToLower(contentType), "json") {
		detail += " (json response)"
	}
	return []MatchResult{{
		Name:   "reachable-api",
		Detail: detail,
	}}
}

func isExternalRedirectMatch(location, requestPath string) bool {
	location = strings.TrimSpace(location)
	if location == "" {
		return false
	}
	if value, ok := queryParamValue(requestPath, redirectParams); ok && strings.EqualFold(strings.TrimSpace(value), location) {
		return true
	}
	locationLower := strings.ToLower(location)
	return strings.Contains(locationLower, "verify.invalid")
}

func isVerifiedUnauthAPIResponse(candidate CandidateCheck, response *HTTPResponseEvidence) bool {
	body := strings.ToLower(strings.TrimSpace(response.Body))
	contentType := strings.ToLower(firstHeaderValue(response.Headers, "Content-Type"))
	switch candidate.Adapter {
	case "kubernetes":
		if candidate.Surface == nil {
			return false
		}
		path := normalizeSurfacePath(candidate.Surface.Path)
		switch path {
		case "/version":
			return strings.Contains(contentType, "json") && strings.Contains(body, "gitversion")
		case "/api", "/apis":
			return strings.Contains(contentType, "json") && strings.Contains(body, "versions")
		}
	case "vault":
		return strings.Contains(contentType, "json") &&
			strings.Contains(body, "\"sealed\"") &&
			strings.Contains(body, "\"initialized\"")
	case "consul":
		return strings.Contains(contentType, "json") &&
			strings.Contains(body, "\"config\"") &&
			strings.Contains(body, "\"member\"")
	}
	return false
}

func queryParamValue(rawPath string, params map[string]struct{}) (string, bool) {
	parsed, err := url.Parse(normalizeSurfacePath(rawPath))
	if err != nil {
		return "", false
	}
	query := parsed.Query()
	for key, values := range query {
		if _, ok := params[strings.ToLower(strings.TrimSpace(key))]; !ok || len(values) == 0 {
			continue
		}
		return values[0], true
	}
	return "", false
}

func firstHeaderValue(headers map[string][]string, key string) string {
	for header, values := range headers {
		if !strings.EqualFold(header, key) || len(values) == 0 {
			continue
		}
		return values[0]
	}
	return ""
}
