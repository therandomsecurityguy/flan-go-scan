package scanner

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestCVELookupWildcardCPEIsSkipped(t *testing.T) {
	l := NewCVELookup()
	got := l.Lookup(context.Background(), "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*")
	if got != nil {
		t.Fatalf("expected wildcard CPE to be skipped, got %+v", got)
	}
}

func TestCVELookupRespectsCanceledContext(t *testing.T) {
	l := NewCVELookup()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := l.Lookup(ctx, "cpe:2.3:a:apache:http_server:2.4.66:*:*:*:*:*:*:*")
	if got != nil {
		t.Fatalf("expected canceled lookup to return nil, got %+v", got)
	}
}

func TestCVELookupDoesNotCacheFailures(t *testing.T) {
	l := NewCVELookup()
	cpe := "cpe:2.3:a:test:svc:1.0:-:-:-:-:-:-:-"
	callCount := 0
	l.client = &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			callCount++
			return nil, errors.New("boom")
		}),
		Timeout: time.Second,
	}

	if got := l.Lookup(context.Background(), cpe); got != nil {
		t.Fatalf("expected nil on failure, got %+v", got)
	}
	if got := l.Lookup(context.Background(), cpe); got != nil {
		t.Fatalf("expected nil on repeated failure, got %+v", got)
	}
	if callCount != 2 {
		t.Fatalf("expected failure lookups not to be cached, got %d calls", callCount)
	}
}

func TestCVELookupFallsBackToOlderCVSSMetrics(t *testing.T) {
	l := NewCVELookup()
	cpe := "cpe:2.3:a:test:svc:1.0:-:-:-:-:-:-:-"
	l.client = &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			body := `{"vulnerabilities":[{"cve":{"id":"CVE-2026-0001","metrics":{"cvssMetricV30":[{"cvssData":{"baseScore":8.1,"baseSeverity":"HIGH"}}]}}}]}`
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     make(http.Header),
			}, nil
		}),
		Timeout: time.Second,
	}

	got := l.Lookup(context.Background(), cpe)
	if len(got) != 1 {
		t.Fatalf("expected one CVE, got %+v", got)
	}
	if got[0].Severity != "HIGH" || got[0].Score != 8.1 {
		t.Fatalf("unexpected CVE metadata: %+v", got[0])
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
