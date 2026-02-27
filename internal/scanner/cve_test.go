package scanner

import (
	"context"
	"testing"
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
