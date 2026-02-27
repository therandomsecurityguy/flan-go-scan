package scanner

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestInspectHeadersReturnsProbeFailureFinding(t *testing.T) {
	findings := InspectHeaders(context.Background(), "http", "127.0.0.1", "", 1, 50*time.Millisecond)
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for unreachable host")
	}
	if findings[0].Header != "HTTP Probe" {
		t.Fatalf("expected HTTP Probe finding, got %q", findings[0].Header)
	}
	if !strings.Contains(findings[0].Detail, "failed") {
		t.Fatalf("expected probe failure detail, got %q", findings[0].Detail)
	}
}

func TestIsInternalIP(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{value: "10.0.0.5", want: true},
		{value: "172.20.1.7", want: true},
		{value: "192.168.1.12", want: true},
		{value: "127.0.0.1", want: true},
		{value: "8.8.8.8", want: false},
		{value: "for=10.1.1.2, for=8.8.8.8", want: true},
	}

	for _, tc := range cases {
		got := isInternalIP(tc.value)
		if got != tc.want {
			t.Fatalf("isInternalIP(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}
