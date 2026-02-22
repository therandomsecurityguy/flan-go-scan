package scanner

import (
	"testing"
	"time"
)

func TestTLSVersionString(t *testing.T) {
	tests := []struct {
		version  uint16
		expected string
	}{
		{
			version:  0x0301,
			expected: "TLS1.0",
		},
		{
			version:  0x0302,
			expected: "TLS1.1",
		},
		{
			version:  0x0303,
			expected: "TLS1.2",
		},
		{
			version:  0x0304,
			expected: "TLS1.3",
		},
		{
			version:  0x0300,
			expected: "0x0300",
		},
	}

	for _, tt := range tests {
		result := tlsVersionString(tt.version)
		if result != tt.expected {
			t.Errorf("tlsVersionString(0x%04x) = %s, want %s", tt.version, result, tt.expected)
		}
	}
}

func TestInspectTLSClosedPort(t *testing.T) {
	result := InspectTLS("127.0.0.1", 1, 100*time.Millisecond)
	if result.Enabled {
		t.Error("expected TLS disabled for closed port")
	}
}
