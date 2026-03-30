package scanner

import (
	"context"
	"testing"
	"time"
)

func TestInspectTLSClosedPort(t *testing.T) {
	result := InspectTLS(context.Background(), "127.0.0.1", "", 1, 100*time.Millisecond, false)
	if result != nil {
		t.Fatal("expected nil for closed port")
	}
}
