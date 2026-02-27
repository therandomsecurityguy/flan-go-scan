package scanner

import (
	"context"
	"testing"
	"time"
)

func TestRateLimiterClampsNonPositiveRate(t *testing.T) {
	rl := NewRateLimiter(0)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := rl.Wait(ctx); err != nil {
		t.Fatalf("first wait should succeed with clamped rate: %v", err)
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()
	if err := rl.Wait(ctx2); err == nil {
		t.Fatal("second immediate wait should be rate-limited")
	}
}
