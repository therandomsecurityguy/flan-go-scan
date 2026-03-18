package scanner

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewHostLimiterDisabledWhenNonPositive(t *testing.T) {
	if limiter := NewHostLimiter(0); limiter != nil {
		t.Fatal("expected nil limiter when maxPerHost is non-positive")
	}
}

func TestHostLimiterBoundsPerHostConcurrency(t *testing.T) {
	limiter := NewHostLimiter(2)
	if limiter == nil {
		t.Fatal("expected limiter")
	}

	var peak int64
	var current int64
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := limiter.Acquire(context.Background(), "1.2.3.4")
			if err != nil {
				t.Errorf("acquire failed: %v", err)
				return
			}
			defer release()

			val := atomic.AddInt64(&current, 1)
			for {
				old := atomic.LoadInt64(&peak)
				if val <= old || atomic.CompareAndSwapInt64(&peak, old, val) {
					break
				}
			}
			time.Sleep(10 * time.Millisecond)
			atomic.AddInt64(&current, -1)
		}()
	}

	wg.Wait()

	if peak > 2 {
		t.Fatalf("peak concurrency %d exceeded host limit 2", peak)
	}
}

func TestHostLimiterContextCancellation(t *testing.T) {
	limiter := NewHostLimiter(1)
	release, err := limiter.Acquire(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatalf("initial acquire failed: %v", err)
	}
	defer release()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	if _, err := limiter.Acquire(ctx, "1.2.3.4"); err == nil {
		t.Fatal("expected acquire to fail when context is cancelled")
	}
}
