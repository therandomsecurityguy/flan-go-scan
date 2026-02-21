package scanner

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestWorkerPoolBoundsConcurrency(t *testing.T) {
	pool := NewWorkerPool(5)
	var peak int64
	var current int64
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		pool.Acquire()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer pool.Release()
			val := atomic.AddInt64(&current, 1)
			for {
				old := atomic.LoadInt64(&peak)
				if val <= old || atomic.CompareAndSwapInt64(&peak, old, val) {
					break
				}
			}
			atomic.AddInt64(&current, -1)
		}()
	}

	wg.Wait()

	if peak > 5 {
		t.Errorf("peak concurrency %d exceeded pool size 5", peak)
	}
}

func TestWorkerPoolDefaultSize(t *testing.T) {
	pool := NewWorkerPool(0)
	if cap(pool.sem) != 100 {
		t.Errorf("expected default size 100, got %d", cap(pool.sem))
	}
}
