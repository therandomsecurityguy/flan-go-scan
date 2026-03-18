package scanner

import (
	"context"
	"sync"

	"golang.org/x/sync/semaphore"
)

type HostLimiter struct {
	limit int64
	mu    sync.RWMutex
	hosts map[string]*semaphore.Weighted
}

func NewHostLimiter(maxPerHost int) *HostLimiter {
	if maxPerHost <= 0 {
		return nil
	}
	return &HostLimiter{
		limit: int64(maxPerHost),
		hosts: make(map[string]*semaphore.Weighted),
	}
}

func (h *HostLimiter) Acquire(ctx context.Context, host string) (func(), error) {
	if h == nil {
		return func() {}, nil
	}
	sem := h.getOrCreate(host)
	if err := sem.Acquire(ctx, 1); err != nil {
		return nil, err
	}
	return func() {
		sem.Release(1)
	}, nil
}

func (h *HostLimiter) getOrCreate(host string) *semaphore.Weighted {
	h.mu.RLock()
	sem, ok := h.hosts[host]
	h.mu.RUnlock()
	if ok {
		return sem
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if sem, ok := h.hosts[host]; ok {
		return sem
	}
	sem = semaphore.NewWeighted(h.limit)
	h.hosts[host] = sem
	return sem
}
