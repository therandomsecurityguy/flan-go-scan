package scanner

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"
)

type Progress struct {
	HostsTotal    int64
	HostsDone     atomic.Int64
	PortsScanned  atomic.Int64
	ServicesFound atomic.Int64
	start         time.Time
}

func NewProgress(hostsTotal int) *Progress {
	return &Progress{
		HostsTotal: int64(hostsTotal),
		start:      time.Now(),
	}
}

func (p *Progress) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			slog.Info("scan progress",
				"hosts_total", p.HostsTotal,
				"hosts_done", p.HostsDone.Load(),
				"ports_scanned", p.PortsScanned.Load(),
				"services_found", p.ServicesFound.Load(),
				"elapsed", time.Since(p.start).Round(time.Second),
			)
		}
	}
}
