package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"
)

type CVE struct {
	ID       string  `json:"id"`
	Severity string  `json:"severity,omitempty"`
	Score    float64 `json:"score,omitempty"`
}

type CVELookup struct {
	client  *http.Client
	cache   map[string][]CVE
	mu      sync.RWMutex
	sf      singleflight.Group
	limiter *rate.Limiter
}

type cvssMetric struct {
	CvssData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
}

type cveMetrics struct {
	CvssV31 []cvssMetric `json:"cvssMetricV31"`
	CvssV30 []cvssMetric `json:"cvssMetricV30"`
	CvssV2  []cvssMetric `json:"cvssMetricV2"`
}

func NewCVELookup() *CVELookup {
	return &CVELookup{
		client: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 5,
				IdleConnTimeout:     30 * time.Second,
			},
		},
		cache:   make(map[string][]CVE),
		limiter: rate.NewLimiter(rate.Every(6*time.Second), 1),
	}
}

func (c *CVELookup) Lookup(ctx context.Context, cpe string) []CVE {
	if strings.Contains(cpe, ":*:*:*:*:*:*:*") {
		return nil
	}

	c.mu.RLock()
	if cached, ok := c.cache[cpe]; ok {
		c.mu.RUnlock()
		return cached
	}
	c.mu.RUnlock()

	v, err, _ := c.sf.Do(cpe, func() (interface{}, error) {
		if err := c.limiter.Wait(ctx); err != nil {
			return nil, err
		}
		cves, err := c.queryNVD(ctx, cpe)
		if err != nil {
			return nil, err
		}

		c.mu.Lock()
		c.cache[cpe] = cves
		c.mu.Unlock()

		return cves, nil
	})
	if err != nil {
		return nil
	}

	if cves, ok := v.([]CVE); ok {
		return cves
	}
	return nil
}

func (c *CVELookup) queryNVD(ctx context.Context, cpe string) ([]CVE, error) {
	u := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=%s&resultsPerPage=20", url.QueryEscape(cpe))

	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		slog.Warn("NVD request build failed", "cpe", cpe, "err", err)
		return nil, err
	}
	req.Header.Set("User-Agent", "flan/1.0")

	resp, err := c.client.Do(req)
	if err != nil {
		slog.Warn("NVD query failed", "cpe", cpe, "err", err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		slog.Warn("NVD returned non-200", "cpe", cpe, "status", resp.StatusCode)
		return nil, fmt.Errorf("unexpected NVD status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result struct {
		Vulnerabilities []struct {
			CVE struct {
				ID      string     `json:"id"`
				Metrics cveMetrics `json:"metrics"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		slog.Warn("NVD parse failed", "cpe", cpe, "err", err)
		return nil, err
	}

	var cves []CVE
	for _, v := range result.Vulnerabilities {
		cve := CVE{ID: v.CVE.ID}
		score, severity := extractCVESeverity(v.CVE.Metrics)
		if severity != "" {
			cve.Score = score
			cve.Severity = severity
		}
		cves = append(cves, cve)
	}
	return cves, nil
}

func extractCVESeverity(metrics cveMetrics) (float64, string) {
	if len(metrics.CvssV31) > 0 {
		return metrics.CvssV31[0].CvssData.BaseScore, metrics.CvssV31[0].CvssData.BaseSeverity
	}
	if len(metrics.CvssV30) > 0 {
		return metrics.CvssV30[0].CvssData.BaseScore, metrics.CvssV30[0].CvssData.BaseSeverity
	}
	if len(metrics.CvssV2) > 0 {
		return metrics.CvssV2[0].CvssData.BaseScore, metrics.CvssV2[0].CvssData.BaseSeverity
	}
	return 0, ""
}
