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
		cves := c.queryNVD(ctx, cpe)

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

func (c *CVELookup) queryNVD(ctx context.Context, cpe string) []CVE {
	u := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=%s&resultsPerPage=20", url.QueryEscape(cpe))

	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		slog.Warn("NVD request build failed", "cpe", cpe, "err", err)
		return nil
	}
	req.Header.Set("User-Agent", "flan/1.0")

	resp, err := c.client.Do(req)
	if err != nil {
		slog.Warn("NVD query failed", "cpe", cpe, "err", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		slog.Warn("NVD returned non-200", "cpe", cpe, "status", resp.StatusCode)
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	var result struct {
		Vulnerabilities []struct {
			CVE struct {
				ID      string `json:"id"`
				Metrics struct {
					CvssV31 []struct {
						CvssData struct {
							BaseScore    float64 `json:"baseScore"`
							BaseSeverity string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
				} `json:"metrics"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		slog.Warn("NVD parse failed", "cpe", cpe, "err", err)
		return nil
	}

	var cves []CVE
	for _, v := range result.Vulnerabilities {
		cve := CVE{ID: v.CVE.ID}
		if len(v.CVE.Metrics.CvssV31) > 0 {
			cve.Score = v.CVE.Metrics.CvssV31[0].CvssData.BaseScore
			cve.Severity = v.CVE.Metrics.CvssV31[0].CvssData.BaseSeverity
		}
		cves = append(cves, cve)
	}
	return cves
}
