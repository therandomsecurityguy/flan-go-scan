package dns

import (
	"context"
	"io"
	"log/slog"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

func PassiveEnumerate(ctx context.Context, domain string, timeout time.Duration) ([]string, error) {
	opts := &runner.Options{
		Threads:            10,
		Timeout:            int(timeout.Seconds()),
		MaxEnumerationTime: 5,
		Silent:             true,
		Sources: []string{
			"crtsh", "anubis", "digitorus", "thc",
			"commoncrawl", "waybackarchive", "rapiddns", "hudsonrock", "sitedossier",
		},
	}

	r, err := runner.NewRunner(opts)
	if err != nil {
		return nil, err
	}

	results, err := r.EnumerateSingleDomainWithCtx(ctx, domain, []io.Writer{io.Discard})
	if err != nil {
		slog.Warn("passive enumeration partial failure", "domain", domain, "err", err)
	}

	var subdomains []string
	for subdomain := range results {
		subdomains = append(subdomains, subdomain)
	}

	return subdomains, nil
}
