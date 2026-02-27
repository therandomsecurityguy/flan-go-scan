package dns

import (
	"context"
	"io"
	"log/slog"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

type PassiveOptions struct {
	Threads        int
	TimeoutSeconds int
	MaxTimeMinutes int
	RateLimit      int
	Sources        []string
	ExcludeSources []string
	AllSources     bool
	RecursiveOnly  bool
	ProviderConfig string
}

var DefaultPassiveSources = []string{
	"crtsh", "anubis", "digitorus", "thc",
	"commoncrawl", "waybackarchive", "rapiddns", "hudsonrock", "sitedossier", "threatcrowd",
}

func DefaultPassiveOptions(timeout time.Duration) PassiveOptions {
	timeoutSeconds := int(timeout.Seconds())
	if timeoutSeconds <= 0 {
		timeoutSeconds = 3
	}
	return PassiveOptions{
		Threads:        10,
		TimeoutSeconds: timeoutSeconds,
		MaxTimeMinutes: 5,
		Sources:        append([]string(nil), DefaultPassiveSources...),
	}
}

func PassiveEnumerate(ctx context.Context, domain string, opts PassiveOptions) ([]string, error) {
	if opts.Threads <= 0 {
		opts.Threads = 10
	}
	if opts.TimeoutSeconds <= 0 {
		opts.TimeoutSeconds = 3
	}
	if opts.MaxTimeMinutes <= 0 {
		opts.MaxTimeMinutes = 5
	}

	runOpts := runnerOptionsFromPassiveOptions(opts)

	r, err := runner.NewRunner(runOpts)
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

func runnerOptionsFromPassiveOptions(opts PassiveOptions) *runner.Options {
	runOpts := &runner.Options{
		Threads:            opts.Threads,
		Timeout:            opts.TimeoutSeconds,
		MaxEnumerationTime: opts.MaxTimeMinutes,
		RateLimit:          opts.RateLimit,
		Silent:             true,
		All:                opts.AllSources,
		OnlyRecursive:      opts.RecursiveOnly,
		Sources:            opts.Sources,
		ExcludeSources:     opts.ExcludeSources,
	}
	if opts.ProviderConfig != "" {
		runOpts.ProviderConfig = opts.ProviderConfig
	}
	return runOpts
}
