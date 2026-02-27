package dns

import (
	"testing"
	"time"
)

func TestDefaultPassiveOptions(t *testing.T) {
	opts := DefaultPassiveOptions(3 * time.Second)
	if opts.Threads != 10 {
		t.Fatalf("unexpected default threads: %d", opts.Threads)
	}
	if opts.TimeoutSeconds != 3 {
		t.Fatalf("unexpected default timeout seconds: %d", opts.TimeoutSeconds)
	}
	if opts.MaxTimeMinutes != 5 {
		t.Fatalf("unexpected default max-time minutes: %d", opts.MaxTimeMinutes)
	}
	if len(opts.Sources) == 0 {
		t.Fatal("expected default passive sources")
	}
}

func TestRunnerOptionsFromPassiveOptions(t *testing.T) {
	opts := PassiveOptions{
		Threads:        20,
		TimeoutSeconds: 7,
		MaxTimeMinutes: 9,
		RateLimit:      15,
		Sources:        []string{"crtsh"},
		ExcludeSources: []string{"thc"},
		AllSources:     true,
		RecursiveOnly:  true,
		ProviderConfig: "/tmp/providers.yaml",
	}
	runOpts := runnerOptionsFromPassiveOptions(opts)
	if runOpts.Threads != 20 || runOpts.Timeout != 7 || runOpts.MaxEnumerationTime != 9 {
		t.Fatalf("unexpected core options mapping: %+v", runOpts)
	}
	if runOpts.RateLimit != 15 {
		t.Fatalf("unexpected rate-limit mapping: %d", runOpts.RateLimit)
	}
	if len(runOpts.Sources) != 1 || runOpts.Sources[0] != "crtsh" {
		t.Fatalf("unexpected source mapping: %v", runOpts.Sources)
	}
	if len(runOpts.ExcludeSources) != 1 || runOpts.ExcludeSources[0] != "thc" {
		t.Fatalf("unexpected excluded source mapping: %v", runOpts.ExcludeSources)
	}
	if !runOpts.All || !runOpts.OnlyRecursive {
		t.Fatalf("unexpected all/recursive mapping: all=%v recursive=%v", runOpts.All, runOpts.OnlyRecursive)
	}
	if runOpts.ProviderConfig != "/tmp/providers.yaml" {
		t.Fatalf("unexpected provider config mapping: %s", runOpts.ProviderConfig)
	}
}
