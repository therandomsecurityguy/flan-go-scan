package verify

import "testing"

func TestExpandCandidateRequestsOpenRedirect(t *testing.T) {
	requests := ExpandCandidateRequests(CandidateCheck{
		Family: "open-redirect",
		Surface: &Surface{
			Path:        "/login?redirect=/",
			Params:      []string{"redirect"},
			MethodHints: []string{"GET"},
		},
	}, PayloadConfig{
		MaxPayloadsPerCandidate: 3,
		ExternalRedirectTarget:  "https://verify.invalid/flan",
	})

	if got, want := len(requests), 3; got != want {
		t.Fatalf("len(requests) = %d, want %d", got, want)
	}
	if got, want := requests[0].Label, "absolute-external:redirect"; got != want {
		t.Fatalf("requests[0].Label = %q, want %q", got, want)
	}
	if got, want := requests[0].Path, "/login?redirect=https%3A%2F%2Fverify.invalid%2Fflan"; got != want {
		t.Fatalf("requests[0].Path = %q, want %q", got, want)
	}
}

func TestExpandCandidateRequestsPreservesPreEncodedPayloads(t *testing.T) {
	requests := ExpandCandidateRequests(CandidateCheck{
		Family: "open-redirect",
		Surface: &Surface{
			Path:        "/login?Redirect=/",
			Params:      []string{"redirect"},
			MethodHints: []string{"GET"},
		},
	}, PayloadConfig{
		MaxPayloadsPerCandidate: 3,
	})

	if got, want := requests[2].Label, "encoded-external:redirect"; got != want {
		t.Fatalf("requests[2].Label = %q, want %q", got, want)
	}
	if got, want := requests[2].Path, "/login?Redirect=https:%2f%2fverify.invalid%2fflan"; got != want {
		t.Fatalf("requests[2].Path = %q, want %q", got, want)
	}
}

func TestExpandCandidateRequestsTraversalRead(t *testing.T) {
	requests := ExpandCandidateRequests(CandidateCheck{
		Family: "traversal-read",
		Surface: &Surface{
			Path:        "/download?file=report.txt",
			Params:      []string{"file"},
			MethodHints: []string{"GET"},
		},
	}, PayloadConfig{
		MaxPayloadsPerCandidate: 2,
	})

	if got, want := len(requests), 2; got != want {
		t.Fatalf("len(requests) = %d, want %d", got, want)
	}
	if got, want := requests[0].Label, "unix-passwd:file"; got != want {
		t.Fatalf("requests[0].Label = %q, want %q", got, want)
	}
	if got, want := requests[1].Path, "/download?file=..%2f..%2f..%2f..%2fetc/passwd"; got != want {
		t.Fatalf("requests[1].Path = %q, want %q", got, want)
	}
}

func TestExpandCandidateRequestsFallsBackToBaseline(t *testing.T) {
	requests := ExpandCandidateRequests(CandidateCheck{
		Family: "unauth-api",
		Surface: &Surface{
			Path:        "/v1/sys/health",
			MethodHints: []string{"GET"},
		},
	}, DefaultPayloadConfig())

	if got, want := len(requests), 1; got != want {
		t.Fatalf("len(requests) = %d, want %d", got, want)
	}
	if got, want := requests[0].Label, "baseline"; got != want {
		t.Fatalf("requests[0].Label = %q, want %q", got, want)
	}
}
