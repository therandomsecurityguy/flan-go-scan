package verify

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestExecuteCandidateChecksCapturesHTTPEvidence(t *testing.T) {
	server := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Host, "app.example.test"; got != want {
			t.Fatalf("request Host = %q, want %q", got, want)
		}
		w.Header().Set("Location", r.URL.Query().Get("redirect"))
		w.WriteHeader(http.StatusFound)
		_, _ = w.Write([]byte("redirect body"))
	}))
	defer server.Close()

	host, port := serverHostPort(t, server)
	results := ExecuteCandidateChecks(context.Background(), []CandidateCheck{{
		CheckID: "generic-web/open-redirect",
		Family:  "open-redirect",
		Adapter: "generic-web",
		Asset: Asset{
			Host:     host,
			Hostname: "app.example.test",
			Port:     port,
			Service:  "http",
		},
		Surface: &Surface{Path: "/login?redirect=/", Params: []string{"redirect"}, MethodHints: []string{"GET"}},
	}}, RuntimeConfig{
		Timeout:      2 * defaultRuntimeConfig().Timeout / 5,
		Workers:      1,
		MaxBodyBytes: 64,
		Payloads: PayloadConfig{
			MaxPayloadsPerCandidate: 1,
			ExternalRedirectTarget:  "https://verify.invalid/flan",
		},
	})

	if got, want := len(results), 1; got != want {
		t.Fatalf("len(results) = %d, want %d", got, want)
	}
	result := results[0]
	if !result.Executed {
		t.Fatalf("result.Executed = false, error=%q", result.Error)
	}
	if result.Error != "" {
		t.Fatalf("result.Error = %q, want empty", result.Error)
	}
	if got, want := result.Evidence.Response.StatusCode, http.StatusFound; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
	if got := result.Evidence.Response.Headers["Location"]; len(got) != 1 || got[0] != "https://verify.invalid/flan" {
		t.Fatalf("location header = %v, want https://verify.invalid/flan", got)
	}
	if got, want := result.Evidence.Request.Headers["Host"], "app.example.test"; got != want {
		t.Fatalf("request Host header = %q, want %q", got, want)
	}
	if got, want := len(result.Evidence.Matches), 1; got != want {
		t.Fatalf("len(result.Evidence.Matches) = %d, want %d", got, want)
	}
	if got, want := result.Evidence.Matches[0].Name, "redirect-location"; got != want {
		t.Fatalf("match name = %q, want %q", got, want)
	}
	if !strings.Contains(result.Evidence.Curl, "curl -i -X GET") {
		t.Fatalf("curl repro = %q, want GET curl", result.Evidence.Curl)
	}
	if got, want := result.Request.Label, "absolute-external:redirect"; got != want {
		t.Fatalf("request label = %q, want %q", got, want)
	}
}

func TestExecuteCandidateChecksDoesNotMatchInternalRedirect(t *testing.T) {
	server := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/dashboard")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	host, port := serverHostPort(t, server)
	results := ExecuteCandidateChecks(context.Background(), []CandidateCheck{{
		CheckID: "generic-web/open-redirect",
		Family:  "open-redirect",
		Adapter: "generic-web",
		Asset: Asset{
			Host:    host,
			Port:    port,
			Service: "http",
		},
		Surface: &Surface{Path: "/login?redirect=/", Params: []string{"redirect"}, MethodHints: []string{"GET"}},
	}}, RuntimeConfig{
		Timeout:  5 * time.Second,
		Workers:  1,
		Payloads: PayloadConfig{MaxPayloadsPerCandidate: 1},
	})

	if got, want := len(results), 1; got != want {
		t.Fatalf("len(results) = %d, want %d", got, want)
	}
	if got := len(results[0].Evidence.Matches); got != 0 {
		t.Fatalf("len(results[0].Evidence.Matches) = %d, want 0", got)
	}
}

func TestExecuteCandidateChecksUsesSafeMethodHints(t *testing.T) {
	var gotMethod string
	server := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	host, port := serverHostPort(t, server)
	results := ExecuteCandidateChecks(context.Background(), []CandidateCheck{{
		CheckID: "generic-web/head-probe",
		Family:  "open-redirect",
		Adapter: "generic-web",
		Asset: Asset{
			Host:    host,
			Port:    port,
			Service: "http",
		},
		Surface: &Surface{Path: "/", MethodHints: []string{"HEAD"}},
	}}, RuntimeConfig{
		Timeout:  5 * time.Second,
		Workers:  1,
		Payloads: PayloadConfig{MaxPayloadsPerCandidate: 1},
	})

	if got, want := len(results), 1; got != want {
		t.Fatalf("len(results) = %d, want %d", got, want)
	}
	if got, want := gotMethod, http.MethodHead; got != want {
		t.Fatalf("request method = %q, want %q", got, want)
	}
	if got, want := results[0].Evidence.Request.Method, http.MethodHead; got != want {
		t.Fatalf("evidence request method = %q, want %q", got, want)
	}
}

func TestExecuteCandidateChecksRejectsNonHTTPService(t *testing.T) {
	results := ExecuteCandidateChecks(context.Background(), []CandidateCheck{{
		CheckID: "ldap/anonymous-bind",
		Family:  "protocol-native",
		Adapter: "ldap",
		Asset: Asset{
			Host:    "192.0.2.10",
			Port:    636,
			Service: "ldap",
		},
		Surface: &Surface{Path: "/"},
	}}, DefaultRuntimeConfig())

	if got, want := len(results), 1; got != want {
		t.Fatalf("len(results) = %d, want %d", got, want)
	}
	if results[0].Executed {
		t.Fatal("expected non-http candidate not to execute")
	}
	if got, want := results[0].Error, "candidate service is not HTTP"; got != want {
		t.Fatalf("result.Error = %q, want %q", got, want)
	}
}

func TestExecuteCandidateChecksMatchesVaultUnauthAPIWithExpectedShape(t *testing.T) {
	server := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"initialized":true,"sealed":false,"standby":false}`))
	}))
	defer server.Close()

	host, port := serverHostPort(t, server)
	results := ExecuteCandidateChecks(context.Background(), []CandidateCheck{{
		CheckID: "vault/unauth-api",
		Family:  "unauth-api",
		Adapter: "vault",
		Asset: Asset{
			Host:    host,
			Port:    port,
			Service: "http",
		},
		Surface: &Surface{Path: "/v1/sys/health", MethodHints: []string{"GET"}},
	}}, RuntimeConfig{
		Timeout:  5 * time.Second,
		Workers:  1,
		Payloads: PayloadConfig{MaxPayloadsPerCandidate: 1},
	})

	if got, want := len(results), 1; got != want {
		t.Fatalf("len(results) = %d, want %d", got, want)
	}
	if got, want := len(results[0].Evidence.Matches), 1; got != want {
		t.Fatalf("len(results[0].Evidence.Matches) = %d, want %d", got, want)
	}
	if got, want := results[0].Evidence.Matches[0].Name, "reachable-api"; got != want {
		t.Fatalf("match name = %q, want %q", got, want)
	}
}

func TestExecuteCandidateChecksDoesNotMatchGeneric200AsUnauthAPI(t *testing.T) {
	server := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>ok</html>"))
	}))
	defer server.Close()

	host, port := serverHostPort(t, server)
	results := ExecuteCandidateChecks(context.Background(), []CandidateCheck{{
		CheckID: "vault/unauth-api",
		Family:  "unauth-api",
		Adapter: "vault",
		Asset: Asset{
			Host:    host,
			Port:    port,
			Service: "http",
		},
		Surface: &Surface{Path: "/v1/sys/health", MethodHints: []string{"GET"}},
	}}, RuntimeConfig{
		Timeout:  5 * time.Second,
		Workers:  1,
		Payloads: PayloadConfig{MaxPayloadsPerCandidate: 1},
	})

	if got, want := len(results), 1; got != want {
		t.Fatalf("len(results) = %d, want %d", got, want)
	}
	if got := len(results[0].Evidence.Matches); got != 0 {
		t.Fatalf("len(results[0].Evidence.Matches) = %d, want 0", got)
	}
}

func newIPv4Server(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp4: %v", err)
	}
	server.Listener = listener
	server.Start()
	return server
}

func serverHostPort(t *testing.T, server *httptest.Server) (string, int) {
	t.Helper()
	host, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	portNum, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return host, portNum
}

func defaultRuntimeConfig() RuntimeConfig {
	return DefaultRuntimeConfig()
}
