package kubernetes

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateUsesDefaultContext(t *testing.T) {
	server := newKubeVersionServer(t)
	client := NewClient(2 * time.Second)
	target, err := client.Validate(t.Context(), ValidateOptions{
		Kubeconfig: writeKubeconfig(t, server, "prod"),
	})
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	if target.Context != "prod" {
		t.Fatalf("unexpected context: %s", target.Context)
	}
	if target.Cluster != "prod-cluster" {
		t.Fatalf("unexpected cluster: %s", target.Cluster)
	}
	if target.Server != server.URL {
		t.Fatalf("unexpected server: %s", target.Server)
	}
}

func TestValidateUsesExplicitContext(t *testing.T) {
	server := newKubeVersionServer(t)
	client := NewClient(2 * time.Second)
	path := writeMultiContextKubeconfig(t, server)
	target, err := client.Validate(t.Context(), ValidateOptions{
		Kubeconfig: path,
		Context:    "staging",
	})
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	if target.Context != "staging" {
		t.Fatalf("unexpected context: %s", target.Context)
	}
	if target.Cluster != "staging-cluster" {
		t.Fatalf("unexpected cluster: %s", target.Cluster)
	}
}

func TestValidateRejectsMissingContext(t *testing.T) {
	server := newKubeVersionServer(t)
	client := NewClient(2 * time.Second)
	_, err := client.Validate(t.Context(), ValidateOptions{
		Kubeconfig: writeKubeconfig(t, server, "prod"),
		Context:    "missing",
	})
	if err == nil || !strings.Contains(err.Error(), `context "missing" not found`) {
		t.Fatalf("expected missing context error, got %v", err)
	}
}

func TestValidateRejectsUnreachableCluster(t *testing.T) {
	client := NewClient(200 * time.Millisecond)
	_, err := client.Validate(context.Background(), ValidateOptions{
		Kubeconfig: writeKubeconfigURL(t, "https://127.0.0.1:1", nil, "prod"),
	})
	if err == nil || !strings.Contains(err.Error(), "validate kubernetes cluster") {
		t.Fatalf("expected unreachable cluster error, got %v", err)
	}
}

func TestResolveUsesKubeconfigEnvFallback(t *testing.T) {
	server := newKubeVersionServer(t)
	path := writeKubeconfig(t, server, "prod")
	if err := os.Setenv("KUBECONFIG", path); err != nil {
		t.Fatalf("setenv: %v", err)
	}
	t.Cleanup(func() { _ = os.Unsetenv("KUBECONFIG") })

	target, cfg, err := NewClient(time.Second).resolve(ValidateOptions{})
	if err != nil {
		t.Fatalf("resolve returned error: %v", err)
	}
	if target.Kubeconfig != path {
		t.Fatalf("unexpected kubeconfig path: %s", target.Kubeconfig)
	}
	if cfg.Host != server.URL {
		t.Fatalf("unexpected host: %s", cfg.Host)
	}
}

func newKubeVersionServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/version" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"gitVersion":"v1.31.0"}`))
	}))
	t.Cleanup(server.Close)
	return server
}

func writeKubeconfig(t *testing.T, server *httptest.Server, currentContext string) string {
	t.Helper()
	return writeKubeconfigURL(t, server.URL, server.Certificate(), currentContext)
}

func writeKubeconfigURL(t *testing.T, serverURL string, cert *x509.Certificate, currentContext string) string {
	t.Helper()
	clusterAuth := "    insecure-skip-tls-verify: true"
	if cert != nil {
		clusterAuth = "    certificate-authority-data: " + encodeCertAuthority(cert)
	}
	body := strings.TrimSpace(`
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: ` + serverURL + `
` + clusterAuth + `
  name: prod-cluster
contexts:
- context:
    cluster: prod-cluster
    user: prod-user
  name: prod
current-context: ` + currentContext + `
users:
- name: prod-user
  user:
    token: test-token
`)
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	return path
}

func writeMultiContextKubeconfig(t *testing.T, server *httptest.Server) string {
	t.Helper()
	caData := encodeCertAuthority(server.Certificate())
	body := strings.TrimSpace(`
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: ` + server.URL + `
    certificate-authority-data: ` + caData + `
  name: prod-cluster
- cluster:
    server: ` + server.URL + `
    certificate-authority-data: ` + caData + `
  name: staging-cluster
contexts:
- context:
    cluster: prod-cluster
    user: prod-user
  name: prod
- context:
    cluster: staging-cluster
    user: staging-user
  name: staging
current-context: prod
users:
- name: prod-user
  user:
    token: prod-token
- name: staging-user
  user:
    token: staging-token
`)
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	return path
}

func encodeCertAuthority(cert *x509.Certificate) string {
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return base64.StdEncoding.EncodeToString(pemBlock)
}
