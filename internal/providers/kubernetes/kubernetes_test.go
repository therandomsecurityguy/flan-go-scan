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
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
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

func TestInventoryFromClient(t *testing.T) {
	clientset := fake.NewSimpleClientset(
		&networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "prod"},
			Spec: networkingv1.IngressSpec{
				Rules: []networkingv1.IngressRule{{Host: "app.example.com"}},
				TLS:   []networkingv1.IngressTLS{{Hosts: []string{"app.example.com"}}},
			},
			Status: networkingv1.IngressStatus{
				LoadBalancer: networkingv1.IngressLoadBalancerStatus{
					Ingress: []networkingv1.IngressLoadBalancerIngress{{Hostname: "alb.example.com"}},
				},
			},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "public-api", Namespace: "prod"},
			Spec: corev1.ServiceSpec{
				Type: corev1.ServiceTypeLoadBalancer,
				Ports: []corev1.ServicePort{
					{Port: 443, Protocol: corev1.ProtocolTCP},
				},
			},
			Status: corev1.ServiceStatus{
				LoadBalancer: corev1.LoadBalancerStatus{
					Ingress: []corev1.LoadBalancerIngress{{Hostname: "api-lb.example.com"}},
				},
			},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "node-app", Namespace: "prod"},
			Spec: corev1.ServiceSpec{
				Type: corev1.ServiceTypeNodePort,
				Ports: []corev1.ServicePort{
					{NodePort: 32080, Protocol: corev1.ProtocolTCP},
				},
			},
		},
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{{Type: corev1.NodeExternalIP, Address: "34.1.2.3"}},
			},
		},
	)

	target := Target{
		Context: "prod",
		Cluster: "prod-cluster",
		Server:  "https://api.cluster.example.com:6443",
	}

	items, err := inventoryFromClient(t.Context(), target, clientset)
	if err != nil {
		t.Fatalf("inventoryFromClient returned error: %v", err)
	}

	want := map[string]struct{}{
		"api.cluster.example.com:6443": {},
		"app.example.com:80":           {},
		"app.example.com:443":          {},
		"alb.example.com:80":           {},
		"alb.example.com:443":          {},
		"api-lb.example.com:443":       {},
		"34.1.2.3:32080":               {},
	}
	got := make(map[string]struct{}, len(items))
	for _, item := range items {
		got[item.Host+":"+itoa(item.Port)] = struct{}{}
	}
	for key := range want {
		if _, ok := got[key]; !ok {
			t.Fatalf("missing inventory item %s in %v", key, got)
		}
	}
}

func TestBuildInventorySnapshot(t *testing.T) {
	target := Target{
		Context: "prod",
		Cluster: "prod-cluster",
		Server:  "https://api.cluster.example.com:6443",
	}
	snapshot := BuildInventorySnapshot(time.Date(2026, 3, 24, 12, 0, 0, 0, time.UTC), target, []InventoryItem{
		{Cluster: "prod-cluster", Context: "prod", Namespace: "prod", Kind: "Ingress", Name: "web", Host: "app.example.com", Port: 443, Protocol: "https", Exposure: "ingress"},
	})

	if snapshot.Source != "kubernetes" {
		t.Fatalf("unexpected source: %s", snapshot.Source)
	}
	if snapshot.Cluster != target.Cluster || snapshot.Context != target.Context || snapshot.Server != target.Server {
		t.Fatalf("unexpected target data in snapshot: %#v", snapshot)
	}
	if snapshot.ResourceCount != 1 || len(snapshot.Resources) != 1 {
		t.Fatalf("unexpected snapshot resources: %#v", snapshot)
	}
}

func TestDiffInventory(t *testing.T) {
	previous := InventorySnapshot{
		GeneratedAt: "2026-03-24T10:00:00Z",
		Resources: []InventoryItem{
			{Cluster: "prod-cluster", Context: "prod", Namespace: "prod", Kind: "Ingress", Name: "web", Host: "old.example.com", Port: 443, Protocol: "https", Exposure: "ingress"},
			{Cluster: "prod-cluster", Context: "prod", Namespace: "prod", Kind: "Service", Name: "legacy", Host: "legacy.example.com", Port: 443, Protocol: "tcp", Exposure: "loadbalancer"},
			{Cluster: "prod-cluster", Context: "prod", Namespace: "prod", Kind: "Service", Name: "node-app", Host: "34.1.2.3", Port: 32080, Protocol: "tcp", Exposure: "nodeport"},
		},
	}
	current := InventorySnapshot{
		GeneratedAt: "2026-03-24T11:00:00Z",
		Resources: []InventoryItem{
			{Cluster: "prod-cluster", Context: "prod", Namespace: "prod", Kind: "Ingress", Name: "web", Host: "new.example.com", Port: 443, Protocol: "https", Exposure: "ingress"},
			{Cluster: "prod-cluster", Context: "prod", Namespace: "prod", Kind: "Service", Name: "node-app", Host: "34.1.2.3", Port: 32080, Protocol: "tcp", Exposure: "cluster-node"},
			{Cluster: "prod-cluster", Context: "prod", Namespace: "prod", Kind: "APIServer", Name: "kubernetes", Host: "api.cluster.example.com", Port: 6443, Protocol: "https", Exposure: "cluster"},
		},
	}

	diff := DiffInventory(time.Date(2026, 3, 24, 12, 0, 0, 0, time.UTC), previous, current)
	if diff.AddedCount != 2 {
		t.Fatalf("unexpected added count: %d", diff.AddedCount)
	}
	if diff.RemovedCount != 2 {
		t.Fatalf("unexpected removed count: %d", diff.RemovedCount)
	}
	if diff.ChangedCount != 1 {
		t.Fatalf("unexpected changed count: %d", diff.ChangedCount)
	}
}

func TestItemsFromDiff(t *testing.T) {
	diff := InventoryDiff{
		Added: []InventoryItem{
			{Host: "api.cluster.example.com", Port: 6443, Protocol: "https", Exposure: "cluster"},
			{Host: "api.cluster.example.com", Port: 6443, Protocol: "https", Exposure: "cluster"},
		},
		Changed: []InventoryItemChange{
			{After: InventoryItem{Host: "app.example.com", Port: 443, Protocol: "https", Exposure: "ingress"}},
		},
	}

	got := ItemsFromDiff(diff)
	want := []InventoryItem{
		{Host: "api.cluster.example.com", Port: 6443, Protocol: "https", Exposure: "cluster"},
		{Host: "app.example.com", Port: 443, Protocol: "https", Exposure: "ingress"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected diff items: got %#v want %#v", got, want)
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

func itoa(v int) string {
	return strconv.Itoa(v)
}
