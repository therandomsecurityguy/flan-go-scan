package kubernetes

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

func encodeCertAuthority(cert *x509.Certificate) string {
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return base64.StdEncoding.EncodeToString(pemBlock)
}

func itoa(v int) string {
	return strconv.Itoa(v)
}
