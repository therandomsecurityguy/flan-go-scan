package kubernetes

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type Client struct {
	timeout time.Duration
}

type ValidateOptions struct {
	Kubeconfig string
	Context    string
}

type Target struct {
	Kubeconfig string
	Context    string
	Cluster    string
	Server     string
}

type InventoryItem struct {
	Cluster   string
	Context   string
	Namespace string
	Kind      string
	Name      string
	Host      string
	Port      int
	Protocol  string
	Exposure  string
}

type InventorySnapshot struct {
	GeneratedAt   string          `json:"generated_at"`
	Source        string          `json:"source"`
	Cluster       string          `json:"cluster"`
	Context       string          `json:"context"`
	Server        string          `json:"server"`
	ResourceCount int             `json:"resource_count"`
	Resources     []InventoryItem `json:"resources"`
}

type InventoryDiff struct {
	GeneratedAt         string                `json:"generated_at"`
	Source              string                `json:"source"`
	PreviousGeneratedAt string                `json:"previous_generated_at,omitempty"`
	CurrentGeneratedAt  string                `json:"current_generated_at,omitempty"`
	AddedCount          int                   `json:"added_count"`
	RemovedCount        int                   `json:"removed_count"`
	ChangedCount        int                   `json:"changed_count"`
	Added               []InventoryItem       `json:"added,omitempty"`
	Removed             []InventoryItem       `json:"removed,omitempty"`
	Changed             []InventoryItemChange `json:"changed,omitempty"`
}

type InventoryItemChange struct {
	Before InventoryItem `json:"before"`
	After  InventoryItem `json:"after"`
}

func NewClient(timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Client{timeout: timeout}
}

func (c *Client) Validate(ctx context.Context, opts ValidateOptions) (Target, error) {
	target, cfg, err := c.resolve(opts)
	if err != nil {
		return Target{}, err
	}
	if err := validateTarget(ctx, target, cfg, c.timeout); err != nil {
		return Target{}, err
	}
	return target, nil
}

func (c *Client) Inventory(ctx context.Context, opts ValidateOptions) (Target, []InventoryItem, error) {
	target, cfg, err := c.resolve(opts)
	if err != nil {
		return Target{}, nil, err
	}
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return Target{}, nil, fmt.Errorf("build kubernetes clientset: %w", err)
	}
	if _, err := clientset.Discovery().ServerVersion(); err != nil {
		return Target{}, nil, fmt.Errorf("validate kubernetes cluster %s: %w", target.Server, err)
	}
	items, err := inventoryFromClient(ctx, target, clientset)
	if err != nil {
		return Target{}, nil, err
	}
	return target, items, nil
}

func BuildInventorySnapshot(now time.Time, target Target, items []InventoryItem) InventorySnapshot {
	resources := append([]InventoryItem(nil), items...)
	sortInventoryItems(resources)
	return InventorySnapshot{
		GeneratedAt:   now.UTC().Format(time.RFC3339),
		Source:        "kubernetes",
		Cluster:       target.Cluster,
		Context:       target.Context,
		Server:        target.Server,
		ResourceCount: len(resources),
		Resources:     resources,
	}
}

func DiffInventory(now time.Time, previous, current InventorySnapshot) InventoryDiff {
	prevByKey := make(map[string]InventoryItem, len(previous.Resources))
	currByKey := make(map[string]InventoryItem, len(current.Resources))
	for _, item := range previous.Resources {
		prevByKey[itemChangeKey(item)] = item
	}
	for _, item := range current.Resources {
		currByKey[itemChangeKey(item)] = item
	}

	diff := InventoryDiff{
		GeneratedAt:         now.UTC().Format(time.RFC3339),
		Source:              "kubernetes",
		PreviousGeneratedAt: previous.GeneratedAt,
		CurrentGeneratedAt:  current.GeneratedAt,
	}

	for key, currentItem := range currByKey {
		previousItem, ok := prevByKey[key]
		if !ok {
			diff.Added = append(diff.Added, currentItem)
			continue
		}
		if itemIdentity(previousItem) != itemIdentity(currentItem) {
			diff.Changed = append(diff.Changed, InventoryItemChange{Before: previousItem, After: currentItem})
		}
	}

	for key, previousItem := range prevByKey {
		if _, ok := currByKey[key]; !ok {
			diff.Removed = append(diff.Removed, previousItem)
		}
	}

	sortInventoryItems(diff.Added)
	sortInventoryItems(diff.Removed)
	slices.SortFunc(diff.Changed, func(a, b InventoryItemChange) int {
		return strings.Compare(itemKey(a.After), itemKey(b.After))
	})

	diff.AddedCount = len(diff.Added)
	diff.RemovedCount = len(diff.Removed)
	diff.ChangedCount = len(diff.Changed)
	return diff
}

func ItemsFromDiff(diff InventoryDiff) []InventoryItem {
	items := append([]InventoryItem(nil), diff.Added...)
	for _, change := range diff.Changed {
		items = append(items, change.After)
	}
	return dedupeInventoryItems(items)
}

func validateTarget(ctx context.Context, target Target, cfg *rest.Config, timeout time.Duration) error {
	transport, err := rest.TransportFor(cfg)
	if err != nil {
		return fmt.Errorf("build kubernetes transport: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.Server+"/version", nil)
	if err != nil {
		return fmt.Errorf("build kubernetes validation request: %w", err)
	}
	resp, err := (&http.Client{
		Timeout:   timeout,
		Transport: transport,
	}).Do(req)
	if err != nil {
		return fmt.Errorf("validate kubernetes cluster %s: %w", target.Server, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("validate kubernetes cluster %s: unexpected status %d: %s", target.Server, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func inventoryFromClient(ctx context.Context, target Target, clientset kubernetes.Interface) ([]InventoryItem, error) {
	items := make([]InventoryItem, 0, 64)
	if item, ok := apiServerItem(target); ok {
		items = append(items, item)
	}

	nodeExternalHosts, err := listNodeExternalHosts(ctx, clientset)
	if err != nil {
		return nil, fmt.Errorf("list kubernetes nodes: %w", err)
	}

	ingresses, err := clientset.NetworkingV1().Ingresses("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list kubernetes ingresses: %w", err)
	}
	for i := range ingresses.Items {
		items = append(items, ingressItems(target, &ingresses.Items[i])...)
	}

	services, err := clientset.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list kubernetes services: %w", err)
	}
	for i := range services.Items {
		items = append(items, serviceItems(target, &services.Items[i], nodeExternalHosts)...)
	}

	return dedupeInventoryItems(items), nil
}

func (c *Client) resolve(opts ValidateOptions) (Target, *rest.Config, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	explicitPath := strings.TrimSpace(opts.Kubeconfig)
	if explicitPath != "" {
		rules.ExplicitPath = explicitPath
	}
	contextName := strings.TrimSpace(opts.Context)
	overrides := &clientcmd.ConfigOverrides{}
	if contextName != "" {
		overrides.CurrentContext = contextName
	}
	loader := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)
	rawConfig, err := loader.RawConfig()
	if err != nil {
		return Target{}, nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	if contextName == "" {
		contextName = strings.TrimSpace(rawConfig.CurrentContext)
	}
	if contextName == "" {
		return Target{}, nil, fmt.Errorf("select kubeconfig context: no current context configured")
	}
	contextConfig, ok := rawConfig.Contexts[contextName]
	if !ok || contextConfig == nil {
		return Target{}, nil, fmt.Errorf("select kubeconfig context: context %q not found", contextName)
	}
	clusterName := strings.TrimSpace(contextConfig.Cluster)
	clusterConfig, ok := rawConfig.Clusters[clusterName]
	if !ok || clusterConfig == nil {
		return Target{}, nil, fmt.Errorf("select kubeconfig cluster: cluster %q not found", clusterName)
	}
	cfg, err := loader.ClientConfig()
	if err != nil {
		return Target{}, nil, fmt.Errorf("build kubernetes client config: %w", err)
	}
	cfg.Timeout = c.timeout
	target := Target{
		Kubeconfig: resolvedKubeconfigPath(explicitPath),
		Context:    contextName,
		Cluster:    clusterName,
		Server:     strings.TrimRight(strings.TrimSpace(clusterConfig.Server), "/"),
	}
	return target, cfg, nil
}

func apiServerItem(target Target) (InventoryItem, bool) {
	serverURL, err := url.Parse(target.Server)
	if err != nil {
		return InventoryItem{}, false
	}
	host := normalizeHost(serverURL.Hostname())
	if host == "" {
		return InventoryItem{}, false
	}
	port := serverURL.Port()
	if port == "" {
		if serverURL.Scheme == "https" {
			port = "443"
		} else if serverURL.Scheme == "http" {
			port = "80"
		}
	}
	portNum := 0
	if port != "" {
		parsed, err := net.LookupPort("tcp", port)
		if err == nil {
			portNum = parsed
		}
	}
	if portNum == 0 {
		return InventoryItem{}, false
	}
	return InventoryItem{
		Cluster:  target.Cluster,
		Context:  target.Context,
		Kind:     "APIServer",
		Name:     "kubernetes",
		Host:     host,
		Port:     portNum,
		Protocol: schemeOrDefault(serverURL.Scheme, "https"),
		Exposure: "cluster",
	}, true
}

func ingressItems(target Target, ingress *networkingv1.Ingress) []InventoryItem {
	tlsHosts := make(map[string]struct{})
	loadBalancerHosts := make(map[string]struct{})
	hasTLS := len(ingress.Spec.TLS) > 0
	for _, tls := range ingress.Spec.TLS {
		for _, host := range tls.Hosts {
			host = normalizeHost(host)
			if host != "" {
				tlsHosts[host] = struct{}{}
			}
		}
	}

	hostSet := make(map[string]struct{})
	for _, rule := range ingress.Spec.Rules {
		host := normalizeHost(rule.Host)
		if host != "" {
			hostSet[host] = struct{}{}
		}
	}
	for _, lb := range ingress.Status.LoadBalancer.Ingress {
		if host := normalizeHost(lb.Hostname); host != "" {
			hostSet[host] = struct{}{}
			loadBalancerHosts[host] = struct{}{}
		}
		if host := normalizeHost(lb.IP); host != "" {
			hostSet[host] = struct{}{}
			loadBalancerHosts[host] = struct{}{}
		}
	}

	if len(hostSet) == 0 {
		return nil
	}

	items := make([]InventoryItem, 0, len(hostSet)*2)
	hosts := make([]string, 0, len(hostSet))
	for host := range hostSet {
		hosts = append(hosts, host)
	}
	slices.Sort(hosts)
	for _, host := range hosts {
		items = append(items, InventoryItem{
			Cluster:   target.Cluster,
			Context:   target.Context,
			Namespace: ingress.Namespace,
			Kind:      "Ingress",
			Name:      ingress.Name,
			Host:      host,
			Port:      80,
			Protocol:  "http",
			Exposure:  "ingress",
		})
		if hasTLS {
			if len(tlsHosts) == 0 {
				items = append(items, InventoryItem{
					Cluster:   target.Cluster,
					Context:   target.Context,
					Namespace: ingress.Namespace,
					Kind:      "Ingress",
					Name:      ingress.Name,
					Host:      host,
					Port:      443,
					Protocol:  "https",
					Exposure:  "ingress",
				})
				continue
			}
			if _, ok := tlsHosts[host]; ok {
				items = append(items, InventoryItem{
					Cluster:   target.Cluster,
					Context:   target.Context,
					Namespace: ingress.Namespace,
					Kind:      "Ingress",
					Name:      ingress.Name,
					Host:      host,
					Port:      443,
					Protocol:  "https",
					Exposure:  "ingress",
				})
				continue
			}
			if _, ok := loadBalancerHosts[host]; ok {
				items = append(items, InventoryItem{
					Cluster:   target.Cluster,
					Context:   target.Context,
					Namespace: ingress.Namespace,
					Kind:      "Ingress",
					Name:      ingress.Name,
					Host:      host,
					Port:      443,
					Protocol:  "https",
					Exposure:  "ingress",
				})
			}
		}
	}
	return items
}

func serviceItems(target Target, service *corev1.Service, nodeExternalHosts []string) []InventoryItem {
	switch service.Spec.Type {
	case corev1.ServiceTypeLoadBalancer:
		return loadBalancerServiceItems(target, service)
	case corev1.ServiceTypeNodePort:
		return nodePortServiceItems(target, service, nodeExternalHosts)
	default:
		return nil
	}
}

func loadBalancerServiceItems(target Target, service *corev1.Service) []InventoryItem {
	hosts := collectServiceExternalHosts(service)
	if len(hosts) == 0 {
		return nil
	}
	items := make([]InventoryItem, 0, len(hosts)*len(service.Spec.Ports))
	for _, host := range hosts {
		for _, port := range service.Spec.Ports {
			if port.Port <= 0 {
				continue
			}
			items = append(items, InventoryItem{
				Cluster:   target.Cluster,
				Context:   target.Context,
				Namespace: service.Namespace,
				Kind:      "Service",
				Name:      service.Name,
				Host:      host,
				Port:      int(port.Port),
				Protocol:  strings.ToLower(string(port.Protocol)),
				Exposure:  "loadbalancer",
			})
		}
	}
	return items
}

func nodePortServiceItems(target Target, service *corev1.Service, nodeExternalHosts []string) []InventoryItem {
	hosts := collectServiceExternalHosts(service)
	if len(hosts) == 0 {
		hosts = append(hosts, nodeExternalHosts...)
	}
	if len(hosts) == 0 {
		return nil
	}
	items := make([]InventoryItem, 0, len(hosts)*len(service.Spec.Ports))
	for _, host := range hosts {
		for _, port := range service.Spec.Ports {
			if port.NodePort <= 0 {
				continue
			}
			items = append(items, InventoryItem{
				Cluster:   target.Cluster,
				Context:   target.Context,
				Namespace: service.Namespace,
				Kind:      "Service",
				Name:      service.Name,
				Host:      host,
				Port:      int(port.NodePort),
				Protocol:  strings.ToLower(string(port.Protocol)),
				Exposure:  "nodeport",
			})
		}
	}
	return items
}

func collectServiceExternalHosts(service *corev1.Service) []string {
	hostSet := make(map[string]struct{})
	for _, host := range service.Spec.ExternalIPs {
		host = normalizeHost(host)
		if host != "" {
			hostSet[host] = struct{}{}
		}
	}
	for _, lb := range service.Status.LoadBalancer.Ingress {
		if host := normalizeHost(lb.Hostname); host != "" {
			hostSet[host] = struct{}{}
		}
		if host := normalizeHost(lb.IP); host != "" {
			hostSet[host] = struct{}{}
		}
	}
	hosts := make([]string, 0, len(hostSet))
	for host := range hostSet {
		hosts = append(hosts, host)
	}
	slices.Sort(hosts)
	return hosts
}

func listNodeExternalHosts(ctx context.Context, clientset kubernetes.Interface) ([]string, error) {
	nodes, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	hostSet := make(map[string]struct{})
	for _, node := range nodes.Items {
		for _, address := range node.Status.Addresses {
			if address.Type != corev1.NodeExternalIP && address.Type != corev1.NodeExternalDNS {
				continue
			}
			host := normalizeHost(address.Address)
			if host != "" {
				hostSet[host] = struct{}{}
			}
		}
	}
	hosts := make([]string, 0, len(hostSet))
	for host := range hostSet {
		hosts = append(hosts, host)
	}
	slices.Sort(hosts)
	return hosts, nil
}

func dedupeInventoryItems(items []InventoryItem) []InventoryItem {
	seen := make(map[string]struct{}, len(items))
	out := make([]InventoryItem, 0, len(items))
	for _, item := range items {
		if item.Host == "" || item.Port <= 0 {
			continue
		}
		key := itemIdentity(item)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	sortInventoryItems(out)
	return out
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

func schemeOrDefault(value, fallback string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return fallback
	}
	return value
}

func resolvedKubeconfigPath(explicitPath string) string {
	if explicitPath != "" {
		return explicitPath
	}
	if envPath := strings.TrimSpace(os.Getenv(clientcmd.RecommendedConfigPathEnvVar)); envPath != "" {
		return envPath
	}
	return filepath.Join(clientcmd.RecommendedHomeDir, clientcmd.RecommendedFileName)
}

func sortInventoryItems(items []InventoryItem) {
	slices.SortFunc(items, func(a, b InventoryItem) int {
		return strings.Compare(itemKey(a), itemKey(b))
	})
}

func itemChangeKey(item InventoryItem) string {
	return strings.Join([]string{
		item.Cluster,
		item.Context,
		item.Namespace,
		item.Kind,
		item.Name,
		item.Host,
		fmt.Sprintf("%d", item.Port),
	}, "|")
}

func itemIdentity(item InventoryItem) string {
	return itemChangeKey(item) + "|" + item.Protocol + "|" + item.Exposure
}

func itemKey(item InventoryItem) string {
	return itemIdentity(item)
}
