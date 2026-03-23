package kubernetes

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

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
	transport, err := rest.TransportFor(cfg)
	if err != nil {
		return Target{}, fmt.Errorf("build kubernetes transport: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.Server+"/version", nil)
	if err != nil {
		return Target{}, fmt.Errorf("build kubernetes validation request: %w", err)
	}
	resp, err := (&http.Client{
		Timeout:   c.timeout,
		Transport: transport,
	}).Do(req)
	if err != nil {
		return Target{}, fmt.Errorf("validate kubernetes cluster %s: %w", target.Server, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return Target{}, fmt.Errorf("validate kubernetes cluster %s: unexpected status %d: %s", target.Server, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return target, nil
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

func resolvedKubeconfigPath(explicitPath string) string {
	if explicitPath != "" {
		return explicitPath
	}
	if envPath := strings.TrimSpace(os.Getenv(clientcmd.RecommendedConfigPathEnvVar)); envPath != "" {
		return envPath
	}
	return filepath.Join(clientcmd.RecommendedHomeDir, clientcmd.RecommendedFileName)
}
