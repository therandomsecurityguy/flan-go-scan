package config

import (
	"os"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Scan struct {
		Timeout       time.Duration `mapstructure:"timeout"`
		Ports         string        `mapstructure:"ports"`
		RateLimit     int           `mapstructure:"rate_limit"`
		Workers       int           `mapstructure:"workers"`
		MaxHostConns  int           `mapstructure:"max_host_conns"`
		Discovery     bool          `mapstructure:"discovery"`
		StatsInterval int           `mapstructure:"stats_interval"`
		UDP           bool          `mapstructure:"udp"`
		UDPPorts      string        `mapstructure:"udp_ports"`
		CrawlDepth    int           `mapstructure:"crawl_depth"`
		MaxTargets    int           `mapstructure:"max_targets"`
		MaxPortsHost  int           `mapstructure:"max_ports_per_target"`
		MaxDuration   time.Duration `mapstructure:"max_duration"`
	} `mapstructure:"scan"`
	Subdomain struct {
		PortProfile    string `mapstructure:"port_profile"`
		Sources        string `mapstructure:"sources"`
		ExcludeSources string `mapstructure:"exclude_sources"`
		AllSources     bool   `mapstructure:"all_sources"`
		RecursiveOnly  bool   `mapstructure:"recursive_only"`
		MaxTime        int    `mapstructure:"max_time"`
		RateLimit      int    `mapstructure:"rate_limit"`
		Threads        int    `mapstructure:"threads"`
		ProviderConfig string `mapstructure:"provider_config"`
	} `mapstructure:"subdomain"`
	DNS struct {
		TTL               time.Duration `mapstructure:"ttl"`
		Resolver          string        `mapstructure:"resolver"`
		FallbackResolvers []string      `mapstructure:"fallback_resolvers"`
		LookupTimeout     time.Duration `mapstructure:"lookup_timeout"`
	} `mapstructure:"dns"`
	Output struct {
		Format    string `mapstructure:"format"`
		Directory string `mapstructure:"directory"`
	} `mapstructure:"output"`
	Checkpoint struct {
		File string `mapstructure:"file"`
	} `mapstructure:"checkpoint"`
	Cloudflare struct {
		Enabled      bool          `mapstructure:"enabled"`
		Zones        []string      `mapstructure:"zones"`
		Include      []string      `mapstructure:"include"`
		Exclude      []string      `mapstructure:"exclude"`
		TokenEnv     string        `mapstructure:"token_env"`
		Timeout      time.Duration `mapstructure:"timeout"`
		InventoryOut string        `mapstructure:"inventory_out"`
		DiffAgainst  string        `mapstructure:"diff_against"`
		DeltaOnly    bool          `mapstructure:"delta_only"`
	} `mapstructure:"cloudflare"`
	AWS struct {
		Enabled      bool          `mapstructure:"enabled"`
		Profile      string        `mapstructure:"profile"`
		Regions      []string      `mapstructure:"regions"`
		Include      []string      `mapstructure:"include"`
		Exclude      []string      `mapstructure:"exclude"`
		Timeout      time.Duration `mapstructure:"timeout"`
		InventoryOut string        `mapstructure:"inventory_out"`
		DiffAgainst  string        `mapstructure:"diff_against"`
		DeltaOnly    bool          `mapstructure:"delta_only"`
	} `mapstructure:"aws"`
	Kubernetes struct {
		Enabled    bool          `mapstructure:"enabled"`
		Kubeconfig string        `mapstructure:"kubeconfig"`
		Context    string        `mapstructure:"context"`
		Timeout    time.Duration `mapstructure:"timeout"`
	} `mapstructure:"kubernetes"`
}

func defaults() *Config {
	cfg := &Config{}
	cfg.Scan.Timeout = 3 * time.Second
	cfg.Scan.Ports = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,2049,3306,3389,5432,5900,6379,8080,8443,9200,9300,27017"
	cfg.Scan.RateLimit = 200
	cfg.Scan.Workers = 100
	cfg.Scan.MaxHostConns = 0
	cfg.Scan.Discovery = true
	cfg.Scan.StatsInterval = 5
	cfg.Scan.UDP = false
	cfg.Scan.UDPPorts = "53,123,161,500"
	cfg.Scan.CrawlDepth = 2
	cfg.Scan.MaxTargets = 5000
	cfg.Scan.MaxPortsHost = 5000
	cfg.Scan.MaxDuration = 30 * time.Minute
	cfg.Subdomain.PortProfile = "web"
	cfg.Subdomain.Sources = "crtsh,anubis,digitorus,thc,commoncrawl,waybackarchive,rapiddns,hudsonrock,sitedossier,threatcrowd"
	cfg.Subdomain.ExcludeSources = ""
	cfg.Subdomain.AllSources = false
	cfg.Subdomain.RecursiveOnly = false
	cfg.Subdomain.MaxTime = 5
	cfg.Subdomain.RateLimit = 0
	cfg.Subdomain.Threads = 10
	cfg.Subdomain.ProviderConfig = ""
	cfg.DNS.TTL = 10 * time.Minute
	cfg.DNS.Resolver = ""
	cfg.DNS.FallbackResolvers = []string{"1.1.1.1:53", "8.8.8.8:53"}
	cfg.DNS.LookupTimeout = 3 * time.Second
	cfg.Output.Format = "jsonl"
	cfg.Output.Directory = "-"
	cfg.Checkpoint.File = "scan-state.json"
	cfg.Cloudflare.Enabled = false
	cfg.Cloudflare.TokenEnv = "CLOUDFLARE_API_TOKEN"
	cfg.Cloudflare.Timeout = 15 * time.Second
	cfg.Cloudflare.InventoryOut = ""
	cfg.Cloudflare.DiffAgainst = ""
	cfg.Cloudflare.DeltaOnly = false
	cfg.AWS.Enabled = false
	cfg.AWS.Profile = ""
	cfg.AWS.Timeout = 15 * time.Second
	cfg.AWS.InventoryOut = ""
	cfg.AWS.DiffAgainst = ""
	cfg.AWS.DeltaOnly = false
	cfg.Kubernetes.Enabled = false
	cfg.Kubernetes.Kubeconfig = ""
	cfg.Kubernetes.Context = ""
	cfg.Kubernetes.Timeout = 10 * time.Second
	return cfg
}

func LoadConfig(path string) (*Config, error) {
	cfg := defaults()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return cfg, nil
	}
	viper.SetConfigFile(path)
	viper.AutomaticEnv()
	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}
	if err := viper.Unmarshal(cfg); err != nil {
		return nil, err
	}
	if viper.IsSet("dns.fallback_resolvers") {
		var resolvers []string
		if err := viper.UnmarshalKey("dns.fallback_resolvers", &resolvers); err == nil {
			cfg.DNS.FallbackResolvers = resolvers
		}
	}
	return cfg, nil
}
