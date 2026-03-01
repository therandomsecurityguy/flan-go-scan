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
}

func defaults() *Config {
	cfg := &Config{}
	cfg.Scan.Timeout = 3 * time.Second
	cfg.Scan.Ports = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,2049,3306,3389,5432,5900,6379,8080,8443,9200,9300,27017"
	cfg.Scan.RateLimit = 200
	cfg.Scan.Workers = 100
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
