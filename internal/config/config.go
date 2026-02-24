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
	} `mapstructure:"scan"`
	DNS struct {
		TTL time.Duration `mapstructure:"ttl"`
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
	cfg.DNS.TTL = 10 * time.Minute
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
	return cfg, nil
}
