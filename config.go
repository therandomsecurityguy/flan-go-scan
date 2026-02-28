package config

import (
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Scan struct {
		Timeout   time.Duration `mapstructure:"timeout"`
		Ports     string        `mapstructure:"ports"`
		RateLimit int           `mapstructure:"rate_limit"`
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

func LoadConfig(path string) (*Config, error) {
	viper.SetConfigFile(path)
	viper.AutomaticEnv()
	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}
	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
