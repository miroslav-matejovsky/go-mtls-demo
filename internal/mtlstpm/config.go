//go:build windows

package mtlstpm

import (
	"fmt"
	"time"

	"github.com/BurntSushi/toml"
)

const defaultConfigPath = "configs/mtlstpm.toml"

// Config holds all externalized configuration for the mtlstpm demo.
type Config struct {
	CA        CAConfig        `toml:"ca"`
	Server    ServerConfig    `toml:"server"`
	Client    ClientConfig    `toml:"client"`
	Untrusted UntrustedConfig `toml:"untrusted"`
}

type CAConfig struct {
	CN       string `toml:"cn"`
	CertFile string `toml:"cert_file"`
	Validity string `toml:"validity"`
}

type ServerConfig struct {
	Address    string `toml:"address"`
	CN         string `toml:"cn"`
	CertFile   string `toml:"cert_file"`
	KeyFile    string `toml:"key_file"`
	CACertFile string `toml:"ca_cert_file"`
}

type ClientConfig struct {
	CN        string `toml:"cn"`
	Container string `toml:"container"`
}

type UntrustedConfig struct {
	CACN string `toml:"ca_cn"`
	CN   string `toml:"cn"`
}

func (c CAConfig) ParseValidity() (time.Duration, error) {
	d, err := time.ParseDuration(c.Validity)
	if err != nil {
		return 0, fmt.Errorf("invalid validity %q: %w", c.Validity, err)
	}
	return d, nil
}

// LoadConfig reads a TOML config file from path.
func LoadConfig(path string) (Config, error) {
	var cfg Config
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return Config{}, fmt.Errorf("loading config %s: %w", path, err)
	}
	return cfg, nil
}
