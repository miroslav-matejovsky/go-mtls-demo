package mtlsenterprise

import (
	"fmt"
	"time"

	"github.com/BurntSushi/toml"
)

const (
	defaultOperatorConfigPath        = "configs/mtlsenterprise/operator.toml"
	defaultServerConfigPath          = "configs/mtlsenterprise/server.toml"
	defaultClientConfigPath          = "configs/mtlsenterprise/client.toml"
	defaultUntrustedClientConfigPath = "configs/mtlsenterprise/untrusted_client.toml"
)

// RootCAConfig holds configuration for the offline root CA.
type RootCAConfig struct {
	CN       string `toml:"cn"`
	CertFile string `toml:"cert_file"`
	Validity string `toml:"validity"`
}

func (c RootCAConfig) ParseValidity() (time.Duration, error) {
	d, err := time.ParseDuration(c.Validity)
	if err != nil {
		return 0, fmt.Errorf("invalid root CA validity %q: %w", c.Validity, err)
	}
	return d, nil
}

// IntermediateCAConfig holds configuration for the operational intermediate CA.
type IntermediateCAConfig struct {
	CN       string `toml:"cn"`
	CertFile string `toml:"cert_file"`
	Validity string `toml:"validity"`
}

func (c IntermediateCAConfig) ParseValidity() (time.Duration, error) {
	d, err := time.ParseDuration(c.Validity)
	if err != nil {
		return 0, fmt.Errorf("invalid intermediate CA validity %q: %w", c.Validity, err)
	}
	return d, nil
}

// OperatorConfig holds configuration for the enterprise PKI operator (root + intermediate CA).
type OperatorConfig struct {
	RootCA         RootCAConfig         `toml:"root_ca"`
	IntermediateCA IntermediateCAConfig `toml:"intermediate_ca"`
}

// ServerConfig holds configuration owned by the server operator.
type ServerConfig struct {
	Address      string   `toml:"address"`
	CN           string   `toml:"cn"`
	ChainFile    string   `toml:"chain_file"`
	KeyFile      string   `toml:"key_file"`
	RootCertFile string   `toml:"root_cert_file"`
	DNSNames     []string `toml:"dns_names"`
}

// ClientConfig holds configuration owned by the client.
type ClientConfig struct {
	CN           string `toml:"cn"`
	ChainFile    string `toml:"chain_file"`
	KeyFile      string `toml:"key_file"`
	RootCertFile string `toml:"root_cert_file"`
}

// UntrustedClientConfig holds configuration for the negative-test client (different PKI).
type UntrustedClientConfig struct {
	RootCACN         string `toml:"root_ca_cn"`
	IntermediateCACN string `toml:"intermediate_ca_cn"`
	CN               string `toml:"cn"`
	ChainFile        string `toml:"chain_file"`
	KeyFile          string `toml:"key_file"`
	RootCertFile     string `toml:"root_cert_file"`
}

// LoadOperatorConfig reads the operator TOML config from path.
func LoadOperatorConfig(path string) (OperatorConfig, error) {
	var cfg OperatorConfig
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return OperatorConfig{}, fmt.Errorf("loading operator config %s: %w", path, err)
	}
	return cfg, nil
}

// LoadServerConfig reads the server TOML config from path.
func LoadServerConfig(path string) (ServerConfig, error) {
	var w struct {
		Server ServerConfig `toml:"server"`
	}
	if _, err := toml.DecodeFile(path, &w); err != nil {
		return ServerConfig{}, fmt.Errorf("loading server config %s: %w", path, err)
	}
	return w.Server, nil
}

// LoadClientConfig reads the client TOML config from path.
func LoadClientConfig(path string) (ClientConfig, error) {
	var w struct {
		Client ClientConfig `toml:"client"`
	}
	if _, err := toml.DecodeFile(path, &w); err != nil {
		return ClientConfig{}, fmt.Errorf("loading client config %s: %w", path, err)
	}
	return w.Client, nil
}

// LoadUntrustedClientConfig reads the untrusted client TOML config from path.
func LoadUntrustedClientConfig(path string) (UntrustedClientConfig, error) {
	var w struct {
		UntrustedClient UntrustedClientConfig `toml:"untrusted_client"`
	}
	if _, err := toml.DecodeFile(path, &w); err != nil {
		return UntrustedClientConfig{}, fmt.Errorf("loading untrusted client config %s: %w", path, err)
	}
	return w.UntrustedClient, nil
}
