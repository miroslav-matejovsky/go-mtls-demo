package mtlsfiles

import (
	"fmt"
	"time"

	"github.com/BurntSushi/toml"
)

const (
	defaultOperatorConfigPath        = "configs/mtlsfiles/operator.toml"
	defaultServerConfigPath          = "configs/mtlsfiles/server.toml"
	defaultClientConfigPath          = "configs/mtlsfiles/client.toml"
	defaultUntrustedClientConfigPath = "configs/mtlsfiles/untrusted_client.toml"
)

// OperatorConfig holds the Certificate Authority configuration owned by the PKI operator.
type OperatorConfig struct {
	CN       string `toml:"cn"`
	CertFile string `toml:"cert_file"`
	Validity string `toml:"validity"`
}

func (c OperatorConfig) ParseValidity() (time.Duration, error) {
	d, err := time.ParseDuration(c.Validity)
	if err != nil {
		return 0, fmt.Errorf("invalid validity %q: %w", c.Validity, err)
	}
	return d, nil
}

// ServerConfig holds configuration owned by the server operator.
type ServerConfig struct {
	Address    string `toml:"address"`
	CN         string `toml:"cn"`
	CertFile   string `toml:"cert_file"`
	KeyFile    string `toml:"key_file"`
	CACertFile string `toml:"ca_cert_file"`
}

// ClientConfig holds configuration owned by the client.
type ClientConfig struct {
	CN         string `toml:"cn"`
	CertFile   string `toml:"cert_file"`
	KeyFile    string `toml:"key_file"`
	CACertFile string `toml:"ca_cert_file"`
}

// UntrustedClientConfig holds configuration for the negative-test client (different CA).
type UntrustedClientConfig struct {
	CACN       string `toml:"ca_cn"`
	CN         string `toml:"cn"`
	CertFile   string `toml:"cert_file"`
	KeyFile    string `toml:"key_file"`
	CACertFile string `toml:"ca_cert_file"`
}

// LoadOperatorConfig reads the operator TOML config from path.
func LoadOperatorConfig(path string) (OperatorConfig, error) {
	var w struct {
		CA OperatorConfig `toml:"ca"`
	}
	if _, err := toml.DecodeFile(path, &w); err != nil {
		return OperatorConfig{}, fmt.Errorf("loading operator config %s: %w", path, err)
	}
	return w.CA, nil
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
