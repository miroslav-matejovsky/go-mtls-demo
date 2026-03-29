package client

import (
	"crypto/tls"
	"fmt"
	"net/http"
)

// FileTLSConfig describes a file-backed one-way TLS client.
type FileTLSConfig struct {
	CACertFile string
}

// FileMTLSConfig describes a file-backed mutual TLS client.
type FileMTLSConfig struct {
	CACertFile      string
	CertificateFile string
	PrivateKeyFile  string
}

// NewTLSFromFiles builds a one-way TLS HTTP client from PEM files.
func NewTLSFromFiles(cfg FileTLSConfig) (*http.Client, error) {
	certPool, err := certPoolFromFile(cfg.CACertFile)
	if err != nil {
		return nil, fmt.Errorf("creating file-backed TLS client: %w", err)
	}

	return newHTTPClient(&tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    certPool,
	}), nil
}

// NewMTLSFromFiles builds a mutual TLS HTTP client from PEM files.
func NewMTLSFromFiles(cfg FileMTLSConfig) (*http.Client, error) {
	certPool, err := certPoolFromFile(cfg.CACertFile)
	if err != nil {
		return nil, fmt.Errorf("creating file-backed mTLS client: %w", err)
	}

	clientCert, err := tls.LoadX509KeyPair(cfg.CertificateFile, cfg.PrivateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("creating file-backed mTLS client: loading certificate: %w", err)
	}

	return newHTTPClient(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      certPool,
		Certificates: []tls.Certificate{clientCert},
	}), nil
}
