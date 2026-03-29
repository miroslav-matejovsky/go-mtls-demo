package client

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
)

// MemoryTLSConfig describes an in-memory one-way TLS client.
type MemoryTLSConfig struct {
	CACert *x509.Certificate
}

// NewTLSFromMemory builds a one-way TLS client from an in-memory CA
// certificate.
func NewTLSFromMemory(cfg MemoryTLSConfig) (*http.Client, error) {
	certPool, err := certPoolFromCertificate(cfg.CACert)
	if err != nil {
		return nil, fmt.Errorf("creating in-memory TLS client: %w", err)
	}

	return newHTTPClient(&tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    certPool,
	}), nil
}
