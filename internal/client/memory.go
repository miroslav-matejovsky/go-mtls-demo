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

// MemoryMTLSConfig describes an in-memory mutual TLS client.
type MemoryMTLSConfig struct {
	CACert         *x509.Certificate
	CertificatePEM []byte
	PrivateKeyPEM  []byte
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

// NewMTLSFromMemory builds a mutual TLS client from in-memory certificate
// material.
func NewMTLSFromMemory(cfg MemoryMTLSConfig) (*http.Client, error) {
	certPool, err := certPoolFromCertificate(cfg.CACert)
	if err != nil {
		return nil, fmt.Errorf("creating in-memory mTLS client: %w", err)
	}

	clientCert, err := tls.X509KeyPair(cfg.CertificatePEM, cfg.PrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("creating in-memory mTLS client: loading certificate: %w", err)
	}

	return newHTTPClient(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      certPool,
		Certificates: []tls.Certificate{clientCert},
	}), nil
}
