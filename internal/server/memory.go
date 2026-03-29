package server

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
)

// MemoryTLSConfig describes an in-memory one-way TLS server.
type MemoryTLSConfig struct {
	Certificate *x509.Certificate
	PrivateKey  crypto.Signer
	Handler     http.Handler
}

// MemoryMTLSConfig describes an in-memory mutual TLS server.
type MemoryMTLSConfig struct {
	Certificate *x509.Certificate
	PrivateKey  crypto.Signer
	ClientCA    *x509.Certificate
	Handler     http.Handler
}

// NewMemoryTLS builds an unstarted in-memory one-way TLS server.
func NewMemoryTLS(cfg MemoryTLSConfig) (*httptest.Server, error) {
	if cfg.Certificate == nil {
		return nil, fmt.Errorf("creating in-memory TLS server: certificate is required")
	}
	if cfg.PrivateKey == nil {
		return nil, fmt.Errorf("creating in-memory TLS server: private key is required")
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{cfg.Certificate.Raw},
		PrivateKey:  cfg.PrivateKey,
		Leaf:        cfg.Certificate,
	}

	server := httptest.NewUnstartedServer(resolveHandler(cfg.Handler, false))
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{tlsCert},
	}
	return server, nil
}

// NewMemoryMTLS builds an unstarted in-memory mutual TLS server.
func NewMemoryMTLS(cfg MemoryMTLSConfig) (*httptest.Server, error) {
	if cfg.Certificate == nil {
		return nil, fmt.Errorf("creating in-memory mTLS server: certificate is required")
	}
	if cfg.PrivateKey == nil {
		return nil, fmt.Errorf("creating in-memory mTLS server: private key is required")
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{cfg.Certificate.Raw},
		PrivateKey:  cfg.PrivateKey,
		Leaf:        cfg.Certificate,
	}

	clientCAs, err := certPoolFromCertificate(cfg.ClientCA)
	if err != nil {
		return nil, fmt.Errorf("creating in-memory mTLS server: %w", err)
	}

	server := httptest.NewUnstartedServer(resolveHandler(cfg.Handler, true))
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{tlsCert},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	return server, nil
}
