package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
)

// MemoryTLSConfig describes an in-memory one-way TLS server.
type MemoryTLSConfig struct {
	CertificatePEM []byte
	PrivateKeyPEM  []byte
	Handler        http.Handler
}

// MemoryMTLSConfig describes an in-memory mutual TLS server.
type MemoryMTLSConfig struct {
	CertificatePEM []byte
	PrivateKeyPEM  []byte
	ClientCA       *x509.Certificate
	Handler        http.Handler
}

// NewMemoryTLS builds an unstarted in-memory one-way TLS server.
func NewMemoryTLS(cfg MemoryTLSConfig) (*httptest.Server, error) {
	serverCert, err := tls.X509KeyPair(cfg.CertificatePEM, cfg.PrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("creating in-memory TLS server: %w", err)
	}

	server := httptest.NewUnstartedServer(resolveHandler(cfg.Handler, false))
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverCert},
	}
	return server, nil
}

// NewMemoryMTLS builds an unstarted in-memory mutual TLS server.
func NewMemoryMTLS(cfg MemoryMTLSConfig) (*httptest.Server, error) {
	serverCert, err := tls.X509KeyPair(cfg.CertificatePEM, cfg.PrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("creating in-memory mTLS server: %w", err)
	}

	clientCAs, err := certPoolFromCertificate(cfg.ClientCA)
	if err != nil {
		return nil, fmt.Errorf("creating in-memory mTLS server: %w", err)
	}

	server := httptest.NewUnstartedServer(resolveHandler(cfg.Handler, true))
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	return server, nil
}
