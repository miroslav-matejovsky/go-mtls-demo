package server

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

// FileTLSConfig describes a file-backed one-way TLS server.
type FileTLSConfig struct {
	CertificateFile string
	PrivateKeyFile  string
	Handler         http.Handler
}

// FileMTLSConfig describes a file-backed mutual TLS server.
type FileMTLSConfig struct {
	CertificateFile string
	PrivateKeyFile  string
	ClientCAFile    string
	Handler         http.Handler
}

// NewFileTLS builds a file-backed one-way TLS server.
func NewFileTLS(cfg FileTLSConfig) (*http.Server, error) {
	if cfg.CertificateFile == "" {
		return nil, fmt.Errorf("creating file-backed TLS server: certificate file is required")
	}
	if cfg.PrivateKeyFile == "" {
		return nil, fmt.Errorf("creating file-backed TLS server: private key file is required")
	}

	serverCert, err := tls.LoadX509KeyPair(cfg.CertificateFile, cfg.PrivateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("creating file-backed TLS server: loading certificate: %w", err)
	}

	return &http.Server{
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{serverCert},
		},
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
		Handler:      resolveHandler(cfg.Handler, false),
	}, nil
}

// NewFileMTLS builds a file-backed mutual TLS server.
func NewFileMTLS(cfg FileMTLSConfig) (*http.Server, error) {
	if cfg.CertificateFile == "" {
		return nil, fmt.Errorf("creating file-backed mTLS server: certificate file is required")
	}
	if cfg.PrivateKeyFile == "" {
		return nil, fmt.Errorf("creating file-backed mTLS server: private key file is required")
	}

	serverCert, err := tls.LoadX509KeyPair(cfg.CertificateFile, cfg.PrivateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("creating file-backed mTLS server: loading certificate: %w", err)
	}

	clientCAs, err := certPoolFromFile(cfg.ClientCAFile)
	if err != nil {
		return nil, fmt.Errorf("creating file-backed mTLS server: %w", err)
	}

	return &http.Server{
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{serverCert},
			ClientCAs:    clientCAs,
			ClientAuth:   tls.RequireAndVerifyClientCert,
		},
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
		Handler:      resolveHandler(cfg.Handler, true),
	}, nil
}
