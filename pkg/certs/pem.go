package certs

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// WriteCert writes a certificate to a PEM file, creating parent directories as needed.
func WriteCert(path string, c *x509.Certificate) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

// WriteChainBundle writes a PEM file containing the leaf certificate followed by
// the intermediate CA certificate. This is the standard format for presenting a
// certificate chain in TLS.
func WriteChainBundle(path string, leaf *x509.Certificate, intermediate *x509.Certificate) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}); err != nil {
		return fmt.Errorf("failed to encode leaf certificate: %w", err)
	}
	return pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: intermediate.Raw})
}

// WriteKey writes a DER-encoded EC private key to a PEM file, creating parent directories as needed.
func WriteKey(path string, keyDER []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}
