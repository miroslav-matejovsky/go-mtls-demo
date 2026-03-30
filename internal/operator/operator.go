package operator

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/ca"
)

// NewSimple creates a single-tier certificate authority service and persists
// the operator-managed CA certificate to disk.
func NewSimple(cfg CAConfig) (*ca.Authority, error) {
	if err := validateCAConfig("simple CA", cfg); err != nil {
		return nil, err
	}

	authority, err := ca.NewSimple(ca.CAConfig{
		CN:       cfg.CN,
		Validity: cfg.Validity,
	})
	if err != nil {
		return nil, fmt.Errorf("creating simple CA: %w", err)
	}
	if err := WriteCert(cfg.CertFile, authority.TrustAnchor()); err != nil {
		return nil, fmt.Errorf("writing simple CA certificate: %w", err)
	}

	return authority, nil
}

// NewEnterprise creates a two-tier certificate authority service and persists
// the operator-managed root and intermediate certificates to disk.
func NewEnterprise(cfg EnterpriseConfig) (*ca.Authority, error) {
	if err := validateCAConfig("root CA", cfg.RootCA); err != nil {
		return nil, err
	}
	if err := validateCAConfig("intermediate CA", cfg.IntermediateCA); err != nil {
		return nil, err
	}

	authority, err := ca.NewEnterprise(ca.EnterpriseConfig{
		RootCA: ca.CAConfig{
			CN:       cfg.RootCA.CN,
			Validity: cfg.RootCA.Validity,
		},
		IntermediateCA: ca.CAConfig{
			CN:       cfg.IntermediateCA.CN,
			Validity: cfg.IntermediateCA.Validity,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("creating enterprise CA: %w", err)
	}
	if err := WriteCert(cfg.RootCA.CertFile, authority.TrustAnchor()); err != nil {
		return nil, fmt.Errorf("writing root CA certificate: %w", err)
	}

	intermediate := authority.Intermediate()
	if intermediate == nil {
		return nil, fmt.Errorf("creating enterprise CA: intermediate certificate is required")
	}
	if err := WriteCert(cfg.IntermediateCA.CertFile, intermediate); err != nil {
		return nil, fmt.Errorf("writing intermediate CA certificate: %w", err)
	}

	return authority, nil
}

// DistributeTrustAnchor writes the trust anchor certificate to destPath so
// relying parties can load it into their trust pool.
func DistributeTrustAnchor(destPath string, trustAnchor *x509.Certificate) error {
	return WriteCert(destPath, trustAnchor)
}

// WriteChain writes the leaf certificate to path. When intermediate is present,
// it appends the intermediate certificate to form a standard chain bundle.
func WriteChain(path string, leaf *x509.Certificate, intermediate *x509.Certificate) error {
	if intermediate != nil {
		return WriteChainBundle(path, leaf, intermediate)
	}
	return WriteCert(path, leaf)
}

// WriteIdentity writes a leaf certificate and its private key to disk.
func WriteIdentity(certPath, keyPath string, cert *x509.Certificate, key *ecdsa.PrivateKey) error {
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshaling EC private key: %w", err)
	}
	if err := WriteCert(certPath, cert); err != nil {
		return err
	}
	return WriteKey(keyPath, keyDER)
}

// WriteChainIdentity writes a leaf certificate chain and its private key to
// disk. When intermediate is nil, the chain file contains only the leaf.
func WriteChainIdentity(chainPath, keyPath string, leaf *x509.Certificate, key *ecdsa.PrivateKey, intermediate *x509.Certificate) error {
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshaling EC private key: %w", err)
	}
	if err := WriteChain(chainPath, leaf, intermediate); err != nil {
		return err
	}
	return WriteKey(keyPath, keyDER)
}

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
