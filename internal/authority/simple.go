package authority

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/pki"
)

// Simple represents a single-tier certificate authority that can issue leaf
// certificates directly.
type Simple struct {
	caCert *x509.Certificate
	signFn pki.SignerFunc
}

// NewSimple creates a new self-signed CA from cfg, writes its public
// certificate to disk, and returns a signer-ready authority.
func NewSimple(cfg CAConfig) (*Simple, error) {
	if err := validateCAConfig("simple CA", cfg); err != nil {
		return nil, err
	}

	caCert, signFn, err := pki.CreateCA(cfg.CN, cfg.Validity)
	if err != nil {
		return nil, fmt.Errorf("creating simple CA: %w", err)
	}
	if err := pki.WriteCert(cfg.CertFile, caCert); err != nil {
		return nil, fmt.Errorf("writing simple CA certificate: %w", err)
	}

	return &Simple{caCert: caCert, signFn: signFn}, nil
}

// SignCert generates a new ECDSA P-256 key pair and issues a leaf certificate
// for cn.
func (a *Simple) SignCert(cn string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	return pki.CreateLeafCertAndKey(a.signFn, cn)
}

// SignCertForKey issues a leaf certificate for an externally provided public
// key, such as a TPM-backed key that never leaves its provider.
func (a *Simple) SignCertForKey(pub crypto.PublicKey, cn string) (*x509.Certificate, error) {
	return a.signFn(pub, cn)
}

// DistributeCA writes the authority certificate to destPath.
func (a *Simple) DistributeCA(destPath string) error {
	return pki.WriteCert(destPath, a.caCert)
}

// CACert returns the authority certificate.
func (a *Simple) CACert() *x509.Certificate {
	return a.caCert
}
