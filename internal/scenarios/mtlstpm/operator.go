//go:build windows

package mtlstpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/kpi"
)

// Operator represents the Certificate Authority actor.
// It creates the CA, signs leaf certificates, and distributes the CA certificate
// to the parties that need it — mirroring a real-world PKI operator.
type Operator struct {
	cfg    OperatorConfig
	caCert *x509.Certificate
	signFn kpi.SignerFunc
}

// NewOperator creates a new CA from cfg, writes the CA certificate to cfg.CertFile,
// and returns an Operator ready to sign and distribute certificates.
func NewOperator(cfg OperatorConfig) (*Operator, error) {
	validity, err := cfg.ParseValidity()
	if err != nil {
		return nil, err
	}
	caCert, signFn, err := kpi.CreateCA(cfg.CN, validity)
	if err != nil {
		return nil, fmt.Errorf("creating CA: %w", err)
	}
	if err := kpi.WriteCert(cfg.CertFile, caCert); err != nil {
		return nil, fmt.Errorf("writing CA certificate: %w", err)
	}
	return &Operator{cfg: cfg, caCert: caCert, signFn: signFn}, nil
}

// SignCert generates a new ECDSA key pair and issues a leaf certificate for cn.
func (o *Operator) SignCert(cn string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	return kpi.CreateLeafCertAndKey(o.signFn, cn)
}

// SignCertForKey issues a leaf certificate for an externally-provided public key.
// Used when the private key is generated inside a TPM or key store and cannot be exported.
func (o *Operator) SignCertForKey(pub crypto.PublicKey, cn string) (*x509.Certificate, error) {
	return o.signFn(pub, cn)
}

// DistributeCA writes the CA certificate to destPath, simulating the operator
// handing the public CA cert to a party (server or client team).
func (o *Operator) DistributeCA(destPath string) error {
	return kpi.WriteCert(destPath, o.caCert)
}

// CACert returns the operator's CA certificate.
func (o *Operator) CACert() *x509.Certificate {
	return o.caCert
}
