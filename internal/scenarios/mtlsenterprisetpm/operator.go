//go:build windows

package mtlsenterprisetpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"net"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/pki"
)

// Operator represents the enterprise PKI operator managing a two-tier CA hierarchy.
// It creates the root CA, signs an intermediate CA, and issues profiled leaf certificates.
type Operator struct {
	rootCert *x509.Certificate
	intCert  *x509.Certificate
	signLeaf pki.ProfiledSignerFunc
}

// NewOperator creates a root CA and an intermediate CA from cfg, writes both CA
// certificates to their configured paths, and returns an Operator ready to issue
// profiled leaf certificates.
func NewOperator(cfg OperatorConfig) (*Operator, error) {
	rootValidity, err := cfg.RootCA.ParseValidity()
	if err != nil {
		return nil, err
	}
	rootCert, signIntermediate, err := pki.CreateRootCA(cfg.RootCA.CN, rootValidity)
	if err != nil {
		return nil, fmt.Errorf("creating root CA: %w", err)
	}
	if err := pki.WriteCert(cfg.RootCA.CertFile, rootCert); err != nil {
		return nil, fmt.Errorf("writing root CA certificate: %w", err)
	}

	intValidity, err := cfg.IntermediateCA.ParseValidity()
	if err != nil {
		return nil, err
	}
	intCert, signLeaf, err := signIntermediate(cfg.IntermediateCA.CN, intValidity)
	if err != nil {
		return nil, fmt.Errorf("creating intermediate CA: %w", err)
	}
	if err := pki.WriteCert(cfg.IntermediateCA.CertFile, intCert); err != nil {
		return nil, fmt.Errorf("writing intermediate CA certificate: %w", err)
	}

	return &Operator{rootCert: rootCert, intCert: intCert, signLeaf: signLeaf}, nil
}

// SignServerCert issues a leaf certificate with ServerAuth EKU, DNS SANs, and loopback IPs.
func (o *Operator) SignServerCert(cn string, dnsNames []string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	profile := pki.LeafProfile{
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    dnsNames,
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	return pki.GenerateLeafCertificateAndKey(o.signLeaf, cn, profile)
}

// SignClientCertForKey issues a leaf certificate with ClientAuth EKU for an
// externally-provided public key (e.g. from a TPM). The private key never
// leaves the provider — only the public key is needed to create the certificate.
func (o *Operator) SignClientCertForKey(pub crypto.PublicKey, cn string) (*x509.Certificate, error) {
	profile := pki.LeafProfile{
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	return o.signLeaf(pub, cn, profile)
}

// DistributeRootCA writes the root CA certificate to destPath.
func (o *Operator) DistributeRootCA(destPath string) error {
	return pki.WriteCert(destPath, o.rootCert)
}

// WriteServerChain writes a PEM bundle containing the server leaf cert followed
// by the intermediate CA cert.
func (o *Operator) WriteServerChain(chainPath string, serverCert *x509.Certificate) error {
	return pki.WriteChainBundle(chainPath, serverCert, o.intCert)
}

// RootCert returns the operator's root CA certificate.
func (o *Operator) RootCert() *x509.Certificate { return o.rootCert }

// IntermediateCert returns the operator's intermediate CA certificate.
func (o *Operator) IntermediateCert() *x509.Certificate { return o.intCert }
