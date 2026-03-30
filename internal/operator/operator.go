package operator

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/ca"
)

// Operator represents a certificate authority operator that can issue server
// and client leaf certificates and distribute them to the file system. It covers
// both single-tier PKI (NewSimple) and two-tier PKI with a root and an
// intermediate CA (NewEnterprise). Use TrustAnchor to obtain the certificate
// that relying parties should trust.
type Operator struct {
	trustAnchor  *x509.Certificate
	intermediate *x509.Certificate // nil for single-tier PKI
	sign         ca.ProfiledSignerFunc
}

// NewSimple creates a single-tier self-signed CA, writes its certificate to
// disk, and returns an Operator ready to issue leaf certificates.
func NewSimple(cfg CAConfig) (*Operator, error) {
	if err := validateCAConfig("simple CA", cfg); err != nil {
		return nil, err
	}

	caCert, sign, err := ca.CreateProfiledCA(cfg.CN, cfg.Validity)
	if err != nil {
		return nil, fmt.Errorf("creating simple CA: %w", err)
	}
	if err := WriteCert(cfg.CertFile, caCert); err != nil {
		return nil, fmt.Errorf("writing simple CA certificate: %w", err)
	}

	return &Operator{trustAnchor: caCert, sign: sign}, nil
}

// NewEnterprise creates a two-tier PKI with an offline-style root CA and an
// operational intermediate CA, writes both certificates to disk, and returns
// an Operator ready to issue profiled leaf certificates.
func NewEnterprise(cfg EnterpriseConfig) (*Operator, error) {
	if err := validateCAConfig("root CA", cfg.RootCA); err != nil {
		return nil, err
	}
	if err := validateCAConfig("intermediate CA", cfg.IntermediateCA); err != nil {
		return nil, err
	}

	rootCert, signIntermediate, err := ca.CreateRootCA(cfg.RootCA.CN, cfg.RootCA.Validity)
	if err != nil {
		return nil, fmt.Errorf("creating root CA: %w", err)
	}
	if err := WriteCert(cfg.RootCA.CertFile, rootCert); err != nil {
		return nil, fmt.Errorf("writing root CA certificate: %w", err)
	}

	intCert, sign, err := signIntermediate(cfg.IntermediateCA.CN, cfg.IntermediateCA.Validity)
	if err != nil {
		return nil, fmt.Errorf("creating intermediate CA: %w", err)
	}
	if err := WriteCert(cfg.IntermediateCA.CertFile, intCert); err != nil {
		return nil, fmt.Errorf("writing intermediate CA certificate: %w", err)
	}

	return &Operator{trustAnchor: rootCert, intermediate: intCert, sign: sign}, nil
}

// TrustAnchor returns the certificate that relying parties should add to their
// trust pool. For single-tier PKI this is the CA certificate; for two-tier PKI
// this is the root CA certificate.
func (o *Operator) TrustAnchor() *x509.Certificate {
	return o.trustAnchor
}

// Intermediate returns the intermediate CA certificate for two-tier PKI, or
// nil for single-tier PKI. It is needed when building chain bundles.
func (o *Operator) Intermediate() *x509.Certificate {
	return o.intermediate
}

// DistributeTrustAnchor writes the trust anchor certificate to destPath so
// relying parties can load it into their trust pool.
func (o *Operator) DistributeTrustAnchor(destPath string) error {
	return WriteCert(destPath, o.trustAnchor)
}

// SignServerCert issues a leaf certificate with ServerAuth EKU, the supplied
// DNS SANs, and loopback IP SANs.
func (o *Operator) SignServerCert(cn string, dnsNames []string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	profile := ca.LeafProfile{
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    dnsNames,
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	return ca.GenerateLeafCertificateAndKey(o.sign, cn, profile)
}

// SignClientCert issues a leaf certificate with ClientAuth EKU and loopback
// IP SANs.
func (o *Operator) SignClientCert(cn string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	profile := ca.LeafProfile{
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	return ca.GenerateLeafCertificateAndKey(o.sign, cn, profile)
}

// SignClientCertForKey issues a ClientAuth certificate for an externally
// provided public key, such as a TPM-backed key that never leaves its provider.
func (o *Operator) SignClientCertForKey(pub crypto.PublicKey, cn string) (*x509.Certificate, error) {
	profile := ca.LeafProfile{
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	return o.sign(pub, cn, profile)
}

// WriteChain writes the leaf certificate to path. When the operator has an
// intermediate CA, it appends the intermediate certificate to form a chain
// bundle (leaf + intermediate), which is the standard format for TLS
// presentation.
func (o *Operator) WriteChain(path string, leaf *x509.Certificate) error {
	if o.intermediate != nil {
		return WriteChainBundle(path, leaf, o.intermediate)
	}
	return WriteCert(path, leaf)
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
