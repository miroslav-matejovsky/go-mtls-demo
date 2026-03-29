package authority

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"net"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/pki"
)

// Authority represents a certificate authority that can issue server and client
// leaf certificates. It covers both single-tier PKI (NewSimple) and two-tier
// PKI with a root and an intermediate CA (NewEnterprise). Use TrustAnchor to
// obtain the certificate that relying parties should trust.
type Authority struct {
	trustAnchor  *x509.Certificate
	intermediate *x509.Certificate // nil for single-tier PKI
	sign         pki.ProfiledSignerFunc
}

// NewSimple creates a single-tier self-signed CA, writes its certificate to
// disk, and returns an Authority ready to issue leaf certificates.
func NewSimple(cfg CAConfig) (*Authority, error) {
	if err := validateCAConfig("simple CA", cfg); err != nil {
		return nil, err
	}

	caCert, sign, err := pki.CreateProfiledCA(cfg.CN, cfg.Validity)
	if err != nil {
		return nil, fmt.Errorf("creating simple CA: %w", err)
	}
	if err := pki.WriteCert(cfg.CertFile, caCert); err != nil {
		return nil, fmt.Errorf("writing simple CA certificate: %w", err)
	}

	return &Authority{trustAnchor: caCert, sign: sign}, nil
}

// NewEnterprise creates a two-tier PKI with an offline-style root CA and an
// operational intermediate CA, writes both certificates to disk, and returns
// an Authority ready to issue profiled leaf certificates.
func NewEnterprise(cfg EnterpriseConfig) (*Authority, error) {
	if err := validateCAConfig("root CA", cfg.RootCA); err != nil {
		return nil, err
	}
	if err := validateCAConfig("intermediate CA", cfg.IntermediateCA); err != nil {
		return nil, err
	}

	rootCert, signIntermediate, err := pki.CreateRootCA(cfg.RootCA.CN, cfg.RootCA.Validity)
	if err != nil {
		return nil, fmt.Errorf("creating root CA: %w", err)
	}
	if err := pki.WriteCert(cfg.RootCA.CertFile, rootCert); err != nil {
		return nil, fmt.Errorf("writing root CA certificate: %w", err)
	}

	intCert, sign, err := signIntermediate(cfg.IntermediateCA.CN, cfg.IntermediateCA.Validity)
	if err != nil {
		return nil, fmt.Errorf("creating intermediate CA: %w", err)
	}
	if err := pki.WriteCert(cfg.IntermediateCA.CertFile, intCert); err != nil {
		return nil, fmt.Errorf("writing intermediate CA certificate: %w", err)
	}

	return &Authority{trustAnchor: rootCert, intermediate: intCert, sign: sign}, nil
}

// TrustAnchor returns the certificate that relying parties should add to their
// trust pool. For single-tier PKI this is the CA certificate; for two-tier PKI
// this is the root CA certificate.
func (a *Authority) TrustAnchor() *x509.Certificate {
	return a.trustAnchor
}

// Intermediate returns the intermediate CA certificate for two-tier PKI, or
// nil for single-tier PKI. It is needed when building chain bundles.
func (a *Authority) Intermediate() *x509.Certificate {
	return a.intermediate
}

// DistributeTrustAnchor writes the trust anchor certificate to destPath so
// relying parties can load it into their trust pool.
func (a *Authority) DistributeTrustAnchor(destPath string) error {
	return pki.WriteCert(destPath, a.trustAnchor)
}

// SignServerCert issues a leaf certificate with ServerAuth EKU, the supplied
// DNS SANs, and loopback IP SANs.
func (a *Authority) SignServerCert(cn string, dnsNames []string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	profile := pki.LeafProfile{
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    dnsNames,
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	return pki.GenerateLeafCertificateAndKey(a.sign, cn, profile)
}

// SignClientCert issues a leaf certificate with ClientAuth EKU and loopback
// IP SANs.
func (a *Authority) SignClientCert(cn string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	profile := pki.LeafProfile{
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	return pki.GenerateLeafCertificateAndKey(a.sign, cn, profile)
}

// SignClientCertForKey issues a ClientAuth certificate for an externally
// provided public key, such as a TPM-backed key that never leaves its provider.
func (a *Authority) SignClientCertForKey(pub crypto.PublicKey, cn string) (*x509.Certificate, error) {
	profile := pki.LeafProfile{
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	return a.sign(pub, cn, profile)
}

// WriteChain writes the leaf certificate to path. When the authority has an
// intermediate CA, it appends the intermediate certificate to form a chain
// bundle (leaf + intermediate), which is the standard format for TLS
// presentation.
func (a *Authority) WriteChain(path string, leaf *x509.Certificate) error {
	if a.intermediate != nil {
		return pki.WriteChainBundle(path, leaf, a.intermediate)
	}
	return pki.WriteCert(path, leaf)
}
