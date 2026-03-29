package authority

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"net"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/pki"
)

// Enterprise represents a two-tier PKI with an offline-style root CA and an
// operational intermediate CA that issues leaf certificates.
type Enterprise struct {
	rootCert *x509.Certificate
	intCert  *x509.Certificate
	signLeaf pki.ProfiledSignerFunc
}

// NewEnterprise creates the configured root and intermediate CAs, writes both
// certificates to disk, and returns an authority ready to issue profiled leaf
// certificates.
func NewEnterprise(cfg EnterpriseConfig) (*Enterprise, error) {
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

	intCert, signLeaf, err := signIntermediate(cfg.IntermediateCA.CN, cfg.IntermediateCA.Validity)
	if err != nil {
		return nil, fmt.Errorf("creating intermediate CA: %w", err)
	}
	if err := pki.WriteCert(cfg.IntermediateCA.CertFile, intCert); err != nil {
		return nil, fmt.Errorf("writing intermediate CA certificate: %w", err)
	}

	return &Enterprise{
		rootCert: rootCert,
		intCert:  intCert,
		signLeaf: signLeaf,
	}, nil
}

// SignServerCert issues a leaf certificate with ServerAuth EKU, DNS SANs, and
// loopback IP SANs.
func (a *Enterprise) SignServerCert(cn string, dnsNames []string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	profile := pki.LeafProfile{
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    dnsNames,
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	return pki.GenerateLeafCertificateAndKey(a.signLeaf, cn, profile)
}

// SignClientCert issues a leaf certificate with ClientAuth EKU and loopback IP
// SANs.
func (a *Enterprise) SignClientCert(cn string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	profile := pki.LeafProfile{
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	return pki.GenerateLeafCertificateAndKey(a.signLeaf, cn, profile)
}

// SignClientCertForKey issues a ClientAuth certificate for an externally
// provided public key, such as a TPM-backed key.
func (a *Enterprise) SignClientCertForKey(pub crypto.PublicKey, cn string) (*x509.Certificate, error) {
	profile := pki.LeafProfile{
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	return a.signLeaf(pub, cn, profile)
}

// DistributeRootCA writes the root CA certificate to destPath.
func (a *Enterprise) DistributeRootCA(destPath string) error {
	return pki.WriteCert(destPath, a.rootCert)
}

// WriteServerChain writes the server leaf certificate followed by the
// intermediate CA certificate.
func (a *Enterprise) WriteServerChain(chainPath string, serverCert *x509.Certificate) error {
	return pki.WriteChainBundle(chainPath, serverCert, a.intCert)
}

// WriteClientChain writes the client leaf certificate followed by the
// intermediate CA certificate.
func (a *Enterprise) WriteClientChain(chainPath string, clientCert *x509.Certificate) error {
	return pki.WriteChainBundle(chainPath, clientCert, a.intCert)
}

// RootCert returns the root CA certificate.
func (a *Enterprise) RootCert() *x509.Certificate {
	return a.rootCert
}

// IntermediateCert returns the intermediate CA certificate.
func (a *Enterprise) IntermediateCert() *x509.Certificate {
	return a.intCert
}
