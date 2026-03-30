package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

// CAConfig describes a certificate authority service with its common name and
// certificate validity period. It contains only CA concerns and no file paths.
type CAConfig struct {
	CN       string
	Validity time.Duration
}

// EnterpriseConfig describes a two-tier CA service consisting of a root CA and
// an operational intermediate CA.
type EnterpriseConfig struct {
	RootCA         CAConfig
	IntermediateCA CAConfig
}

// Authority represents an in-memory certificate authority service that can
// issue server and client leaf certificates. For enterprise PKI it exposes the
// trust anchor and intermediate separately so operators can distribute them.
type Authority struct {
	trustAnchor  *x509.Certificate
	intermediate *x509.Certificate
	sign         ProfiledSignerFunc
}

// NewSimple creates a single-tier self-signed certificate authority service.
func NewSimple(cfg CAConfig) (*Authority, error) {
	if err := validateCAConfig("simple CA", cfg); err != nil {
		return nil, err
	}

	cert, sign, err := CreateProfiledCA(cfg.CN, cfg.Validity)
	if err != nil {
		return nil, fmt.Errorf("creating simple CA: %w", err)
	}

	return &Authority{
		trustAnchor: cert,
		sign:        sign,
	}, nil
}

// NewEnterprise creates a two-tier certificate authority service with a root
// CA and an operational intermediate CA.
func NewEnterprise(cfg EnterpriseConfig) (*Authority, error) {
	if err := validateCAConfig("root CA", cfg.RootCA); err != nil {
		return nil, err
	}
	if err := validateCAConfig("intermediate CA", cfg.IntermediateCA); err != nil {
		return nil, err
	}

	rootCert, signIntermediate, err := CreateRootCA(cfg.RootCA.CN, cfg.RootCA.Validity)
	if err != nil {
		return nil, fmt.Errorf("creating root CA: %w", err)
	}

	intCert, sign, err := signIntermediate(cfg.IntermediateCA.CN, cfg.IntermediateCA.Validity)
	if err != nil {
		return nil, fmt.Errorf("creating intermediate CA: %w", err)
	}

	return &Authority{
		trustAnchor:  rootCert,
		intermediate: intCert,
		sign:         sign,
	}, nil
}

// TrustAnchor returns the certificate that relying parties should trust. For
// single-tier PKI this is the CA certificate; for two-tier PKI this is the root
// CA certificate.
func (a *Authority) TrustAnchor() *x509.Certificate {
	return a.trustAnchor
}

// Intermediate returns the intermediate CA certificate for two-tier PKI, or
// nil for single-tier PKI.
func (a *Authority) Intermediate() *x509.Certificate {
	return a.intermediate
}

// SignServerCert issues a leaf certificate with ServerAuth EKU, the supplied
// DNS SANs, and loopback IP SANs. It is a compatibility wrapper over the CSR
// flow; new callers should prefer CreateServerCSR + SignServerCSR.
func (a *Authority) SignServerCert(cn string, dnsNames []string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	csr, key, err := CreateServerCSR(cn, dnsNames)
	if err != nil {
		return nil, nil, err
	}
	cert, err := a.SignServerCSR(csr)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// SignClientCert issues a leaf certificate with ClientAuth EKU and loopback IP
// SANs. It is a compatibility wrapper over the CSR flow; new callers should
// prefer CreateClientCSR + SignClientCSR.
func (a *Authority) SignClientCert(cn string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	csr, key, err := CreateClientCSR(cn)
	if err != nil {
		return nil, nil, err
	}
	cert, err := a.SignClientCSR(csr)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// SignClientCertForKey issues a ClientAuth certificate for an externally
// provided public key, such as a TPM-backed key that never leaves its provider.
func (a *Authority) SignClientCertForKey(pub crypto.PublicKey, cn string) (*x509.Certificate, error) {
	profile := LeafProfile{
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	return a.sign(pub, cn, profile)
}

// SignServerCSR issues a server certificate from a CSR. SANs are copied from the
// request and ServerAuth EKU is applied by the CA.
func (a *Authority) SignServerCSR(req *x509.CertificateRequest) (*x509.Certificate, error) {
	return a.signRequest(req, x509.ExtKeyUsageServerAuth, "server")
}

// SignClientCSR issues a client certificate from a CSR. SANs are copied from the
// request and ClientAuth EKU is applied by the CA.
func (a *Authority) SignClientCSR(req *x509.CertificateRequest) (*x509.Certificate, error) {
	return a.signRequest(req, x509.ExtKeyUsageClientAuth, "client")
}

func (a *Authority) signRequest(req *x509.CertificateRequest, eku x509.ExtKeyUsage, role string) (*x509.Certificate, error) {
	if req == nil {
		return nil, fmt.Errorf("signing %s CSR: request is required", role)
	}
	if err := req.CheckSignature(); err != nil {
		return nil, fmt.Errorf("signing %s CSR: invalid request signature: %w", role, err)
	}
	profile := LeafProfile{
		ExtKeyUsage: []x509.ExtKeyUsage{eku},
		DNSNames:    req.DNSNames,
		IPAddresses: req.IPAddresses,
	}
	return a.sign(req.PublicKey, req.Subject.CommonName, profile)
}

func validateCAConfig(role string, cfg CAConfig) error {
	if cfg.CN == "" {
		return fmt.Errorf("creating %s: common name is required", role)
	}
	if cfg.Validity <= 0 {
		return fmt.Errorf("creating %s: validity must be greater than zero", role)
	}
	return nil
}
