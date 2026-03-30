package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
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
// issue server and client leaf certificates via CSRs. For enterprise PKI it
// exposes the trust anchor and intermediate separately so operators can
// distribute them.
type Authority struct {
	trustAnchor  *x509.Certificate
	intermediate *x509.Certificate
	// issuingCert is the certificate used to sign leaf certificates.
	// For simple PKI it equals trustAnchor; for enterprise PKI it is the intermediate.
	issuingCert *x509.Certificate
	caKey       *ecdsa.PrivateKey
	validity    time.Duration
}

// NewSimple creates a single-tier self-signed certificate authority service.
func NewSimple(cfg CAConfig) (*Authority, error) {
	if err := validateCAConfig("simple CA", cfg); err != nil {
		return nil, err
	}

	cert, key, err := newSimpleCA(cfg.CN, cfg.Validity)
	if err != nil {
		return nil, fmt.Errorf("creating simple CA: %w", err)
	}

	return &Authority{
		trustAnchor: cert,
		issuingCert: cert,
		caKey:       key,
		validity:    cfg.Validity,
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

	rootCert, intCert, intKey, err := newEnterpriseCA(cfg.RootCA.CN, cfg.RootCA.Validity, cfg.IntermediateCA.CN, cfg.IntermediateCA.Validity)
	if err != nil {
		return nil, err
	}

	return &Authority{
		trustAnchor:  rootCert,
		intermediate: intCert,
		issuingCert:  intCert,
		caKey:        intKey,
		validity:     cfg.IntermediateCA.Validity,
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

// SignClientCertForKey issues a ClientAuth certificate for an externally
// provided public key, such as a TPM-backed key that never leaves its provider.
func (a *Authority) SignClientCertForKey(pub crypto.PublicKey, cn string) (*x509.Certificate, error) {
	return a.signPublicKey(pub, cn, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback})
}

func (a *Authority) signRequest(req *x509.CertificateRequest, eku x509.ExtKeyUsage, role string) (*x509.Certificate, error) {
	if req == nil {
		return nil, fmt.Errorf("signing %s CSR: request is required", role)
	}
	if err := req.CheckSignature(); err != nil {
		return nil, fmt.Errorf("signing %s CSR: invalid request signature: %w", role, err)
	}
	return a.signPublicKey(req.PublicKey, req.Subject.CommonName, []x509.ExtKeyUsage{eku}, req.DNSNames, req.IPAddresses)
}

func (a *Authority) signPublicKey(pub crypto.PublicKey, cn string, ekus []x509.ExtKeyUsage, dnsNames []string, ipAddresses []net.IP) (*x509.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("failed to generate leaf serial: %w", err)
	}
	skid, err := computeSKID(pub)
	if err != nil {
		return nil, fmt.Errorf("failed to compute leaf SKID: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber:   serial,
		Subject:        pkix.Name{CommonName: cn},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(a.validity),
		ExtKeyUsage:    ekus,
		KeyUsage:       x509.KeyUsageDigitalSignature,
		DNSNames:       dnsNames,
		IPAddresses:    ipAddresses,
		SubjectKeyId:   skid,
		AuthorityKeyId: a.issuingCert.SubjectKeyId,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, a.issuingCert, pub, a.caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}
	return x509.ParseCertificate(certDER)
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
