package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"time"
)

// SignerFunc signs a public key with the given CN and returns a leaf certificate.
type SignerFunc func(pub crypto.PublicKey, cn string) (*x509.Certificate, error)

// CreateCA creates a self-signed CA certificate with the given common name and validity duration.
// The same validity is applied to any leaf certificates signed by the returned SignerFunc.
// It returns the CA certificate and a SignerFunc closure for issuing leaf certificates.
func CreateCA(cn string, validity time.Duration) (*x509.Certificate, SignerFunc, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate CA key: %w", err)
	}
	caSerial, err := randomSerial()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate CA serial: %w", err)
	}
	caSKID, err := computeSKID(&caKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute CA SKID: %w", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(validity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		SubjectKeyId:          caSKID,
		// ExtKeyUsageClientAuth - allows the certificate to be used for client authentication in TLS
		// ExtKeyUsageServerAuth - allows the certificate to be used for server authentication in TLS
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		// KeyUsageCertSign - allows the certificate to be used for signing other certificates (i.e. as a CA)
		// KeyUsageCRLSign - allows the certificate to be used for signing Certificate Revocation Lists (CRLs)
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}
	signLeaf := func(pub crypto.PublicKey, cn string) (*x509.Certificate, error) {
		leafSerial, err := randomSerial()
		if err != nil {
			return nil, fmt.Errorf("failed to generate leaf serial: %w", err)
		}
		leafSKID, err := computeSKID(pub)
		if err != nil {
			return nil, fmt.Errorf("failed to compute leaf SKID: %w", err)
		}
		certTemplate := &x509.Certificate{
			SerialNumber:   leafSerial,
			Subject:        pkix.Name{CommonName: cn},
			NotBefore:      time.Now().Add(-time.Hour),
			NotAfter:       time.Now().Add(validity),
			ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:       x509.KeyUsageDigitalSignature,
			IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
			SubjectKeyId:   leafSKID,
			AuthorityKeyId: caCert.SubjectKeyId,
		}
		certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, caCert, pub, caKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create certificate: %w", err)
		}
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
		return cert, nil
	}
	return caCert, signLeaf, nil
}

// CreateLeafCertAndKey generates a new ECDSA P-256 key pair and issues a leaf certificate
// signed by the provided SignerFunc with the given common name.
func CreateLeafCertAndKey(signLeaf SignerFunc, cn string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate leaf key: %w", err)
	}
	leafCert, err := signLeaf(&leafKey.PublicKey, cn)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create leaf certificate: %w", err)
	}
	return leafCert, leafKey, nil
}
