package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"net"
)

// CreateLeafCert generates a new ECDSA P-256 key pair and issues a leaf certificate
// signed by the provided SignerFunc with the given common name.
func CreateLeafCert(signLeaf SignerFunc, cn string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
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

// LeafProfile controls the certificate extensions for leaf certificates
// issued by a profiled signer, enabling role-specific EKU and configurable SANs.
type LeafProfile struct {
	ExtKeyUsage []x509.ExtKeyUsage
	DNSNames    []string
	IPAddresses []net.IP
}

// CreateLeafCertWithProfile generates a new ECDSA P-256 key pair and issues a
// leaf certificate via the given ProfiledSignerFunc, applying the LeafProfile.
func CreateLeafCertWithProfile(sign ProfiledSignerFunc, cn string, profile LeafProfile) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate leaf key: %w", err)
	}
	leafCert, err := sign(&leafKey.PublicKey, cn, profile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create leaf certificate: %w", err)
	}
	return leafCert, leafKey, nil
}
