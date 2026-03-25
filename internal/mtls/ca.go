package mtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

func CreateCa() (*x509.Certificate, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA key: %w", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "go mTLS Demo CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		// KeyUsageCertSign - allows the certificate to be used for signing other certificates (i.e. as a CA)
		// KeyUsageCRLSign - allows the certificate to be used for signing Certificate Revocation Lists (CRLs)
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}
	return caCert, nil
}

func PrintCertificateInfo(cert *x509.Certificate) {
	fmt.Printf("Certificate Subject: %s\n", cert.Subject)
	fmt.Printf("Certificate Issuer: %s\n", cert.Issuer)
	fmt.Printf("Certificate Serial Number: %s\n", cert.SerialNumber)
	fmt.Printf("Certificate Not Before: %s\n", cert.NotBefore)
	fmt.Printf("Certificate Not After: %s\n", cert.NotAfter)
	fmt.Printf("Is CA: %t\n", cert.IsCA)
	fmt.Printf("Key Usage: %v\n", cert.KeyUsage)
	fmt.Printf("Extended Key Usage: %v\n", cert.ExtKeyUsage)
}
