package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"time"
)

// newEnterpriseCA creates a two-tier PKI: a self-signed root CA that signs an
// intermediate CA. It returns the root certificate, intermediate certificate,
// and the intermediate private key. Used internally by NewEnterprise.
func newEnterpriseCA(rootCN string, rootValidity time.Duration, intCN string, intValidity time.Duration) (*x509.Certificate, *x509.Certificate, *ecdsa.PrivateKey, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate root CA key: %w", err)
	}
	rootSerial, err := randomSerial()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate root CA serial: %w", err)
	}
	rootSKID, err := computeSKID(&rootKey.PublicKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to compute root CA SKID: %w", err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          rootSerial,
		Subject:               pkix.Name{CommonName: rootCN},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(rootValidity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		SubjectKeyId:          rootSKID,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create root CA certificate: %w", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse root CA certificate: %w", err)
	}

	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate intermediate CA key: %w", err)
	}
	intSerial, err := randomSerial()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate intermediate CA serial: %w", err)
	}
	intSKID, err := computeSKID(&intKey.PublicKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to compute intermediate CA SKID: %w", err)
	}
	intTemplate := &x509.Certificate{
		SerialNumber:          intSerial,
		Subject:               pkix.Name{CommonName: intCN},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(intValidity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          intSKID,
		AuthorityKeyId:        rootCert.SubjectKeyId,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	intDER, err := x509.CreateCertificate(rand.Reader, intTemplate, rootCert, &intKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create intermediate CA certificate: %w", err)
	}
	intCert, err := x509.ParseCertificate(intDER)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse intermediate CA certificate: %w", err)
	}

	return rootCert, intCert, intKey, nil
}
