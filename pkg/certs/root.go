package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"time"
)

// CreateRootCA creates a self-signed root CA and returns a SignIntermediateFunc
// for creating intermediate CAs. The root CA key is captured in the closure and
// never exposed — only intermediate CAs can be created from it.
func CreateRootCA(cn string, validity time.Duration) (*x509.Certificate, SignIntermediateFunc, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate root CA key: %w", err)
	}
	rootSerial, err := randomSerial()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate root CA serial: %w", err)
	}
	rootSKID, err := computeSKID(&rootKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute root CA SKID: %w", err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          rootSerial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(validity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		SubjectKeyId:          rootSKID,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create root CA certificate: %w", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse root CA certificate: %w", err)
	}

	signIntermediate := func(cn string, validity time.Duration) (*x509.Certificate, ProfiledSignerFunc, error) {
		intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate intermediate CA key: %w", err)
		}
		intSerial, err := randomSerial()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate intermediate CA serial: %w", err)
		}
		intSKID, err := computeSKID(&intKey.PublicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to compute intermediate CA SKID: %w", err)
		}
		intTemplate := &x509.Certificate{
			SerialNumber:          intSerial,
			Subject:               pkix.Name{CommonName: cn},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(validity),
			IsCA:                  true,
			BasicConstraintsValid: true,
			MaxPathLen:            0,
			MaxPathLenZero:        true,
			SubjectKeyId:          intSKID,
			AuthorityKeyId:        rootCert.SubjectKeyId,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}
		intDER, err := x509.CreateCertificate(rand.Reader, intTemplate, rootCert, &intKey.PublicKey, rootKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create intermediate CA certificate: %w", err)
		}
		intCert, err := x509.ParseCertificate(intDER)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse intermediate CA certificate: %w", err)
		}

		profiledSign := func(pub crypto.PublicKey, cn string, profile LeafProfile) (*x509.Certificate, error) {
			leafSerial, err := randomSerial()
			if err != nil {
				return nil, fmt.Errorf("failed to generate leaf serial: %w", err)
			}
			leafSKID, err := computeSKID(pub)
			if err != nil {
				return nil, fmt.Errorf("failed to compute leaf SKID: %w", err)
			}
			leafTemplate := &x509.Certificate{
				SerialNumber:   leafSerial,
				Subject:        pkix.Name{CommonName: cn},
				NotBefore:      time.Now().Add(-time.Hour),
				NotAfter:       time.Now().Add(validity),
				ExtKeyUsage:    profile.ExtKeyUsage,
				KeyUsage:       x509.KeyUsageDigitalSignature,
				DNSNames:       profile.DNSNames,
				IPAddresses:    profile.IPAddresses,
				SubjectKeyId:   leafSKID,
				AuthorityKeyId: intCert.SubjectKeyId,
			}
			leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, intCert, pub, intKey)
			if err != nil {
				return nil, fmt.Errorf("failed to create certificate: %w", err)
			}
			leafCert, err := x509.ParseCertificate(leafDER)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate: %w", err)
			}
			return leafCert, nil
		}

		return intCert, profiledSign, nil
	}

	return rootCert, signIntermediate, nil
}
