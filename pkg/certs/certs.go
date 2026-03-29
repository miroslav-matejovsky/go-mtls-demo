package certs

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// SignerFunc signs a public key with the given CN and returns a leaf certificate.
type SignerFunc func(pub crypto.PublicKey, cn string) (*x509.Certificate, error)

// ProfiledSignerFunc signs a leaf certificate with the caller-supplied profile
// controlling EKU and SANs. Used by the enterprise PKI path.
type ProfiledSignerFunc func(pub crypto.PublicKey, cn string, profile LeafProfile) (*x509.Certificate, error)

// SignIntermediateFunc creates a new intermediate CA signed by the root.
// It returns the intermediate certificate and a ProfiledSignerFunc for issuing
// profile-aware leaf certificates.
type SignIntermediateFunc func(cn string, validity time.Duration) (*x509.Certificate, ProfiledSignerFunc, error)

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	for {
		serial, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return nil, err
		}
		if serial.Sign() > 0 {
			return serial, nil
		}
	}
}

func computeSKID(pub crypto.PublicKey) ([]byte, error) {
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	hash := sha256.Sum256(b)
	return hash[:], nil
}

// PrintCertificateInfo prints certificate details to stdout.
func PrintCertificateInfo(c *x509.Certificate) {
	format := "2006-01-02 15:04:05 UTC"
	fmt.Printf("  Subject       : %s\n", c.Subject.CommonName)
	fmt.Printf("  Issuer        : %s\n", c.Issuer.CommonName)
	fmt.Printf("  Serial        : %s\n", c.SerialNumber)
	fmt.Printf("  Valid         : %s → %s\n",
		c.NotBefore.Format(format),
		c.NotAfter.Format(format))
	fmt.Printf("  Is CA         : %t\n", c.IsCA)
	fmt.Printf("  Key Usage     : %s\n", keyUsageNames(c.KeyUsage))
	fmt.Printf("  Ext Key Usage : %v\n", c.ExtKeyUsage)
	if len(c.SubjectKeyId) > 0 {
		fmt.Printf("  Subject Key ID: %X\n", c.SubjectKeyId)
	}
	if len(c.AuthorityKeyId) > 0 {
		fmt.Printf("  Auth Key ID   : %X\n", c.AuthorityKeyId)
	}
	fmt.Println()
}

// TLSVersionName returns a human-readable name for the given TLS version.
func TLSVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04X)", version)
	}
}

func keyUsageNames(ku x509.KeyUsage) string {
	var names []string
	if ku&x509.KeyUsageCertSign != 0 {
		names = append(names, "certSign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		names = append(names, "cRLSign")
	}
	if ku&x509.KeyUsageDigitalSignature != 0 {
		names = append(names, "digitalSignature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		names = append(names, "contentCommitment")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		names = append(names, "keyEncipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		names = append(names, "dataEncipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		names = append(names, "keyAgreement")
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		names = append(names, "encipherOnly")
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
		names = append(names, "decipherOnly")
	}
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}
