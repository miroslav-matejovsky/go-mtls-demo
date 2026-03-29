// Package pki provides low-level certificate generation and file helpers shared
// across all demo scenarios. It handles CA creation, leaf certificate issuance
// via closure-based signers, PEM encoding, and certificate inspection utilities.
package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
)

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

// PrintCertificateInfo prints a formatted summary of a certificate to stdout,
// including subject, issuer, serial, validity, key usage, and key identifiers.
func PrintCertificateInfo(c *x509.Certificate) {
	fmt.Printf("  Subject       : %s\n", c.Subject.CommonName)
	fmt.Printf("  Issuer        : %s\n", c.Issuer.CommonName)
	fmt.Printf("  Serial        : %s\n", c.SerialNumber)
	fmt.Printf("  Valid         : %s → %s\n",
		c.NotBefore.Format("2006-01-02 15:04 UTC"),
		c.NotAfter.Format("2006-01-02 15:04 UTC"))
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

// WriteCert writes a certificate to a PEM file, creating parent directories as needed.
func WriteCert(path string, c *x509.Certificate) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

// WriteKey writes a DER-encoded EC private key to a PEM file, creating parent directories as needed.
func WriteKey(path string, keyDER []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// TLSVersionName returns a human-readable name for a TLS version constant
// (e.g. tls.VersionTLS13 → "TLS 1.3").
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

// CertPoolFromCertificate builds an x509.CertPool containing the given certificate.
// Callers use this to populate the ClientCAs / RootCAs field of a tls.Config when
// the trust anchor is already held in memory as an *x509.Certificate.
func CertPoolFromCertificate(caCert *x509.Certificate) (*x509.CertPool, error) {
	if caCert == nil {
		return nil, fmt.Errorf("certificate authority certificate is required")
	}
	certPool := x509.NewCertPool()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	if !certPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to build certificate pool")
	}
	return certPool, nil
}

// CertPoolFromFile builds an x509.CertPool by reading a PEM-encoded certificate
// file from disk. Callers use this when the trust anchor is stored on the file
// system (file-backed scenarios).
func CertPoolFromFile(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, fmt.Errorf("certificate authority file is required")
	}
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading certificate authority file: %w", err)
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("failed to parse certificate authority file %s", path)
	}
	return certPool, nil
}
