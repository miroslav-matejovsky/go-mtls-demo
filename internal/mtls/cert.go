package mtls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

func tlsVersionName(version uint16) string {
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
	if ku&x509.KeyUsageCertSign != 0          { names = append(names, "certSign") }
	if ku&x509.KeyUsageCRLSign != 0           { names = append(names, "cRLSign") }
	if ku&x509.KeyUsageDigitalSignature != 0  { names = append(names, "digitalSignature") }
	if ku&x509.KeyUsageContentCommitment != 0 { names = append(names, "contentCommitment") }
	if ku&x509.KeyUsageKeyEncipherment != 0   { names = append(names, "keyEncipherment") }
	if ku&x509.KeyUsageDataEncipherment != 0  { names = append(names, "dataEncipherment") }
	if ku&x509.KeyUsageKeyAgreement != 0      { names = append(names, "keyAgreement") }
	if ku&x509.KeyUsageEncipherOnly != 0      { names = append(names, "encipherOnly") }
	if ku&x509.KeyUsageDecipherOnly != 0      { names = append(names, "decipherOnly") }
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}

type signerFunc func(pub crypto.PublicKey, cn string) (*x509.Certificate, error)

func CreateCa() (*x509.Certificate, signerFunc, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate CA key: %w", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "go mTLS Demo CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
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
		certTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:     x509.KeyUsageDigitalSignature,
			IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
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

func CreateLeafCert(signLeaf signerFunc, cn string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	// this might be replaced by certtostore store.GenerateKey()
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

func PrintCertificateInfo(cert *x509.Certificate) {
	fmt.Printf("  Subject       : %s\n", cert.Subject.CommonName)
	fmt.Printf("  Issuer        : %s\n", cert.Issuer.CommonName)
	fmt.Printf("  Serial        : %s\n", cert.SerialNumber)
	fmt.Printf("  Valid         : %s → %s\n",
		cert.NotBefore.Format("2006-01-02 15:04 UTC"),
		cert.NotAfter.Format("2006-01-02 15:04 UTC"))
	fmt.Printf("  Is CA         : %t\n", cert.IsCA)
	fmt.Printf("  Key Usage     : %s\n", keyUsageNames(cert.KeyUsage))
	fmt.Printf("  Ext Key Usage : %v\n", cert.ExtKeyUsage)
	fmt.Println()
}
