package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
)

var loopbackIPs = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}

// CreateIntermediateCSR creates a CSR for an intermediate CA with a fresh ECDSA P-256 key.
// The CSR carries only the Subject DN and public key — CA policy extensions
// (IsCA, MaxPathLen, KeyUsage:CertSign) are NOT included because they are
// applied by the root CA as signer policy, not by the requestor.
func CreateIntermediateCSR(cn string) (*x509.CertificateRequest, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate intermediate CA key: %w", err)
	}
	csr, err := createCSR(&x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key, "intermediate CA")
	if err != nil {
		return nil, nil, err
	}
	return csr, key, nil
}

// CreateServerCSR creates a server CSR and a fresh ECDSA P-256 private key.
func CreateServerCSR(cn string, dnsNames []string) (*x509.CertificateRequest, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate server key: %w", err)
	}
	csr, err := createServerCSRWithSigner(key, cn, dnsNames)
	if err != nil {
		return nil, nil, err
	}
	return csr, key, nil
}

// CreateServerCSRForSigner creates a server CSR using an existing signer.
func CreateServerCSRForSigner(signer crypto.Signer, cn string, dnsNames []string) (*x509.CertificateRequest, error) {
	return createServerCSRWithSigner(signer, cn, dnsNames)
}

// CreateClientCSR creates a client CSR and a fresh ECDSA P-256 private key.
func CreateClientCSR(cn string) (*x509.CertificateRequest, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate client key: %w", err)
	}
	csr, err := createClientCSRWithSigner(key, cn)
	if err != nil {
		return nil, nil, err
	}
	return csr, key, nil
}

// CreateClientCSRForSigner creates a client CSR using an existing signer.
func CreateClientCSRForSigner(signer crypto.Signer, cn string) (*x509.CertificateRequest, error) {
	return createClientCSRWithSigner(signer, cn)
}

func createServerCSRWithSigner(signer crypto.Signer, cn string, dnsNames []string) (*x509.CertificateRequest, error) {
	if signer == nil {
		return nil, fmt.Errorf("failed to create server CSR: signer is required")
	}
	template := &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: cn},
		DNSNames:    dnsNames,
		IPAddresses: loopbackIPs,
	}
	return createCSR(template, signer, "server")
}

func createClientCSRWithSigner(signer crypto.Signer, cn string) (*x509.CertificateRequest, error) {
	if signer == nil {
		return nil, fmt.Errorf("failed to create client CSR: signer is required")
	}
	template := &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: cn},
		IPAddresses: loopbackIPs,
	}
	return createCSR(template, signer, "client")
}

func createCSR(template *x509.CertificateRequest, signer crypto.Signer, role string) (*x509.CertificateRequest, error) {
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s CSR: %w", role, err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s CSR: %w", role, err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("failed to verify %s CSR signature: %w", role, err)
	}
	return csr, nil
}
