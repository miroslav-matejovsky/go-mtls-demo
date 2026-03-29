package client

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
)

// SignerMTLSConfig describes a mutual TLS client whose private key lives behind
// a crypto.Signer, such as a TPM-backed NCrypt key.
type SignerMTLSConfig struct {
	CACert           *x509.Certificate
	PrivateKey       crypto.Signer
	CertificateChain []*x509.Certificate
}

// NewMTLSWithSigner builds a mutual TLS client whose private key operations are
// delegated to cfg.PrivateKey.
func NewMTLSWithSigner(cfg SignerMTLSConfig) (*http.Client, error) {
	certPool, err := certPoolFromCertificate(cfg.CACert)
	if err != nil {
		return nil, fmt.Errorf("creating signer-backed mTLS client: %w", err)
	}
	if cfg.PrivateKey == nil {
		return nil, fmt.Errorf("creating signer-backed mTLS client: private key is required")
	}
	if len(cfg.CertificateChain) == 0 {
		return nil, fmt.Errorf("creating signer-backed mTLS client: certificate chain is required")
	}

	certChain := make([][]byte, 0, len(cfg.CertificateChain))
	for i, cert := range cfg.CertificateChain {
		if cert == nil {
			return nil, fmt.Errorf("creating signer-backed mTLS client: certificate chain entry %d is nil", i)
		}
		certChain = append(certChain, cert.Raw)
	}

	tlsCert := tls.Certificate{
		Certificate: certChain,
		PrivateKey:  cfg.PrivateKey,
		Leaf:        cfg.CertificateChain[0],
	}

	return newHTTPClient(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      certPool,
		Certificates: []tls.Certificate{tlsCert},
	}), nil
}
