//go:build windows

package mtlsenterprisetpm

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
)

// CreateClient builds an mTLS HTTP client whose private key is a crypto.Signer.
// The TLS certificate includes both the leaf and the intermediate CA cert so the
// server can verify the full chain during the handshake. The trust pool uses the
// root CA certificate for server verification.
func CreateClient(rootCert *x509.Certificate, intermediateCert *x509.Certificate, key crypto.Signer, clientCert *x509.Certificate) (*http.Client, error) {
	certpool := x509.NewCertPool()
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Raw})
	if !certpool.AppendCertsFromPEM(rootPEM) {
		return nil, fmt.Errorf("failed to build root CA cert pool")
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{clientCert.Raw, intermediateCert.Raw},
		PrivateKey:  key,
		Leaf:        clientCert,
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:   tls.VersionTLS12,
				RootCAs:      certpool,
				Certificates: []tls.Certificate{tlsCert},
			},
		},
	}
	return client, nil
}
