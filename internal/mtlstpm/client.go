//go:build windows

package mtlstpm

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
)

// CreateClient builds an mTLS HTTP client whose private key is a crypto.Signer.
// When called with a certtostore Key, signing happens inside the TPM or NCrypt
// provider — the raw private key bytes never leave the secure enclave.
// The same function accepts an *ecdsa.PrivateKey for the untrusted-client step.
func CreateClient(caCert *x509.Certificate, key crypto.Signer, clientCert *x509.Certificate) (*http.Client, error) {
	certpool := x509.NewCertPool()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	if !certpool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to build CA cert pool")
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{clientCert.Raw},
		PrivateKey:  key,
		Leaf:        clientCert,
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      certpool,
				Certificates: []tls.Certificate{tlsCert},
			},
		},
	}
	return client, nil
}
