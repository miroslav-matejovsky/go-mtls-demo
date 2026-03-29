//go:build windows

package mtlstpm

import (
	"crypto"
	"crypto/x509"
	"net/http"

	sharedclient "github.com/miroslav-matejovsky/go-mtls-demo/internal/client"
)

// CreateClient builds an mTLS HTTP client whose private key is a crypto.Signer.
// When called with a certtostore Key, signing happens inside the TPM or NCrypt
// provider — the raw private key bytes never leave the secure enclave.
// The same function accepts an *ecdsa.PrivateKey for the untrusted-client step.
func CreateClient(caCert *x509.Certificate, key crypto.Signer, clientCert *x509.Certificate) (*http.Client, error) {
	return sharedclient.NewMTLSWithSigner(sharedclient.SignerMTLSConfig{
		CACert:           caCert,
		PrivateKey:       key,
		CertificateChain: []*x509.Certificate{clientCert},
	})
}
