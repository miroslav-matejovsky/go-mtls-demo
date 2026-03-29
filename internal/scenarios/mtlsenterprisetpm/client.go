//go:build windows

package mtlsenterprisetpm

import (
	"crypto"
	"crypto/x509"
	"net/http"

	sharedclient "github.com/miroslav-matejovsky/go-mtls-demo/internal/client"
)

// CreateClient builds an mTLS HTTP client whose private key is a crypto.Signer.
// The TLS certificate includes both the leaf and the intermediate CA cert so the
// server can verify the full chain during the handshake. The trust pool uses the
// root CA certificate for server verification.
func CreateClient(rootCert *x509.Certificate, intermediateCert *x509.Certificate, key crypto.Signer, clientCert *x509.Certificate) (*http.Client, error) {
	return sharedclient.NewMTLSWithSigner(sharedclient.SignerMTLSConfig{
		CACert:     rootCert,
		PrivateKey: key,
		CertificateChain: []*x509.Certificate{
			clientCert,
			intermediateCert,
		},
	})
}
