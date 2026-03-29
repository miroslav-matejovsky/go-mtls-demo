package mtlsmem

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"net/http"
	"net/http/httptest"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/client"
	"github.com/miroslav-matejovsky/go-mtls-demo/internal/pki"
	"github.com/miroslav-matejovsky/go-mtls-demo/internal/server"
)

func RunDemo() error {
	return runDemo()
}

func runDemo() error {
	state := &demoState{}

	if err := step1GenerateCA(state); err != nil {
		return err
	}
	if err := step2GenerateServerCertificate(state); err != nil {
		return err
	}
	if err := step3GenerateClientCertificate(state); err != nil {
		return err
	}
	if err := step4StartServer(state); err != nil {
		return err
	}
	defer state.server.Close()

	if err := step5MakeTrustedRequest(state); err != nil {
		return err
	}

	return step6MakeUntrustedRequest(state)
}

type demoState struct {
	caCert           *x509.Certificate
	signLeaf         pki.SignerFunc
	serverCert       *x509.Certificate
	serverPrivateKey *ecdsa.PrivateKey
	clientCert       *x509.Certificate
	clientPrivateKey *ecdsa.PrivateKey
	server           *httptest.Server
	serverURL        string
}

func CreateServer(cert *x509.Certificate, key crypto.Signer, caCert *x509.Certificate) (*httptest.Server, error) {
	return server.NewMemoryMTLS(server.MemoryMTLSConfig{
		Certificate: cert,
		PrivateKey:  key,
		ClientCA:    caCert,
	})
}

func CreateClient(caCert *x509.Certificate, key crypto.Signer, clientCert *x509.Certificate) (*http.Client, error) {
	return client.NewMTLSWithSigner(client.SignerMTLSConfig{
		CACert:           caCert,
		PrivateKey:       key,
		CertificateChain: []*x509.Certificate{clientCert},
	})
}
