package mtlsmem

import (
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
	serverCertPEM    []byte
	serverKeyPEM     []byte
	clientCertPEM    []byte
	clientKeyPEM     []byte
	server           *httptest.Server
	serverURL        string
}

func CreateServer(certPem, privateKeyPem []byte, caCert *x509.Certificate) (*httptest.Server, error) {
	return server.NewMemoryMTLS(server.MemoryMTLSConfig{
		CertificatePEM: certPem,
		PrivateKeyPEM:  privateKeyPem,
		ClientCA:       caCert,
	})
}

func CreateClient(ca *x509.Certificate, clientCertPem, clientKeyPem []byte) (*http.Client, error) {
	return client.NewMTLSFromMemory(client.MemoryMTLSConfig{
		CACert:         ca,
		CertificatePEM: clientCertPem,
		PrivateKeyPEM:  clientKeyPem,
	})
}
