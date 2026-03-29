package tlsmem

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
	if err := step3StartServer(state); err != nil {
		return err
	}
	defer state.server.Close()

	return step4MakeRequest(state)
}

type demoState struct {
	caCert           *x509.Certificate
	signLeaf         pki.SignerFunc
	serverCert       *x509.Certificate
	serverPrivateKey *ecdsa.PrivateKey
	server           *httptest.Server
	serverURL        string
	client           *http.Client
}

func CreateServer(cert *x509.Certificate, key crypto.Signer) (*httptest.Server, error) {
	return server.NewMemoryTLS(server.MemoryTLSConfig{
		Certificate: cert,
		PrivateKey:  key,
	})
}

func CreateClient(ca *x509.Certificate) (*http.Client, error) {
	return client.NewTLSFromMemory(client.MemoryTLSConfig{
		CACert: ca,
	})
}
