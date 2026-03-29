package tlsmem

import (
	"crypto/ecdsa"
	"crypto/x509"
	"net/http"
	"net/http/httptest"

	sharedclient "github.com/miroslav-matejovsky/go-mtls-demo/internal/client"
	"github.com/miroslav-matejovsky/go-mtls-demo/internal/pki"
	sharedserver "github.com/miroslav-matejovsky/go-mtls-demo/internal/server"
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
	serverCertPEM    []byte
	serverKeyPEM     []byte
	server           *httptest.Server
	serverURL        string
	client           *http.Client
}

func CreateServer(certPem, privateKeyPem []byte) (*httptest.Server, error) {
	return sharedserver.NewMemoryTLS(sharedserver.MemoryTLSConfig{
		CertificatePEM: certPem,
		PrivateKeyPEM:  privateKeyPem,
	})
}

func CreateClient(ca *x509.Certificate) (*http.Client, error) {
	return sharedclient.NewTLSFromMemory(sharedclient.MemoryTLSConfig{
		CACert: ca,
	})
}
