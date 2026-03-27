package tlsmem

import (
	"crypto/ecdsa"
	"crypto/x509"
	"net/http"
	"net/http/httptest"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/cert"
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
	signLeaf         cert.SignerFunc
	serverCert       *x509.Certificate
	serverPrivateKey *ecdsa.PrivateKey
	serverCertPEM    []byte
	serverKeyPEM     []byte
	server           *httptest.Server
	serverURL        string
	client           *http.Client
}
