package mtlsmem

import (
	"crypto/ecdsa"
	"crypto/x509"
	"net/http/httptest"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/kpi"
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
	signLeaf         kpi.SignerFunc
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
