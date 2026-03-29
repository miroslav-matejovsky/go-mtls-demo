package mtlsmem

import (
	"crypto/x509"
	"net/http/httptest"

	sharedserver "github.com/miroslav-matejovsky/go-mtls-demo/internal/server"
)

func CreateServer(certPem, privateKeyPem []byte, caCert *x509.Certificate) (*httptest.Server, error) {
	return sharedserver.NewMemoryMTLS(sharedserver.MemoryMTLSConfig{
		CertificatePEM: certPem,
		PrivateKeyPEM:  privateKeyPem,
		ClientCA:       caCert,
	})
}
