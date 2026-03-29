package mtlsmem

import (
	"crypto/x509"
	"net/http"

	sharedclient "github.com/miroslav-matejovsky/go-mtls-demo/internal/client"
)

func CreateClient(ca *x509.Certificate, clientCertPem, clientKeyPem []byte) (*http.Client, error) {
	return sharedclient.NewMTLSFromMemory(sharedclient.MemoryMTLSConfig{
		CACert:         ca,
		CertificatePEM: clientCertPem,
		PrivateKeyPEM:  clientKeyPem,
	})
}
