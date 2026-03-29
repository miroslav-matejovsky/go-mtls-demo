package tlsmem

import (
	"net/http/httptest"

	sharedserver "github.com/miroslav-matejovsky/go-mtls-demo/internal/server"
)

func CreateServer(certPem, privateKeyPem []byte) (*httptest.Server, error) {
	return sharedserver.NewMemoryTLS(sharedserver.MemoryTLSConfig{
		CertificatePEM: certPem,
		PrivateKeyPEM:  privateKeyPem,
	})
}
