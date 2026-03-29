package tlsmem

import (
	"crypto/x509"
	"net/http"

	sharedclient "github.com/miroslav-matejovsky/go-mtls-demo/internal/client"
)

func CreateClient(ca *x509.Certificate) (*http.Client, error) {
	return sharedclient.NewTLSFromMemory(sharedclient.MemoryTLSConfig{
		CACert: ca,
	})
}
