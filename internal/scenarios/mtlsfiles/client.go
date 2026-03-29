package mtlsfiles

import (
	"net/http"

	sharedclient "github.com/miroslav-matejovsky/go-mtls-demo/internal/client"
)

func CreateClient(caCertFile, clientCertFile, clientKeyFile string) (*http.Client, error) {
	return sharedclient.NewMTLSFromFiles(sharedclient.FileMTLSConfig{
		CACertFile:      caCertFile,
		CertificateFile: clientCertFile,
		PrivateKeyFile:  clientKeyFile,
	})
}
