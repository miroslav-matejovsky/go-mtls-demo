package mtlsfiles

import (
	"net/http"

	sharedserver "github.com/miroslav-matejovsky/go-mtls-demo/internal/server"
)

func CreateServer(certFile, keyFile, caCertFile string) (*http.Server, error) {
	return sharedserver.NewFileMTLS(sharedserver.FileMTLSConfig{
		CertificateFile: certFile,
		PrivateKeyFile:  keyFile,
		ClientCAFile:    caCertFile,
	})
}
