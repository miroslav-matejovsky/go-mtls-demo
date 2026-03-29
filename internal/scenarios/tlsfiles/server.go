package tlsfiles

import (
	"net/http"

	sharedserver "github.com/miroslav-matejovsky/go-mtls-demo/internal/server"
)

func CreateServer(certFile, keyFile string) (*http.Server, error) {
	return sharedserver.NewFileTLS(sharedserver.FileTLSConfig{
		CertificateFile: certFile,
		PrivateKeyFile:  keyFile,
	})
}
