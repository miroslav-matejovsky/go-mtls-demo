//go:build windows

package mtlstpm

import (
	"net/http"

	sharedserver "github.com/miroslav-matejovsky/go-mtls-demo/internal/server"
)

// CreateServer builds a file-backed mTLS server that requires client certificates
// signed by the CA whose cert is in caCertFile.
func CreateServer(certFile, keyFile, caCertFile string) (*http.Server, error) {
	return sharedserver.NewFileMTLS(sharedserver.FileMTLSConfig{
		CertificateFile: certFile,
		PrivateKeyFile:  keyFile,
		ClientCAFile:    caCertFile,
	})
}
