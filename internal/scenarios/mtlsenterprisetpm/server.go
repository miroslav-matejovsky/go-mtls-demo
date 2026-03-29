//go:build windows

package mtlsenterprisetpm

import (
	"net/http"

	sharedserver "github.com/miroslav-matejovsky/go-mtls-demo/internal/server"
)

// CreateServer builds a file-backed mTLS server that loads its chain bundle and key from disk,
// and requires client certificates signed by the root CA whose cert is in rootCertFile.
func CreateServer(chainFile, keyFile, rootCertFile string) (*http.Server, error) {
	return sharedserver.NewFileMTLS(sharedserver.FileMTLSConfig{
		CertificateFile: chainFile,
		PrivateKeyFile:  keyFile,
		ClientCAFile:    rootCertFile,
	})
}
