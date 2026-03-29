package mtlsenterprise

import (
	"net/http"

	sharedserver "github.com/miroslav-matejovsky/go-mtls-demo/internal/server"
)

func CreateServer(chainFile, keyFile, rootCertFile string) (*http.Server, error) {
	return sharedserver.NewFileMTLS(sharedserver.FileMTLSConfig{
		CertificateFile: chainFile,
		PrivateKeyFile:  keyFile,
		ClientCAFile:    rootCertFile,
	})
}
