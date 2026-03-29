package mtlsenterprise

import (
	"net/http"

	sharedclient "github.com/miroslav-matejovsky/go-mtls-demo/internal/client"
)

func CreateClient(rootCertFile, chainFile, keyFile string) (*http.Client, error) {
	return sharedclient.NewMTLSFromFiles(sharedclient.FileMTLSConfig{
		CACertFile:      rootCertFile,
		CertificateFile: chainFile,
		PrivateKeyFile:  keyFile,
	})
}
