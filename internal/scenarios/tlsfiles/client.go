package tlsfiles

import (
	"net/http"

	sharedclient "github.com/miroslav-matejovsky/go-mtls-demo/internal/client"
)

func CreateClient(caCertFile string) (*http.Client, error) {
	return sharedclient.NewTLSFromFiles(sharedclient.FileTLSConfig{
		CACertFile: caCertFile,
	})
}
