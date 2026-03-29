package mtlsenterprise

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
)

func CreateClient(rootCertFile, chainFile, keyFile string) (*http.Client, error) {
	rootPEM, err := os.ReadFile(rootCertFile)
	if err != nil {
		return nil, fmt.Errorf("error reading root CA certificate: %w", err)
	}
	certpool := x509.NewCertPool()
	if !certpool.AppendCertsFromPEM(rootPEM) {
		return nil, fmt.Errorf("failed to parse root CA certificate from %s", rootCertFile)
	}

	clientCert, err := tls.LoadX509KeyPair(chainFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("error loading client certificate chain: %w", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:   tls.VersionTLS12,
				RootCAs:      certpool,
				Certificates: []tls.Certificate{clientCert},
			},
		},
	}
	return client, nil
}
