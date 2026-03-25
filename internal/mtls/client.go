package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
)

func CreateClient(ca *x509.Certificate, clientCert, clientKey string) (*http.Client, error) {
	certpool := x509.NewCertPool()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	certpool.AppendCertsFromPEM(caPEM)

	certificate, err := tls.LoadX509KeyPair(clientCert, clientKey)
	if err != nil {
		return nil, fmt.Errorf("error loading client certificate and key: %w", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      certpool,
				Certificates: []tls.Certificate{certificate},
			},
		},
	}
	return client, nil
}
