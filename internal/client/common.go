// Package client provides shared TLS client builders used by the demo
// scenarios. It centralizes trust-pool assembly and TLS certificate creation
// while leaving request execution and narrative output to the scenario
// packages.
package client

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
)

func newHTTPClient(tlsConfig *tls.Config) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
}

func certPoolFromCertificate(caCert *x509.Certificate) (*x509.CertPool, error) {
	if caCert == nil {
		return nil, fmt.Errorf("certificate authority certificate is required")
	}
	certPool := x509.NewCertPool()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	if !certPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to build certificate pool")
	}
	return certPool, nil
}

func certPoolFromFile(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, fmt.Errorf("certificate authority file is required")
	}
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading certificate authority file: %w", err)
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("failed to parse certificate authority file %s", path)
	}
	return certPool, nil
}
