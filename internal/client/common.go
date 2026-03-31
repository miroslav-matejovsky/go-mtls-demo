// Package client provides shared TLS client builders used by the demo
// scenarios. It centralizes trust-pool assembly and TLS certificate creation
// while leaving request execution and narrative output to the scenario
// packages.
package client

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/ca"
)

func newHTTPClient(tlsConfig *tls.Config) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
}

func certPoolFromCertificate(caCert *x509.Certificate) (*x509.CertPool, error) {
	return ca.CertPoolFromCertificate(caCert)
}

func certPoolFromFile(path string) (*x509.CertPool, error) {
	pool, err := ca.CertPoolFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("client trust pool: %w", err)
	}
	return pool, nil
}
