// Package server provides shared TLS server builders used by the demo
// scenarios. It centralizes TLS configuration, trust-pool assembly, and
// default demo handlers while still allowing scenarios to inject custom HTTP
// handlers when needed.
package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/pki"
)

func resolveHandler(handler http.Handler, mutualTLS bool) http.Handler {
	if handler != nil {
		return handler
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tlsState := r.TLS
		protocol := "TLS"
		if mutualTLS {
			protocol = "mTLS"
		}
		fmt.Printf("[SERVER] Received request over %s — version: %s, cipher suite: %s\n",
			protocol,
			pki.TLSVersionName(tlsState.Version),
			tls.CipherSuiteName(tlsState.CipherSuite),
		)
		if mutualTLS && len(tlsState.PeerCertificates) > 0 {
			fmt.Printf("[SERVER] Client certificate: %s (issued by %s)\n",
				tlsState.PeerCertificates[0].Subject,
				tlsState.PeerCertificates[0].Issuer,
			)
		}
		fmt.Fprintln(w, "success!")
	})
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
