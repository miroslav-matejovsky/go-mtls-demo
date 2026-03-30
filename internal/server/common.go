// Package server provides shared TLS server builders used by the demo
// scenarios. It centralizes TLS configuration, trust-pool assembly, and
// default demo handlers while still allowing scenarios to inject custom HTTP
// handlers when needed.
package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/ca"
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
			ca.TLSVersionName(tlsState.Version),
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
	return ca.CertPoolFromCertificate(caCert)
}

func certPoolFromFile(path string) (*x509.CertPool, error) {
	pool, err := ca.CertPoolFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("server trust pool: %w", err)
	}
	return pool, nil
}
