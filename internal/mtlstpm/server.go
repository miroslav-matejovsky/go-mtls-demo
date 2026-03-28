//go:build windows

package mtlstpm

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/cert"
)

// CreateServer builds a file-backed mTLS server that requires client certificates
// signed by the CA whose cert is in caCertFile.
func CreateServer(certFile, keyFile, caCertFile string) (*http.Server, error) {
	serverCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("error loading server certificate: %w", err)
	}

	caPEM, err := os.ReadFile(caCertFile)
	if err != nil {
		return nil, fmt.Errorf("error reading CA certificate: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to parse CA certificate from %s", caCertFile)
	}

	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	srv := &http.Server{
		TLSConfig:    tlsCfg,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tlsState := r.TLS
			fmt.Printf("[SERVER] Received request over mTLS — version: %s, cipher suite: %s\n",
				cert.TLSVersionName(tlsState.Version), tls.CipherSuiteName(tlsState.CipherSuite))
			if len(tlsState.PeerCertificates) > 0 {
				fmt.Printf("[SERVER] Client certificate: %s (issued by %s)\n",
					tlsState.PeerCertificates[0].Subject, tlsState.PeerCertificates[0].Issuer)
			}
			fmt.Fprintln(w, "success!")
		}),
	}
	return srv, nil
}
