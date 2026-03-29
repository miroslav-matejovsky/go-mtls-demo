package tlsfiles

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/pki"
)

func CreateServer(certFile, keyFile string) (*http.Server, error) {
	serverCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("error loading server certificate: %w", err)
	}

	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverCert},
	}

	srv := &http.Server{
		TLSConfig:    tlsCfg,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tlsState := r.TLS
			fmt.Printf("[SERVER] Received request over TLS — version: %s, cipher suite: %s\n",
				pki.TLSVersionName(tlsState.Version), tls.CipherSuiteName(tlsState.CipherSuite))
			fmt.Fprintln(w, "success!")
		}),
	}
	return srv, nil
}
