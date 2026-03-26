package tlsfiles

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/cert"
)

func CreateServer(certFile, keyFile string) (*http.Server, error) {
	serverCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("error loading server certificate: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}

	srv := &http.Server{
		TLSConfig: tlsCfg,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tlsState := r.TLS
			fmt.Printf("[SERVER] Received request over TLS — version: %s, cipher suite: %s\n",
				cert.TLSVersionName(tlsState.Version), tls.CipherSuiteName(tlsState.CipherSuite))
			fmt.Fprintln(w, "success!")
		}),
	}
	return srv, nil
}
