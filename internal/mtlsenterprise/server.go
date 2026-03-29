package mtlsenterprise

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/kpi"
)

func CreateServer(chainFile, keyFile, rootCertFile string) (*http.Server, error) {
	serverCert, err := tls.LoadX509KeyPair(chainFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("error loading server certificate chain: %w", err)
	}

	rootPEM, err := os.ReadFile(rootCertFile)
	if err != nil {
		return nil, fmt.Errorf("error reading root CA certificate: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(rootPEM) {
		return nil, fmt.Errorf("failed to parse root CA certificate from %s", rootCertFile)
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
				kpi.TLSVersionName(tlsState.Version), tls.CipherSuiteName(tlsState.CipherSuite))
			if len(tlsState.PeerCertificates) > 0 {
				fmt.Printf("[SERVER] Client certificate: %s (issued by %s)\n",
					tlsState.PeerCertificates[0].Subject, tlsState.PeerCertificates[0].Issuer)
			}
			fmt.Fprintln(w, "success!")
		}),
	}
	return srv, nil
}
