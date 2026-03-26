package mtlsfiles

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"crypto/x509"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/ca"
)

func CreateServer(certFile, keyFile, caCertFile string) (*httptest.Server, error) {
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

	serverTLSConf := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tlsState := r.TLS
		fmt.Printf("[SERVER] Received request over mTLS — version: %s, cipher suite: %s\n",
			ca.TLSVersionName(tlsState.Version), tls.CipherSuiteName(tlsState.CipherSuite))
		if len(tlsState.PeerCertificates) > 0 {
			fmt.Printf("[SERVER] Client certificate: %s (issued by %s)\n",
				tlsState.PeerCertificates[0].Subject, tlsState.PeerCertificates[0].Issuer)
		}
		fmt.Fprintln(w, "success!")
	}))
	server.TLS = serverTLSConf
	return server, nil
}
