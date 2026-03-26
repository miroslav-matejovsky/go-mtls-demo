package tlsfiles

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/ca"
)

func CreateServer(certFile, keyFile string) (*httptest.Server, error) {
	serverCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("error loading server certificate: %w", err)
	}

	serverTLSConf := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tlsState := r.TLS
		fmt.Printf("[SERVER] Received request over TLS — version: %s, cipher suite: %s\n",
			ca.TLSVersionName(tlsState.Version), tls.CipherSuiteName(tlsState.CipherSuite))
		fmt.Fprintln(w, "success!")
	}))
	server.TLS = serverTLSConf
	return server, nil
}
