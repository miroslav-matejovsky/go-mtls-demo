package mtls

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
)

func CreateServer(certPem, keyPem []byte) (*httptest.Server, error) {
	serverCert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		return nil, fmt.Errorf("error creating TLS certificate: %w", err)
	}

	serverTLSConf := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tlsState := r.TLS
		fmt.Printf("[SERVER] Received request over TLS — version: %s, cipher suite: %s\n",
			tlsVersionName(tlsState.Version), tls.CipherSuiteName(tlsState.CipherSuite))
		fmt.Fprintln(w, "success!")
	}))
	server.TLS = serverTLSConf
	return server, nil
}
