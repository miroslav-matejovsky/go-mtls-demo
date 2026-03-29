package mtlsmem

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/kpi"
)

func CreateServer(certPem, privateKeyPem []byte, caCert *x509.Certificate) (*httptest.Server, error) {
	serverCert, err := tls.X509KeyPair(certPem, privateKeyPem)
	if err != nil {
		return nil, fmt.Errorf("error creating TLS certificate: %w", err)
	}

	clientCAs := x509.NewCertPool()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	clientCAs.AppendCertsFromPEM(caPEM)

	serverTLSConf := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tlsState := r.TLS
		fmt.Printf("[SERVER] Received request over mTLS — version: %s, cipher suite: %s\n",
			kpi.TLSVersionName(tlsState.Version), tls.CipherSuiteName(tlsState.CipherSuite))
		if len(tlsState.PeerCertificates) > 0 {
			fmt.Printf("[SERVER] Client certificate: %s (issued by %s)\n",
				tlsState.PeerCertificates[0].Subject, tlsState.PeerCertificates[0].Issuer)
		}
		fmt.Fprintln(w, "success!")
	}))
	server.TLS = serverTLSConf
	return server, nil
}
