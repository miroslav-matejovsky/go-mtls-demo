package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/mtls"
)

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04X)", version)
	}
}

func main() {
	println("Creating CA...")
	ca, signLeaf, err := mtls.CreateCa()
	if err != nil {
		println("Error creating CA:", err)
		return
	}
	println("CA created successfully")
	mtls.PrintCertificateInfo(ca)

	// this can be replaced by certtostore store.GenerateKey()
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		println("Error generating leaf key:", err)
		return
	}
	cert, err := signLeaf(&certKey.PublicKey, "go mTLS Demo Certificate")
	if err != nil {
		println("Error signing leaf certificate:", err)
		return
	}

	println("Leaf certificate created successfully")
	mtls.PrintCertificateInfo(cert)

	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	privPemBytes, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		println("Error marshaling EC private key:", err)
		return
	}
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privPemBytes})
	serverCert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		println("Error creating TLS certificate:", err)
		return
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
	server.StartTLS()
	defer server.Close()

	fmt.Printf("[SERVER] Listening on %s (TLS enabled)\n", server.URL)

	certpool := x509.NewCertPool()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	certpool.AppendCertsFromPEM(caPEM)

	clientTLSConf := &tls.Config{
		RootCAs: certpool,
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: clientTLSConf,
		},
	}

	fmt.Println("[CLIENT] Sending GET request over TLS...")
	resp, err := client.Get(server.URL)
	if err != nil {
		println("Error making GET request:", err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("[CLIENT] TLS handshake complete — version: %s, cipher suite: %s, server: %s\n",
		tlsVersionName(resp.TLS.Version), tls.CipherSuiteName(resp.TLS.CipherSuite), resp.TLS.ServerName)
	fmt.Println("[CLIENT] Response status:", resp.Status)

}
