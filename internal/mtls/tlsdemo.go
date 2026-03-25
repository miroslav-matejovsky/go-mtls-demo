package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
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

func TlsDemo() {
	println("Creating CA...")
	ca, signLeaf, err := CreateCa()
	if err != nil {
		println("Error creating CA:", err)
		return
	}
	println("CA created successfully")
	PrintCertificateInfo(ca)

	cert, certKey, err := CreateLeafCert(signLeaf)
	if err != nil {
		println("Error creating leaf certificate:", err)
		return
	}
	println("Leaf certificate created successfully")
	PrintCertificateInfo(cert)

	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	privPemBytes, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		println("Error marshaling EC private key:", err)
		return
	}
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privPemBytes})

	server, err := CreateServer(certPem, keyPem)
	if err != nil {
		println("Error creating server:", err)
		return
	}
	server.StartTLS()
	defer server.Close()

	fmt.Printf("[SERVER] Listening on %s (TLS enabled)\n", server.URL)

	certpool := x509.NewCertPool()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	certpool.AppendCertsFromPEM(caPEM)

	clientTLSConf := &tls.Config{RootCAs: certpool}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: clientTLSConf},
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
