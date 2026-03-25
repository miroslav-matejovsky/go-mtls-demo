package tls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
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

func RunDemoTLS() error {
	println("Creating CA...")
	ca, signLeaf, err := CreateCa()
	if err != nil {
		return fmt.Errorf("error creating CA: %w", err)
	}
	println("CA created successfully")
	PrintCertificateInfo(ca)

	leafCert, leafPrivateKey, err := CreateLeafCert(signLeaf)
	if err != nil {
		return fmt.Errorf("error creating leaf certificate: %w", err)
	}
	println("Leaf certificate created successfully")
	PrintCertificateInfo(leafCert)

	leafPrivPemBytes, err := x509.MarshalECPrivateKey(leafPrivateKey)
	if err != nil {
		return fmt.Errorf("error marshaling EC private key: %w", err)
	}

	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw})

	privateKeyPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafPrivPemBytes})

	server, err := CreateServer(certPem, privateKeyPem)
	if err != nil {
		return fmt.Errorf("error creating server: %w", err)
	}
	server.StartTLS()
	defer server.Close()

	fmt.Printf("[SERVER] Listening on %s (TLS enabled)\n", server.URL)
	client, err := CreateClient(ca)
	if err != nil {
		return fmt.Errorf("error creating client: %w", err)
	}

	fmt.Println("[CLIENT] Sending GET request over TLS...")
	resp, err := client.Get(server.URL)
	if err != nil {
		return fmt.Errorf("error making GET request: %w", err)
	}
	defer resp.Body.Close()

	fmt.Printf("[CLIENT] TLS handshake complete — version: %s, cipher suite: %s, server: %s\n",
		tlsVersionName(resp.TLS.Version), tls.CipherSuiteName(resp.TLS.CipherSuite), resp.TLS.ServerName)
	fmt.Println("[CLIENT] Response status:", resp.Status)
	return nil
}
