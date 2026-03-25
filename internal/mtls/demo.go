package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func RunDemo() error {
	println("Creating CA...")
	ca, signLeaf, err := CreateCa()
	if err != nil {
		return fmt.Errorf("error creating CA: %w", err)
	}
	println("CA created successfully")
	PrintCertificateInfo(ca)

	serverCert, serverPrivateKey, err := CreateLeafCert(signLeaf)
	if err != nil {
		return fmt.Errorf("error creating server certificate: %w", err)
	}
	println("Server certificate created successfully")
	PrintCertificateInfo(serverCert)

	clientCert, clientPrivateKey, err := CreateLeafCert(signLeaf)
	if err != nil {
		return fmt.Errorf("error creating client certificate: %w", err)
	}
	println("Client certificate created successfully")
	PrintCertificateInfo(clientCert)

	serverPrivPemBytes, err := x509.MarshalECPrivateKey(serverPrivateKey)
	if err != nil {
		return fmt.Errorf("error marshaling server EC private key: %w", err)
	}
	serverCertPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Raw})
	serverPrivKeyPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverPrivPemBytes})

	clientPrivPemBytes, err := x509.MarshalECPrivateKey(clientPrivateKey)
	if err != nil {
		return fmt.Errorf("error marshaling client EC private key: %w", err)
	}
	clientCertPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCert.Raw})
	clientPrivKeyPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: clientPrivPemBytes})

	server, err := CreateServer(serverCertPem, serverPrivKeyPem, ca)
	if err != nil {
		return fmt.Errorf("error creating server: %w", err)
	}
	server.StartTLS()
	defer server.Close()

	fmt.Printf("[SERVER] Listening on %s (mTLS enabled)\n", server.URL)

	client, err := CreateClient(ca, clientCertPem, clientPrivKeyPem)
	if err != nil {
		return fmt.Errorf("error creating client: %w", err)
	}

	fmt.Println("[CLIENT] Sending GET request over mTLS...")
	resp, err := client.Get(server.URL)
	if err != nil {
		return fmt.Errorf("error making GET request: %w", err)
	}
	defer resp.Body.Close()

	fmt.Printf("[CLIENT] mTLS handshake complete — version: %s, cipher suite: %s, server: %s\n",
		tlsVersionName(resp.TLS.Version), tls.CipherSuiteName(resp.TLS.CipherSuite), resp.TLS.ServerName)
	fmt.Println("[CLIENT] Response status:", resp.Status)
	return nil
}
