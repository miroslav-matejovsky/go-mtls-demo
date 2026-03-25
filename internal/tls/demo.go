package tls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func RunDemo() error {
	fmt.Println("=== Step 1/4: Generate Certificate Authority (CA) ===")
	fmt.Println("A self-signed CA is the trusted root for this demo.")
	fmt.Println("Its certificate is given to the client so it can verify the server's identity.")
	fmt.Println()

	ca, signLeaf, err := CreateCa()
	if err != nil {
		return fmt.Errorf("error creating CA: %w", err)
	}
	PrintCertificateInfo(ca)

	fmt.Println("=== Step 2/4: Generate Server Certificate (signed by CA) ===")
	fmt.Println("The server presents this certificate during the TLS handshake.")
	fmt.Println("The client verifies its signature chain leads back to the trusted CA.")
	fmt.Println()

	serverCert, serverPrivateKey, err := CreateLeafCert(signLeaf, "go TLS Demo Server")
	if err != nil {
		return fmt.Errorf("error creating server certificate: %w", err)
	}
	PrintCertificateInfo(serverCert)

	serverPrivPemBytes, err := x509.MarshalECPrivateKey(serverPrivateKey)
	if err != nil {
		return fmt.Errorf("error marshaling EC private key: %w", err)
	}
	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Raw})
	privateKeyPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverPrivPemBytes})

	fmt.Println("=== Step 3/4: Start TLS server ===")
	fmt.Println("Server config: presents its certificate to clients.")
	fmt.Println("Server does NOT require a certificate from the client (one-way TLS).")
	fmt.Println()

	server, err := CreateServer(certPem, privateKeyPem)
	if err != nil {
		return fmt.Errorf("error creating server: %w", err)
	}
	server.StartTLS()
	defer server.Close()
	fmt.Printf("[SERVER] Listening on %s\n", server.URL)
	fmt.Println()

	fmt.Println("=== Step 4/4: Make request over TLS ===")
	fmt.Println("Client config: trusts the CA — does NOT send a certificate (one-way TLS).")
	fmt.Println("Authentication: client verifies server cert → CA   |   server trusts any client.")
	fmt.Println()

	client, err := CreateClient(ca)
	if err != nil {
		return fmt.Errorf("error creating client: %w", err)
	}

	fmt.Printf("[CLIENT] GET %s\n", server.URL)
	resp, err := client.Get(server.URL)
	if err != nil {
		return fmt.Errorf("error making GET request: %w", err)
	}
	defer resp.Body.Close()

	fmt.Printf("[CLIENT] Handshake complete  — version: %s, cipher suite: %s\n",
		tlsVersionName(resp.TLS.Version), tls.CipherSuiteName(resp.TLS.CipherSuite))
	fmt.Println("[CLIENT] Response:", resp.Status)
	return nil
}
