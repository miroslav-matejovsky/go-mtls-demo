package mtlsmem

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/ca"
)

func RunDemo() error {
	fmt.Println("=== Step 1/5: Generate Certificate Authority (CA) ===")
	fmt.Println("The same CA signs both the server and client certificates.")
	fmt.Println("Both parties trust this CA and will accept any certificate it has signed.")
	fmt.Println()

	caCert, signLeaf, err := ca.CreateCA("go mTLS Demo CA")
	if err != nil {
		return fmt.Errorf("error creating CA: %w", err)
	}
	ca.PrintCertificateInfo(caCert)

	fmt.Println("=== Step 2/5: Generate Server Certificate (signed by CA) ===")
	fmt.Println("The server presents this certificate to the client during the mTLS handshake.")
	fmt.Println("The client verifies its signature chain leads back to the trusted CA.")
	fmt.Println()

	serverCert, serverPrivateKey, err := ca.CreateLeafCert(signLeaf, "go mTLS Demo Server")
	if err != nil {
		return fmt.Errorf("error creating server certificate: %w", err)
	}
	ca.PrintCertificateInfo(serverCert)

	fmt.Println("=== Step 3/5: Generate Client Certificate (signed by CA) ===")
	fmt.Println("KEY DIFFERENCE from plain TLS: the client also has a certificate.")
	fmt.Println("The server will require this certificate and verify it against the trusted CA.")
	fmt.Println()

	clientCert, clientPrivateKey, err := ca.CreateLeafCert(signLeaf, "go mTLS Demo Client")
	if err != nil {
		return fmt.Errorf("error creating client certificate: %w", err)
	}
	ca.PrintCertificateInfo(clientCert)

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

	fmt.Println("=== Step 4/5: Start mTLS server ===")
	fmt.Println("Server config: presents its certificate AND requires a valid client certificate.")
	fmt.Println("Connections without a CA-signed client certificate will be rejected.")
	fmt.Println()

	server, err := CreateServer(serverCertPem, serverPrivKeyPem, caCert)
	if err != nil {
		return fmt.Errorf("error creating server: %w", err)
	}
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	fmt.Printf("[SERVER] Listening on %s\n", server.URL)
	fmt.Println()

	fmt.Println("=== Step 5/6: Make request over mTLS (trusted client) ===")
	fmt.Println("Client config: trusts the CA AND sends its own certificate (mutual TLS).")
	fmt.Println("Authentication: client verifies server cert → CA   |   server verifies client cert → CA.")
	fmt.Println()

	client, err := CreateClient(caCert, clientCertPem, clientPrivKeyPem)
	if err != nil {
		return fmt.Errorf("error creating client: %w", err)
	}

	fmt.Printf("[CLIENT] GET %s\n", server.URL)
	resp, err := client.Get(server.URL)
	if err != nil {
		return fmt.Errorf("error making GET request: %w", err)
	}
	defer resp.Body.Close()

	fmt.Printf("[CLIENT] Server certificate verified: %s (issued by %s)\n",
		resp.TLS.PeerCertificates[0].Subject.CommonName, resp.TLS.PeerCertificates[0].Issuer.CommonName)
	fmt.Printf("[CLIENT] Handshake complete  — version: %s, cipher suite: %s\n",
		ca.TLSVersionName(resp.TLS.Version), tls.CipherSuiteName(resp.TLS.CipherSuite))
	fmt.Println("[CLIENT] Response:", resp.Status)
	fmt.Println()

	fmt.Println("=== Step 6/6: Make request with an untrusted client certificate ===")
	fmt.Println("This client has a certificate signed by a different CA that the server does not trust.")
	fmt.Println("The server must reject the connection during the TLS handshake.")
	fmt.Println()

	_, untrustedSignLeaf, err := ca.CreateCA("go mTLS Untrusted CA")
	if err != nil {
		return fmt.Errorf("error creating untrusted CA: %w", err)
	}
	untrustedClientCert, untrustedClientKey, err := ca.CreateLeafCert(untrustedSignLeaf, "go mTLS Untrusted Client")
	if err != nil {
		return fmt.Errorf("error creating untrusted client certificate: %w", err)
	}

	untrustedKeyPemBytes, err := x509.MarshalECPrivateKey(untrustedClientKey)
	if err != nil {
		return fmt.Errorf("error marshaling untrusted client key: %w", err)
	}
	untrustedCertPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: untrustedClientCert.Raw})
	untrustedKeyPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: untrustedKeyPemBytes})

	// The untrusted client trusts the server's CA so the TLS dial proceeds far enough for
	// the server to reject the client certificate.
	untrustedClient, err := CreateClient(caCert, untrustedCertPem, untrustedKeyPem)
	if err != nil {
		return fmt.Errorf("error creating untrusted client: %w", err)
	}

	fmt.Printf("[UNTRUSTED CLIENT] GET %s\n", server.URL)
	_, err = untrustedClient.Get(server.URL)
	if err != nil {
		fmt.Printf("[UNTRUSTED CLIENT] Connection rejected — %s\n", err)
		fmt.Println("[UNTRUSTED CLIENT] Expected: server refused the certificate because it was not signed by the trusted CA.")
	} else {
		return fmt.Errorf("expected untrusted client to be rejected, but request succeeded")
	}
	return nil
}
