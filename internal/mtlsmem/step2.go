package mtlsmem

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/cert"
)

// step2GenerateServerCertificate creates the server certificate and PEM material needed by the mTLS server.
func step2GenerateServerCertificate(state *demoState) error {
	fmt.Println("=== Step 2/5: Generate Server Certificate (signed by CA) ===")
	fmt.Println("The server presents this certificate to the client during the mTLS handshake.")
	fmt.Println("The client verifies its signature chain leads back to the trusted cert.")
	fmt.Println()

	serverCert, serverPrivateKey, err := cert.CreateLeafCert(state.signLeaf, "go mTLS Demo Server")
	if err != nil {
		return fmt.Errorf("error creating server certificate: %w", err)
	}

	serverPrivPEMBytes, err := x509.MarshalECPrivateKey(serverPrivateKey)
	if err != nil {
		return fmt.Errorf("error marshaling server EC private key: %w", err)
	}

	state.serverCert = serverCert
	state.serverPrivateKey = serverPrivateKey
	state.serverCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Raw})
	state.serverKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverPrivPEMBytes})

	cert.PrintCertificateInfo(serverCert)
	return nil
}
