package tlsmem

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/pki"
)

// step2GenerateServerCertificate creates the server leaf certificate and PEM material for the TLS server.
func step2GenerateServerCertificate(state *demoState) error {
	fmt.Println("=== Step 2/4: Generate Server Certificate (signed by CA) ===")
	fmt.Println("The server presents this certificate during the TLS handshake.")
	fmt.Println("The client verifies its signature chain leads back to the trusted cert.")
	fmt.Println()

	serverCert, serverPrivateKey, err := pki.CreateLeafCertAndKey(state.signLeaf, "go TLS Demo Server")
	if err != nil {
		return fmt.Errorf("error creating server certificate: %w", err)
	}

	serverPrivPEMBytes, err := x509.MarshalECPrivateKey(serverPrivateKey)
	if err != nil {
		return fmt.Errorf("error marshaling EC private key: %w", err)
	}

	state.serverCert = serverCert
	state.serverPrivateKey = serverPrivateKey
	state.serverCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Raw})
	state.serverKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverPrivPEMBytes})

	pki.PrintCertificateInfo(serverCert)
	return nil
}
