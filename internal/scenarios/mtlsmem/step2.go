package mtlsmem

import (
	"fmt"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/ca"
)

// step2GenerateServerCertificate creates the server certificate needed by the mTLS server.
func step2GenerateServerCertificate(state *demoState) error {
	fmt.Println("=== Step 2/6: Generate Server Certificate (signed by CA) ===")
	fmt.Println("The server presents this certificate to the client during the mTLS handshake.")
	fmt.Println("The client verifies its signature chain leads back to the trusted CA.")
	fmt.Println()

	serverCert, serverPrivateKey, err := ca.CreateLeafCertAndKey(state.signLeaf, "go mTLS Demo Server")
	if err != nil {
		return fmt.Errorf("error creating server certificate: %w", err)
	}

	state.serverCert = serverCert
	state.serverPrivateKey = serverPrivateKey

	ca.PrintCertificateInfo(serverCert)
	return nil
}
