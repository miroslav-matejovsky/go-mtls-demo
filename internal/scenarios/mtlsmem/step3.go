package mtlsmem

import (
	"fmt"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/ca"
)

// step3GenerateClientCertificate creates the trusted client certificate for the mutual-TLS client.
func step3GenerateClientCertificate(state *demoState) error {
	fmt.Println("=== Step 3/6: Generate Client Certificate (signed by CA) ===")
	fmt.Println("KEY DIFFERENCE from plain TLS: the client also has a certificate.")
	fmt.Println("The server will require this certificate and verify it against the trusted CA.")
	fmt.Println()

	clientCSR, clientPrivateKey, err := ca.CreateClientCSR("go mTLS Demo Client")
	if err != nil {
		return fmt.Errorf("error creating client CSR: %w", err)
	}
	clientCert, err := state.authority.SignClientCSR(clientCSR)
	if err != nil {
		return fmt.Errorf("error signing client certificate: %w", err)
	}

	state.clientCert = clientCert
	state.clientPrivateKey = clientPrivateKey

	ca.PrintCertificateInfo(clientCert)
	return nil
}
