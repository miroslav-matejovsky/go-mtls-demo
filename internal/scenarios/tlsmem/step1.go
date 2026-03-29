package tlsmem

import (
	"fmt"
	"time"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/pki"
)

// step1GenerateCA prints the CA introduction and creates the trusted root for the TLS memory demo.
func step1GenerateCA(state *demoState) error {
	fmt.Println("=== Step 1/4: Generate Certificate Authority (CA) ===")
	fmt.Println("A self-signed CA is the trusted root for this demo.")
	fmt.Println("Its certificate is given to the client so it can verify the server's identity.")
	fmt.Println()

	caCert, signLeaf, err := pki.CreateCA("go TLS Demo CA", 24*time.Hour)
	if err != nil {
		return fmt.Errorf("error creating CA: %w", err)
	}

	state.caCert = caCert
	state.signLeaf = signLeaf

	pki.PrintCertificateInfo(caCert)
	return nil
}
