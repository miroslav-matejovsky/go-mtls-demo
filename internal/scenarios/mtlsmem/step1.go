package mtlsmem

import (
	"fmt"
	"time"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/ca"
)

// step1GenerateCA prints the shared trust-root introduction and creates the CA used by both peers.
func step1GenerateCA(state *demoState) error {
	fmt.Println("=== Step 1/6: Generate Certificate Authority (CA) ===")
	fmt.Println("The same CA signs both the server and client certificates.")
	fmt.Println("Both parties trust this CA and will accept any certificate it has signed.")
	fmt.Println()

	authority, err := ca.NewSimple(ca.CAConfig{
		CN:       "go mTLS Demo CA",
		Validity: 24 * time.Hour,
	})
	if err != nil {
		return fmt.Errorf("error creating CA: %w", err)
	}

	state.authority = authority

	ca.PrintCertificateInfo(authority.TrustAnchor())
	return nil
}
