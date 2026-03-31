package tlsfiles

import (
	"fmt"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/ca"
	"github.com/miroslav-matejovsky/go-mtls-demo/internal/operator"
)

// step1GenerateCA creates the operator CA, prints its details, and distributes the trust anchor to the client.
func step1GenerateCA(state *demoState, opCfg OperatorConfig, clientCfg ClientConfig) error {
	fmt.Println("=== Step 1/4: Generate Certificate Authority (CA) ===")
	fmt.Println("In a real deployment the CA lives on a dedicated secure machine.")
	fmt.Println("Its public certificate is distributed to clients and servers.")
	fmt.Println("The private key never leaves the CA machine — it is NOT written to disk here.")
	fmt.Println()

	authority, err := NewAuthority(opCfg)
	if err != nil {
		return fmt.Errorf("error creating operator: %w", err)
	}
	if err := operator.DistributeTrustAnchor(clientCfg.CACertFile, authority.TrustAnchor()); err != nil {
		return fmt.Errorf("error distributing CA certificate to client: %w", err)
	}

	state.authority = authority

	ca.PrintCertificateInfo(authority.TrustAnchor())
	fmt.Printf("  [OPERATOR] CA Certificate → %s\n", opCfg.CertFile)
	fmt.Printf("  [OPERATOR] Distributed to client → %s\n", clientCfg.CACertFile)
	fmt.Println()
	return nil
}
