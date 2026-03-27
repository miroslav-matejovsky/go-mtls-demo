package tlsfiles

import (
	"fmt"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/cert"
)

// step1GenerateCA creates the operator CA, prints its details, and distributes the trust anchor to the client.
func step1GenerateCA(state *demoState, opCfg OperatorConfig, clientCfg ClientConfig) error {
	fmt.Println("=== Step 1/4: Generate Certificate Authority (CA) ===")
	fmt.Println("In a real deployment the CA lives on a dedicated secure machine.")
	fmt.Println("Its public certificate is distributed to clients and servers.")
	fmt.Println("The private key never leaves the CA machine — it is NOT written to disk here.")
	fmt.Println()

	operator, err := NewOperator(opCfg)
	if err != nil {
		return fmt.Errorf("error creating operator: %w", err)
	}
	if err := operator.DistributeCA(clientCfg.CACertFile); err != nil {
		return fmt.Errorf("error distributing CA certificate to client: %w", err)
	}

	state.operator = operator

	cert.PrintCertificateInfo(operator.CACert())
	fmt.Printf("  [OPERATOR] CA Certificate → %s\n", opCfg.CertFile)
	fmt.Printf("  [OPERATOR] Distributed to client → %s\n", clientCfg.CACertFile)
	fmt.Println()
	return nil
}
