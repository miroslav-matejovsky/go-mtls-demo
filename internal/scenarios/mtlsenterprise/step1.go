package mtlsenterprise

import (
	"fmt"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/ca"
)

// step1CreateRootCA creates the enterprise PKI operator (root + intermediate CA) and prints root CA info.
func step1CreateRootCA(state *demoState, opCfg OperatorConfig) error {
	fmt.Println("=== Step 1/8: Create Root CA ===")
	fmt.Println("In production the root CA is offline — it only signs intermediate CAs.")
	fmt.Println()

	operator, err := NewOperator(opCfg)
	if err != nil {
		return fmt.Errorf("error creating operator: %w", err)
	}
	state.operator = operator

	fmt.Println("[OPERATOR] Root CA certificate:")
	ca.PrintCertificateInfo(operator.TrustAnchor())
	fmt.Printf("  [OPERATOR] Root CA cert → %s\n", opCfg.RootCA.CertFile)
	fmt.Println("  [OPERATOR] Root CA key stays in memory — never written to disk.")
	fmt.Println()
	return nil
}
