//go:build windows

package mtlsenterprisetpm

import (
	"fmt"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/ca"
)

// step1CreateRootCA creates the root CA and persists its certificate to disk.
// The root CA is offline in production — its only job is to sign intermediate CA CSRs.
func step1CreateRootCA(state *demoState, opCfg OperatorConfig) error {
	fmt.Println("=== Step 1/9: Create Root CA (Enterprise PKI) ===")
	fmt.Println("In production the root CA is offline — it only signs intermediate CAs.")
	fmt.Println()

	rootCA, err := NewRootAuthority(opCfg)
	if err != nil {
		return fmt.Errorf("error creating root CA: %w", err)
	}
	state.rootAuthority = rootCA

	fmt.Println("[OPERATOR] Root CA certificate:")
	ca.PrintCertificateInfo(rootCA.TrustAnchor())
	fmt.Printf("  [OPERATOR] Root CA cert → %s\n", opCfg.RootCA.CertFile)
	fmt.Println("  [OPERATOR] Root CA key stays in memory — never written to disk.")
	fmt.Println()
	return nil
}
