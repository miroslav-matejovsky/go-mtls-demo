//go:build windows

package mtlsenterprisetpm

import (
	"fmt"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/ca"
	"github.com/miroslav-matejovsky/go-mtls-demo/internal/operator"
)

// step3GenerateServerCert issues a server certificate with ServerAuth EKU and DNS SANs.
func step3GenerateServerCert(state *demoState, serverCfg ServerConfig) error {
	fmt.Println("=== Step 3/9: Generate Server Certificate ===")
	fmt.Println()

	serverCert, serverKey, err := state.authority.SignServerCert(serverCfg.CN, serverCfg.DNSNames)
	if err != nil {
		return fmt.Errorf("error creating server certificate: %w", err)
	}
	if err := operator.WriteChainIdentity(serverCfg.ChainFile, serverCfg.KeyFile, serverCert, serverKey, state.authority.Intermediate()); err != nil {
		return fmt.Errorf("error writing server credentials: %w", err)
	}
	if err := operator.DistributeTrustAnchor(serverCfg.RootCertFile, state.authority.TrustAnchor()); err != nil {
		return fmt.Errorf("error distributing root CA to server: %w", err)
	}

	fmt.Println("[OPERATOR] Server certificate:")
	ca.PrintCertificateInfo(serverCert)
	fmt.Printf("  [SERVER] EKU         : ServerAuth only\n")
	fmt.Printf("  [SERVER] Chain bundle → %s\n", serverCfg.ChainFile)
	fmt.Printf("  [SERVER] Private key  → %s\n", serverCfg.KeyFile)
	fmt.Printf("  [SERVER] Root CA cert → %s  (distributed by operator)\n", serverCfg.RootCertFile)
	fmt.Println()
	return nil
}
