package mtlsenterprise

import (
	"crypto/x509"
	"fmt"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/pki"
)

// step3GenerateServerCert issues a server certificate with ServerAuth EKU and DNS SANs.
func step3GenerateServerCert(state *demoState, serverCfg ServerConfig) error {
	fmt.Println("=== Step 3/8: Generate server certificate (ServerAuth EKU, DNS SANs) ===")
	fmt.Println()

	serverCert, serverKey, err := state.operator.SignServerCert(serverCfg.CN, serverCfg.DNSNames)
	if err != nil {
		return fmt.Errorf("error creating server certificate: %w", err)
	}
	serverKeyBytes, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		return fmt.Errorf("error marshaling server key: %w", err)
	}

	if err := state.operator.WriteChain(serverCfg.ChainFile, serverCert); err != nil {
		return fmt.Errorf("error writing server chain bundle: %w", err)
	}
	if err := pki.WriteKey(serverCfg.KeyFile, serverKeyBytes); err != nil {
		return fmt.Errorf("error writing server key: %w", err)
	}
	if err := state.operator.DistributeTrustAnchor(serverCfg.RootCertFile); err != nil {
		return fmt.Errorf("error distributing root CA to server: %w", err)
	}

	fmt.Println("[OPERATOR] Server certificate:")
	pki.PrintCertificateInfo(serverCert)
	fmt.Printf("  [SERVER] EKU         : ServerAuth only\n")
	fmt.Printf("  [SERVER] Chain bundle → %s\n", serverCfg.ChainFile)
	fmt.Printf("  [SERVER] Private key  → %s\n", serverCfg.KeyFile)
	fmt.Printf("  [SERVER] Root CA cert → %s  (distributed by operator)\n", serverCfg.RootCertFile)
	fmt.Println()
	return nil
}
