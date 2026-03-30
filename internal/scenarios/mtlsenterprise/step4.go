package mtlsenterprise

import (
	"crypto/x509"
	"fmt"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/ca"
	"github.com/miroslav-matejovsky/go-mtls-demo/internal/operator"
)

// step4GenerateClientCert issues a client certificate with ClientAuth EKU.
func step4GenerateClientCert(state *demoState, clientCfg ClientConfig) error {
	fmt.Println("=== Step 4/8: Generate client certificate (ClientAuth EKU) ===")
	fmt.Println()

	clientCert, clientKey, err := state.operator.SignClientCert(clientCfg.CN)
	if err != nil {
		return fmt.Errorf("error creating client certificate: %w", err)
	}
	clientKeyBytes, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		return fmt.Errorf("error marshaling client key: %w", err)
	}

	if err := state.operator.WriteChain(clientCfg.ChainFile, clientCert); err != nil {
		return fmt.Errorf("error writing client chain bundle: %w", err)
	}
	if err := operator.WriteKey(clientCfg.KeyFile, clientKeyBytes); err != nil {
		return fmt.Errorf("error writing client key: %w", err)
	}
	if err := state.operator.DistributeTrustAnchor(clientCfg.RootCertFile); err != nil {
		return fmt.Errorf("error distributing root CA to client: %w", err)
	}

	fmt.Println("[OPERATOR] Client certificate:")
	ca.PrintCertificateInfo(clientCert)
	fmt.Printf("  [CLIENT] EKU         : ClientAuth only\n")
	fmt.Printf("  [CLIENT] Chain bundle → %s\n", clientCfg.ChainFile)
	fmt.Printf("  [CLIENT] Private key  → %s\n", clientCfg.KeyFile)
	fmt.Printf("  [CLIENT] Root CA cert → %s  (distributed by operator)\n", clientCfg.RootCertFile)
	fmt.Println()
	return nil
}
