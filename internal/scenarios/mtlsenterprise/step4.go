package mtlsenterprise

import (
	"crypto/x509"
	"fmt"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/kpi"
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

	if err := state.operator.WriteClientChain(clientCfg.ChainFile, clientCert); err != nil {
		return fmt.Errorf("error writing client chain bundle: %w", err)
	}
	if err := kpi.WriteKey(clientCfg.KeyFile, clientKeyBytes); err != nil {
		return fmt.Errorf("error writing client key: %w", err)
	}
	if err := state.operator.DistributeRootCA(clientCfg.RootCertFile); err != nil {
		return fmt.Errorf("error distributing root CA to client: %w", err)
	}

	fmt.Println("[OPERATOR] Client certificate:")
	kpi.PrintCertificateInfo(clientCert)
	fmt.Printf("  [CLIENT] EKU         : ClientAuth only\n")
	fmt.Printf("  [CLIENT] Chain bundle → %s\n", clientCfg.ChainFile)
	fmt.Printf("  [CLIENT] Private key  → %s\n", clientCfg.KeyFile)
	fmt.Printf("  [CLIENT] Root CA cert → %s  (distributed by operator)\n", clientCfg.RootCertFile)
	fmt.Println()
	return nil
}
