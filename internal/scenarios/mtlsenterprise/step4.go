package mtlsenterprise

import (
	"fmt"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/ca"
	"github.com/miroslav-matejovsky/go-mtls-demo/internal/operator"
)

// step4GenerateClientCert issues a client certificate with ClientAuth EKU.
func step4GenerateClientCert(state *demoState, clientCfg ClientConfig) error {
	fmt.Println("=== Step 4/8: Generate client certificate (ClientAuth EKU) ===")
	fmt.Println()

	clientCSR, clientKey, err := ca.CreateClientCSR(clientCfg.CN)
	if err != nil {
		return fmt.Errorf("error creating client CSR: %w", err)
	}
	clientCert, err := state.authority.SignClientCSR(clientCSR)
	if err != nil {
		return fmt.Errorf("error signing client certificate: %w", err)
	}
	if err := operator.WriteChainIdentity(clientCfg.ChainFile, clientCfg.KeyFile, clientCert, clientKey, state.authority.Intermediate()); err != nil {
		return fmt.Errorf("error writing client credentials: %w", err)
	}
	if err := operator.DistributeTrustAnchor(clientCfg.RootCertFile, state.authority.TrustAnchor()); err != nil {
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
