//go:build windows

package mtlstpm

import (
	"fmt"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/ca"
	"github.com/miroslav-matejovsky/go-mtls-demo/internal/operator"
)

// step1GenerateCAAndServer creates the in-memory CA, signs the server certificate, and writes server files to disk.
func step1GenerateCAAndServer(state *demoState, opCfg OperatorConfig, serverCfg ServerConfig) error {
	fmt.Println("=== Step 1/7: Generate CA and Server certificate ===")
	fmt.Println("CA is in-memory only — its private key is never written to disk.")
	fmt.Printf("Server cert and CA distribution copy written to: %s\n", serverCfg.CertFile)
	fmt.Println()

	authority, err := NewAuthority(opCfg)
	if err != nil {
		return fmt.Errorf("error creating operator: %w", err)
	}
	serverCSR, serverKey, err := ca.CreateServerCSR(serverCfg.CN, nil)
	if err != nil {
		return fmt.Errorf("error creating server CSR: %w", err)
	}
	serverCert, err := authority.SignServerCSR(serverCSR)
	if err != nil {
		return fmt.Errorf("error signing server certificate: %w", err)
	}
	if err := operator.WriteIdentity(serverCfg.CertFile, serverCfg.KeyFile, serverCert, serverKey); err != nil {
		return fmt.Errorf("error writing server credentials: %w", err)
	}
	if err := operator.DistributeTrustAnchor(serverCfg.CACertFile, authority.TrustAnchor()); err != nil {
		return fmt.Errorf("error distributing CA cert to server: %w", err)
	}

	state.authority = authority

	ca.PrintCertificateInfo(authority.TrustAnchor())
	ca.PrintCertificateInfo(serverCert)
	fmt.Printf("  [SERVER]   Certificate → %s\n", serverCfg.CertFile)
	fmt.Printf("  [SERVER]   Private key  → %s\n", serverCfg.KeyFile)
	fmt.Printf("  [SERVER]   CA cert      → %s\n", serverCfg.CACertFile)
	fmt.Printf("  [OPERATOR] Reference    → %s\n", opCfg.CertFile)
	fmt.Println()
	return nil
}
