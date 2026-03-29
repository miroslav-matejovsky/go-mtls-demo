//go:build windows

package mtlstpm

import (
	"crypto/x509"
	"fmt"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/pki"
)

// step1GenerateCAAndServer creates the in-memory CA, signs the server certificate, and writes server files to disk.
func step1GenerateCAAndServer(state *demoState, opCfg OperatorConfig, serverCfg ServerConfig) error {
	fmt.Println("=== Step 1/7: Generate CA and Server certificate ===")
	fmt.Println("CA is in-memory only — its private key is never written to disk.")
	fmt.Printf("Server cert and CA distribution copy written to: %s\n", serverCfg.CertFile)
	fmt.Println()

	operator, err := NewOperator(opCfg)
	if err != nil {
		return fmt.Errorf("error creating operator: %w", err)
	}
	serverCert, serverKey, err := operator.SignCert(serverCfg.CN)
	if err != nil {
		return fmt.Errorf("error creating server certificate: %w", err)
	}
	serverKeyBytes, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		return fmt.Errorf("error marshaling server key: %w", err)
	}
	if err := pki.WriteCert(serverCfg.CertFile, serverCert); err != nil {
		return fmt.Errorf("error writing server certificate: %w", err)
	}
	if err := pki.WriteKey(serverCfg.KeyFile, serverKeyBytes); err != nil {
		return fmt.Errorf("error writing server key: %w", err)
	}
	if err := operator.DistributeCA(serverCfg.CACertFile); err != nil {
		return fmt.Errorf("error distributing CA cert to server: %w", err)
	}

	state.operator = operator

	pki.PrintCertificateInfo(operator.CACert())
	pki.PrintCertificateInfo(serverCert)
	fmt.Printf("  [SERVER]   Certificate → %s\n", serverCfg.CertFile)
	fmt.Printf("  [SERVER]   Private key  → %s\n", serverCfg.KeyFile)
	fmt.Printf("  [SERVER]   CA cert      → %s\n", serverCfg.CACertFile)
	fmt.Printf("  [OPERATOR] Reference    → %s\n", opCfg.CertFile)
	fmt.Println()
	return nil
}
