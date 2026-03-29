package tlsfiles

import (
	"crypto/x509"
	"fmt"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/kpi"
)

// step2GenerateServerCertificate issues the server certificate and writes the server-owned files to disk.
func step2GenerateServerCertificate(state *demoState, serverCfg ServerConfig) error {
	fmt.Println("=== Step 2/4: Generate Server Certificate (signed by CA) ===")
	fmt.Println("The CA signs the server certificate and hands it to the server operator.")
	fmt.Println("The private key is generated locally and stays in the server's own directory.")
	fmt.Println()

	serverCert, serverPrivateKey, err := state.operator.SignCert(serverCfg.CN)
	if err != nil {
		return fmt.Errorf("error creating server certificate: %w", err)
	}

	serverKeyBytes, err := x509.MarshalECPrivateKey(serverPrivateKey)
	if err != nil {
		return fmt.Errorf("error marshaling server key: %w", err)
	}
	if err := kpi.WriteCert(serverCfg.CertFile, serverCert); err != nil {
		return fmt.Errorf("error writing server certificate: %w", err)
	}
	if err := kpi.WriteKey(serverCfg.KeyFile, serverKeyBytes); err != nil {
		return fmt.Errorf("error writing server key: %w", err)
	}

	kpi.PrintCertificateInfo(serverCert)
	fmt.Printf("  [SERVER] Certificate → %s\n", serverCfg.CertFile)
	fmt.Printf("  [SERVER] Private key  → %s\n", serverCfg.KeyFile)
	fmt.Println()
	return nil
}
