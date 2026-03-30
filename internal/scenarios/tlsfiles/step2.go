package tlsfiles

import (
	"fmt"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/ca"
	"github.com/miroslav-matejovsky/go-mtls-demo/internal/operator"
)

// step2GenerateServerCertificate issues the server certificate and writes the server-owned files to disk.
func step2GenerateServerCertificate(state *demoState, serverCfg ServerConfig) error {
	fmt.Println("=== Step 2/4: Generate Server Certificate (signed by CA) ===")
	fmt.Println("The CA signs the server certificate and hands it to the server operator.")
	fmt.Println("The private key is generated locally and stays in the server's own directory.")
	fmt.Println()

	serverCert, serverPrivateKey, err := state.authority.SignServerCert(serverCfg.CN, nil)
	if err != nil {
		return fmt.Errorf("error creating server certificate: %w", err)
	}

	if err := operator.WriteIdentity(serverCfg.CertFile, serverCfg.KeyFile, serverCert, serverPrivateKey); err != nil {
		return fmt.Errorf("error writing server credentials: %w", err)
	}

	ca.PrintCertificateInfo(serverCert)
	fmt.Printf("  [SERVER] Certificate → %s\n", serverCfg.CertFile)
	fmt.Printf("  [SERVER] Private key  → %s\n", serverCfg.KeyFile)
	fmt.Println()
	return nil
}
