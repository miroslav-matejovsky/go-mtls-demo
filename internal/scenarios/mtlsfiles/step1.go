package mtlsfiles

import (
	"fmt"
	"path/filepath"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/ca"
	"github.com/miroslav-matejovsky/go-mtls-demo/internal/operator"
)

// step1GenerateCertificates creates the CA plus trusted server and client credentials and writes them to their directories.
func step1GenerateCertificates(state *demoState, opCfg OperatorConfig, serverCfg ServerConfig, clientCfg ClientConfig) error {
	fmt.Println("=== Step 1/6: Generate CA, Server, and Client certificates ===")
	fmt.Println("Each party owns its own directory — in production they never share private keys:")
	fmt.Printf("  %s  — Certificate Authority (operator)\n", filepath.Dir(opCfg.CertFile))
	fmt.Printf("  %s  — Server operator\n", filepath.Dir(serverCfg.CertFile))
	fmt.Printf("  %s  — Client operator\n", filepath.Dir(clientCfg.CertFile))
	fmt.Println()

	authority, err := NewAuthority(opCfg)
	if err != nil {
		return fmt.Errorf("error creating operator: %w", err)
	}
	validity, err := opCfg.ParseValidity()
	if err != nil {
		return err
	}
	if err := operator.DistributeTrustAnchor(serverCfg.CACertFile, authority.TrustAnchor()); err != nil {
		return fmt.Errorf("error distributing CA certificate to server: %w", err)
	}
	if err := operator.DistributeTrustAnchor(clientCfg.CACertFile, authority.TrustAnchor()); err != nil {
		return fmt.Errorf("error distributing CA certificate to client: %w", err)
	}

	state.authority = authority
	state.validity = validity

	ca.PrintCertificateInfo(authority.TrustAnchor())
	fmt.Printf("  [OPERATOR] CA Certificate → %s\n", opCfg.CertFile)
	fmt.Printf("  [OPERATOR] Distributed to server → %s\n", serverCfg.CACertFile)
	fmt.Printf("  [OPERATOR] Distributed to client → %s\n", clientCfg.CACertFile)
	fmt.Println("  [OPERATOR] Private key stays on the CA machine — NOT written to disk here.")
	fmt.Println()

	serverCert, serverPrivateKey, err := authority.SignServerCert(serverCfg.CN, nil)
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

	clientCert, clientPrivateKey, err := authority.SignClientCert(clientCfg.CN)
	if err != nil {
		return fmt.Errorf("error creating client certificate: %w", err)
	}
	if err := operator.WriteIdentity(clientCfg.CertFile, clientCfg.KeyFile, clientCert, clientPrivateKey); err != nil {
		return fmt.Errorf("error writing client credentials: %w", err)
	}

	ca.PrintCertificateInfo(clientCert)
	fmt.Printf("  [CLIENT] Certificate → %s\n", clientCfg.CertFile)
	fmt.Printf("  [CLIENT] Private key  → %s\n", clientCfg.KeyFile)
	fmt.Println()
	return nil
}
