package mtlsfiles

import (
	"crypto/x509"
	"fmt"
	"path/filepath"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/cert"
)

// step4GenerateUntrustedClient creates a separate client identity signed by a different CA to use in the rejection flow.
func step4GenerateUntrustedClient(state *demoState, untrustedCfg UntrustedClientConfig) error {
	fmt.Println("=== Step 4/6: Generate untrusted client certificate (different CA) ===")
	fmt.Println("This simulates a client from an external organisation — its CA is not trusted by the server.")
	fmt.Printf("Untrusted client files written to: %s\n", filepath.Dir(untrustedCfg.CertFile))
	fmt.Println()

	_, untrustedSignLeaf, err := cert.CreateCA(untrustedCfg.CACN, state.validity)
	if err != nil {
		return fmt.Errorf("error creating untrusted CA: %w", err)
	}
	untrustedClientCert, untrustedClientKey, err := cert.CreateLeafCert(untrustedSignLeaf, untrustedCfg.CN)
	if err != nil {
		return fmt.Errorf("error creating untrusted client certificate: %w", err)
	}
	untrustedKeyBytes, err := x509.MarshalECPrivateKey(untrustedClientKey)
	if err != nil {
		return fmt.Errorf("error marshaling untrusted client key: %w", err)
	}
	if err := cert.WriteCert(untrustedCfg.CertFile, untrustedClientCert); err != nil {
		return fmt.Errorf("error writing untrusted client certificate: %w", err)
	}
	if err := cert.WriteKey(untrustedCfg.KeyFile, untrustedKeyBytes); err != nil {
		return fmt.Errorf("error writing untrusted client key: %w", err)
	}
	// The untrusted client still needs the server's CA cert to verify the server during
	// the handshake — it's untrusted because its OWN cert is signed by a different CA.
	if err := state.operator.DistributeCA(untrustedCfg.CACertFile); err != nil {
		return fmt.Errorf("error writing trusted CA cert to untrusted directory: %w", err)
	}

	fmt.Printf("  [UNTRUSTED CLIENT] Certificate → %s\n", untrustedCfg.CertFile)
	fmt.Printf("  [UNTRUSTED CLIENT] Private key  → %s\n", untrustedCfg.KeyFile)
	fmt.Printf("  [UNTRUSTED CLIENT] Server CA    → %s  (to verify server, but client cert is from a different CA)\n", untrustedCfg.CACertFile)
	fmt.Println()
	return nil
}
