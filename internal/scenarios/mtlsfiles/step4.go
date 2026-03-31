package mtlsfiles

import (
	"fmt"
	"path/filepath"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/ca"
	"github.com/miroslav-matejovsky/go-mtls-demo/internal/operator"
)

// step4GenerateUntrustedClient creates a separate client identity signed by a different CA to use in the rejection flow.
func step4GenerateUntrustedClient(state *demoState, untrustedCfg UntrustedClientConfig) error {
	fmt.Println("=== Step 4/6: Generate untrusted client certificate (different CA) ===")
	fmt.Println("This simulates a client from an external organisation — its CA is not trusted by the server.")
	fmt.Printf("Untrusted client files written to: %s\n", filepath.Dir(untrustedCfg.CertFile))
	fmt.Println()

	untrustedAuthority, err := ca.NewSimple(ca.CAConfig{
		CN:       untrustedCfg.CACN,
		Validity: state.validity,
	})
	if err != nil {
		return fmt.Errorf("error creating untrusted CA: %w", err)
	}
	untrustedCSR, untrustedClientKey, err := ca.CreateClientCSR(untrustedCfg.CN)
	if err != nil {
		return fmt.Errorf("error creating untrusted client CSR: %w", err)
	}
	untrustedClientCert, err := untrustedAuthority.SignClientCSR(untrustedCSR)
	if err != nil {
		return fmt.Errorf("error signing untrusted client certificate: %w", err)
	}
	if err := operator.WriteIdentity(untrustedCfg.CertFile, untrustedCfg.KeyFile, untrustedClientCert, untrustedClientKey); err != nil {
		return fmt.Errorf("error writing untrusted client credentials: %w", err)
	}
	// The untrusted client still needs the server's CA cert to verify the server during
	// the handshake — it's untrusted because its OWN cert is signed by a different CA.
	if err := operator.DistributeTrustAnchor(untrustedCfg.CACertFile, state.authority.TrustAnchor()); err != nil {
		return fmt.Errorf("error writing trusted CA cert to untrusted directory: %w", err)
	}

	fmt.Printf("  [UNTRUSTED CLIENT] Certificate → %s\n", untrustedCfg.CertFile)
	fmt.Printf("  [UNTRUSTED CLIENT] Private key  → %s\n", untrustedCfg.KeyFile)
	fmt.Printf("  [UNTRUSTED CLIENT] Server CA    → %s  (to verify server, but client cert is from a different CA)\n", untrustedCfg.CACertFile)
	fmt.Println()
	return nil
}
