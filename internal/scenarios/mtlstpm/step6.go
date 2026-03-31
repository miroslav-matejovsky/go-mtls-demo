//go:build windows

package mtlstpm

import (
	"fmt"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/ca"
)

// step6DemonstrateUntrustedClient creates a different-CA client in memory and shows the server rejecting it.
func step6DemonstrateUntrustedClient(state *demoState, opCfg OperatorConfig, untrustedCfg UntrustedClientConfig) error {
	if err := state.unexpectedServerError(); err != nil {
		return err
	}

	fmt.Println("=== Step 6/7: Demonstrate untrusted client ===")
	fmt.Println("Creating a client cert signed by a different CA — not trusted by the server.")
	fmt.Println("The private key is in-memory (no cert store). The server must reject the connection.")
	fmt.Println()

	validity, err := opCfg.ParseValidity()
	if err != nil {
		return err
	}
	untrustedAuthority, err := ca.NewSimple(ca.CAConfig{
		CN:       untrustedCfg.CACN,
		Validity: validity,
	})
	if err != nil {
		return fmt.Errorf("error creating untrusted CA: %w", err)
	}
	untrustedCSR, untrustedKey, err := ca.CreateClientCSR(untrustedCfg.CN)
	if err != nil {
		return fmt.Errorf("error creating untrusted client CSR: %w", err)
	}
	untrustedCert, err := untrustedAuthority.SignClientCSR(untrustedCSR)
	if err != nil {
		return fmt.Errorf("error signing untrusted client certificate: %w", err)
	}

	// The untrusted client still uses the trusted CA cert to verify the server —
	// it's rejected because its OWN cert is from a different CA, not because it
	// can't reach the server.
	untrustedClient, err := CreateClient(state.authority.TrustAnchor(), untrustedKey, untrustedCert)
	if err != nil {
		return fmt.Errorf("error creating untrusted client: %w", err)
	}

	fmt.Printf("[UNTRUSTED CLIENT] GET %s\n", state.serverURL)
	_, err = untrustedClient.Get(state.serverURL)
	if err != nil {
		fmt.Printf("[UNTRUSTED CLIENT] Connection rejected — %s\n", err)
		fmt.Println("[UNTRUSTED CLIENT] Expected: server refused client cert — not signed by the trusted CA.")
		fmt.Println()
		if err := state.unexpectedServerError(); err != nil {
			return err
		}
		return nil
	}

	return fmt.Errorf("expected untrusted client to be rejected, but request succeeded")
}
