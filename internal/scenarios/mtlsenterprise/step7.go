package mtlsenterprise

import (
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/ca"
	"github.com/miroslav-matejovsky/go-mtls-demo/internal/operator"
)

// step7UntrustedRequest creates a separate PKI hierarchy and attempts a request that must be rejected.
func step7UntrustedRequest(state *demoState, untrustedCfg UntrustedClientConfig) error {
	if err := state.unexpectedServerError(); err != nil {
		return err
	}

	fmt.Println("=== Step 7/8: Make request with untrusted client (different PKI) ===")
	fmt.Println("This client's certificate chain originates from a completely different root CA.")
	fmt.Println()

	// Build an entirely separate PKI: root → intermediate → client leaf
	_, untrustedSignInt, err := ca.CreateRootCA(untrustedCfg.RootCACN, 24*time.Hour)
	if err != nil {
		return fmt.Errorf("error creating untrusted root CA: %w", err)
	}
	untrustedIntCert, untrustedSignLeaf, err := untrustedSignInt(untrustedCfg.IntermediateCACN, 24*time.Hour)
	if err != nil {
		return fmt.Errorf("error creating untrusted intermediate CA: %w", err)
	}

	profile := ca.LeafProfile{
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	untrustedClientCert, untrustedClientKey, err := ca.GenerateLeafCertificateAndKey(untrustedSignLeaf, untrustedCfg.CN, profile)
	if err != nil {
		return fmt.Errorf("error creating untrusted client certificate: %w", err)
	}
	if err := operator.WriteChainIdentity(untrustedCfg.ChainFile, untrustedCfg.KeyFile, untrustedClientCert, untrustedClientKey, untrustedIntCert); err != nil {
		return fmt.Errorf("error writing untrusted client credentials: %w", err)
	}
	// The untrusted client still needs the TRUSTED server's root CA to verify the server cert
	if err := operator.DistributeTrustAnchor(untrustedCfg.RootCertFile, state.authority.TrustAnchor()); err != nil {
		return fmt.Errorf("error writing trusted root CA to untrusted directory: %w", err)
	}

	fmt.Printf("  [UNTRUSTED CLIENT] Chain bundle → %s\n", untrustedCfg.ChainFile)
	fmt.Printf("  [UNTRUSTED CLIENT] Private key  → %s\n", untrustedCfg.KeyFile)
	fmt.Printf("  [UNTRUSTED CLIENT] Server root  → %s  (to verify server, but client cert chains to different root)\n", untrustedCfg.RootCertFile)
	fmt.Println()

	untrustedClient, err := CreateClient(untrustedCfg.RootCertFile, untrustedCfg.ChainFile, untrustedCfg.KeyFile)
	if err != nil {
		return fmt.Errorf("error creating untrusted client: %w", err)
	}

	fmt.Printf("[UNTRUSTED CLIENT] GET %s\n", state.serverURL)
	_, err = untrustedClient.Get(state.serverURL)
	if err != nil {
		fmt.Printf("[UNTRUSTED CLIENT] Connection rejected — %s\n", err)
		fmt.Println("[UNTRUSTED CLIENT] Expected: server refused the certificate because it was not signed by the trusted CA.")
		fmt.Println()
		if err := state.unexpectedServerError(); err != nil {
			return err
		}
		return nil
	}

	return fmt.Errorf("expected untrusted client to be rejected, but request succeeded")
}
