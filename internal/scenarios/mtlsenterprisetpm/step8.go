//go:build windows

package mtlsenterprisetpm

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/ca"
	"github.com/miroslav-matejovsky/go-mtls-demo/internal/operator"
)

// step8UntrustedClient creates a separate enterprise PKI hierarchy and shows the server rejecting it.
func step8UntrustedClient(state *demoState, untrustedCfg UntrustedClientConfig) error {
	if err := state.unexpectedServerError(); err != nil {
		return err
	}

	fmt.Println("=== Step 8/9: Demonstrate untrusted client (separate enterprise PKI) ===")
	fmt.Println("This client's certificate chain originates from a completely different root CA.")
	fmt.Println("The private key is generated in-memory (not from a cert store), then written to disk for this demo. The server must reject the connection.")
	fmt.Println()

	// Build an entirely separate enterprise PKI for the untrusted client.
	untrustedAuthority, err := ca.NewEnterprise(ca.EnterpriseConfig{
		RootCA:         ca.CAConfig{CN: untrustedCfg.RootCACN, Validity: 24 * time.Hour},
		IntermediateCA: ca.CAConfig{CN: untrustedCfg.IntermediateCACN, Validity: 24 * time.Hour},
	})
	if err != nil {
		return fmt.Errorf("error creating untrusted enterprise CA: %w", err)
	}

	untrustedCSR, untrustedClientKey, err := ca.CreateClientCSR(untrustedCfg.CN)
	if err != nil {
		return fmt.Errorf("error creating untrusted client CSR: %w", err)
	}
	untrustedClientCert, err := untrustedAuthority.SignClientCSR(untrustedCSR)
	if err != nil {
		return fmt.Errorf("error signing untrusted client certificate: %w", err)
	}
	if err := operator.WriteChainIdentity(untrustedCfg.ChainFile, untrustedCfg.KeyFile, untrustedClientCert, untrustedClientKey, untrustedAuthority.Intermediate()); err != nil {
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

	// Build the untrusted client using file-based chain + trusted root for server verification
	untrustedClient, err := createUntrustedClient(untrustedCfg)
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

// createUntrustedClient builds an HTTP client using file-based chain bundle and key.
// It trusts the server's root CA (from rootCertFile) but presents a client cert from
// a different PKI, which the server will reject.
func createUntrustedClient(cfg UntrustedClientConfig) (*http.Client, error) {
	rootPEM, err := os.ReadFile(cfg.RootCertFile)
	if err != nil {
		return nil, fmt.Errorf("error reading root CA certificate: %w", err)
	}
	certpool := x509.NewCertPool()
	if !certpool.AppendCertsFromPEM(rootPEM) {
		return nil, fmt.Errorf("failed to parse root CA certificate from %s", cfg.RootCertFile)
	}

	tlsCert, err := tls.LoadX509KeyPair(cfg.ChainFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("error loading untrusted client chain/key: %w", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:   tls.VersionTLS12,
				RootCAs:      certpool,
				Certificates: []tls.Certificate{tlsCert},
			},
		},
	}
	return client, nil
}
