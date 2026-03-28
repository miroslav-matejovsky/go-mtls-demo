//go:build windows

package mtlsenterprisetpm

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/cert"
)

// step8UntrustedClient creates a separate enterprise PKI hierarchy and shows the server rejecting it.
func step8UntrustedClient(state *demoState, untrustedCfg UntrustedClientConfig) error {
	if err := state.unexpectedServerError(); err != nil {
		return err
	}

	fmt.Println("=== Step 8/9: Demonstrate untrusted client (separate enterprise PKI) ===")
	fmt.Println("This client's certificate chain originates from a completely different root CA.")
	fmt.Println("The private key is in-memory (no cert store). The server must reject the connection.")
	fmt.Println()

	// Build an entirely separate PKI: root → intermediate → client leaf
	_, untrustedSignInt, err := cert.CreateRootCA(untrustedCfg.RootCACN, 24*time.Hour)
	if err != nil {
		return fmt.Errorf("error creating untrusted root CA: %w", err)
	}
	untrustedIntCert, untrustedSignLeaf, err := untrustedSignInt(untrustedCfg.IntermediateCACN, 24*time.Hour)
	if err != nil {
		return fmt.Errorf("error creating untrusted intermediate CA: %w", err)
	}

	profile := cert.LeafProfile{
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	untrustedClientCert, untrustedClientKey, err := cert.CreateLeafCertWithProfile(untrustedSignLeaf, untrustedCfg.CN, profile)
	if err != nil {
		return fmt.Errorf("error creating untrusted client certificate: %w", err)
	}
	untrustedKeyBytes, err := x509.MarshalECPrivateKey(untrustedClientKey)
	if err != nil {
		return fmt.Errorf("error marshaling untrusted client key: %w", err)
	}

	// Write untrusted chain bundle (leaf + untrusted intermediate)
	if err := cert.WriteChainBundle(untrustedCfg.ChainFile, untrustedClientCert, untrustedIntCert); err != nil {
		return fmt.Errorf("error writing untrusted client chain bundle: %w", err)
	}
	if err := cert.WriteKey(untrustedCfg.KeyFile, untrustedKeyBytes); err != nil {
		return fmt.Errorf("error writing untrusted client key: %w", err)
	}
	// The untrusted client still needs the TRUSTED server's root CA to verify the server cert
	if err := state.operator.DistributeRootCA(untrustedCfg.RootCertFile); err != nil {
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

	// Load the untrusted chain bundle (leaf + untrusted intermediate) + key
	chainPEM, err := os.ReadFile(cfg.ChainFile)
	if err != nil {
		return nil, fmt.Errorf("error reading untrusted chain file: %w", err)
	}
	keyPEM, err := os.ReadFile(cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("error reading untrusted key file: %w", err)
	}

	// Parse the chain PEM to get individual cert DER blocks
	var certDERs [][]byte
	rest := chainPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			certDERs = append(certDERs, block.Bytes)
		}
	}
	if len(certDERs) == 0 {
		return nil, fmt.Errorf("no certificates found in %s", cfg.ChainFile)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode key PEM from %s", cfg.KeyFile)
	}
	privKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing untrusted client key: %w", err)
	}

	leaf, err := x509.ParseCertificate(certDERs[0])
	if err != nil {
		return nil, fmt.Errorf("error parsing untrusted leaf certificate: %w", err)
	}

	tlsCert := tls.Certificate{
		Certificate: certDERs,
		PrivateKey:  privKey,
		Leaf:        leaf,
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
