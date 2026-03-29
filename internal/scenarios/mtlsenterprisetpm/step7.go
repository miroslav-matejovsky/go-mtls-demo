//go:build windows

package mtlsenterprisetpm

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/pki"
)

// step7StartServerAndRequest starts the file-backed mTLS server and completes the trusted request
// using the TPM-backed client key with the enterprise certificate chain.
func step7StartServerAndRequest(state *demoState, serverCfg ServerConfig) error {
	fmt.Println("=== Step 7/9: Start mTLS server and make trusted request ===")
	fmt.Printf("Server loads chain bundle from disk: %s\n", serverCfg.ChainFile)
	fmt.Printf("Client uses TPM-backed key (provider: %s) with enterprise cert chain (leaf + intermediate).\n", state.provider)
	fmt.Println()

	server, err := CreateServer(serverCfg.ChainFile, serverCfg.KeyFile, serverCfg.RootCertFile)
	if err != nil {
		return fmt.Errorf("error creating server: %w", err)
	}
	server.ErrorLog = log.New(io.Discard, "", 0)

	ln, err := tls.Listen("tcp", serverCfg.Address, server.TLSConfig)
	if err != nil {
		return fmt.Errorf("error starting TLS listener on %s: %w", serverCfg.Address, err)
	}
	go func() {
		state.recordServerError(server.Serve(ln))
	}()

	state.server = server
	state.serverURL = "https://" + ln.Addr().String()

	fmt.Printf("[SERVER] Listening on %s\n", state.serverURL)
	fmt.Println()

	client, err := CreateClient(state.operator.RootCert(), state.operator.IntermediateCert(), state.storeKey, state.storedClientCert)
	if err != nil {
		return fmt.Errorf("error creating client: %w", err)
	}

	fmt.Printf("[CLIENT] GET %s\n", state.serverURL)
	resp, err := client.Get(state.serverURL)
	if err != nil {
		return fmt.Errorf("error making GET request: %w", err)
	}
	defer resp.Body.Close()

	fmt.Printf("[CLIENT] Server certificate verified: %s (issued by %s)\n",
		resp.TLS.PeerCertificates[0].Subject.CommonName, resp.TLS.PeerCertificates[0].Issuer.CommonName)
	fmt.Printf("[CLIENT] Handshake complete  — version: %s, cipher suite: %s\n",
		pki.TLSVersionName(resp.TLS.Version), tls.CipherSuiteName(resp.TLS.CipherSuite))
	fmt.Printf("[CLIENT] Signing performed by: %s (private key never left the provider)\n", state.provider)
	fmt.Println("[CLIENT] Response:", resp.Status)
	fmt.Println()
	if err := state.unexpectedServerError(); err != nil {
		return err
	}
	return nil
}
