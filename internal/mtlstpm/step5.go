//go:build windows

package mtlstpm

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/cert"
)

// step5StartServerAndMakeTrustedRequest starts the file-backed mTLS server and completes the trusted Windows-store client request.
func step5StartServerAndMakeTrustedRequest(state *demoState, serverCfg ServerConfig) error {
	fmt.Println("=== Step 5/7: Start mTLS server and make trusted request ===")
	fmt.Printf("Server loads certificates from disk: %s\n", serverCfg.CertFile)
	fmt.Printf("Client uses key from Windows cert store (provider: %s) — no key file on disk.\n", state.provider)
	fmt.Println()

	server, err := CreateServer(serverCfg.CertFile, serverCfg.KeyFile, serverCfg.CACertFile)
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

	client, err := CreateClient(state.operator.CACert(), state.storeKey, state.storedClientCert)
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
		cert.TLSVersionName(resp.TLS.Version), tls.CipherSuiteName(resp.TLS.CipherSuite))
	fmt.Printf("[CLIENT] Signing performed by: %s (private key never left the provider)\n", state.provider)
	fmt.Println("[CLIENT] Response:", resp.Status)
	fmt.Println()
	if err := state.unexpectedServerError(); err != nil {
		return err
	}
	return nil
}
