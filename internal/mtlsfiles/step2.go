package mtlsfiles

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"path/filepath"
)

// step2StartServer loads the server materials from disk and starts the mTLS listener that requires client certificates.
func step2StartServer(state *demoState, serverCfg ServerConfig) error {
	fmt.Println("=== Step 2/6: Start mTLS server (loading certificates from disk) ===")
	fmt.Printf("Server reads from its own directory only: %s\n", filepath.Dir(serverCfg.CertFile))
	fmt.Println("Server config: presents its certificate AND requires a valid client certificate.")
	fmt.Println("Connections without a CA-signed client certificate will be rejected.")
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
	go server.Serve(ln) //nolint:errcheck

	state.server = server
	state.serverURL = "https://" + ln.Addr().String()

	fmt.Printf("[SERVER] Listening on %s\n", state.serverURL)
	fmt.Println()
	return nil
}
