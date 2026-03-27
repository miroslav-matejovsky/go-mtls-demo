package tlsfiles

import (
	"crypto/tls"
	"fmt"
	"path/filepath"
)

// step3StartServer loads the server certificate from disk and starts the file-backed TLS listener.
func step3StartServer(state *demoState, serverCfg ServerConfig) error {
	fmt.Println("=== Step 3/4: Start TLS server (loading certificate from disk) ===")
	fmt.Printf("Server reads from its own directory: %s\n", filepath.Dir(serverCfg.CertFile))
	fmt.Println("Server does NOT require a certificate from the client (one-way TLS).")
	fmt.Println()

	server, err := CreateServer(serverCfg.CertFile, serverCfg.KeyFile)
	if err != nil {
		return fmt.Errorf("error creating server: %w", err)
	}
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
