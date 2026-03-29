package mtlsenterprise

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
)

// step5StartServer loads the chain bundle and root CA from disk and starts the mTLS listener.
func step5StartServer(state *demoState, serverCfg ServerConfig) error {
	fmt.Println("=== Step 5/8: Start mTLS server (presenting certificate chain) ===")
	fmt.Println("Server presents: server cert + intermediate CA. Server trusts: root CA for client validation.")
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
	return nil
}
