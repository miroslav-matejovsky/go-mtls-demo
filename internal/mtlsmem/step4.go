package mtlsmem

import (
	"fmt"
	"io"
	"log"
)

// step4StartServer starts the in-memory mTLS server and suppresses the default rejected-client error log noise.
func step4StartServer(state *demoState) error {
	fmt.Println("=== Step 4/6: Start mTLS server ===")
	fmt.Println("Server config: presents its certificate AND requires a valid client certificate.")
	fmt.Println("Connections without a CA-signed client certificate will be rejected.")
	fmt.Println()

	server, err := CreateServer(state.serverCertPEM, state.serverKeyPEM, state.caCert)
	if err != nil {
		return fmt.Errorf("error creating server: %w", err)
	}
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()

	state.server = server
	state.serverURL = server.URL

	fmt.Printf("[SERVER] Listening on %s\n", state.serverURL)
	fmt.Println()
	return nil
}
