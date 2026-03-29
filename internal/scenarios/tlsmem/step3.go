package tlsmem

import "fmt"

// step3StartServer starts the in-memory TLS server with the certificate prepared in step 2.
func step3StartServer(state *demoState) error {
	fmt.Println("=== Step 3/4: Start TLS server ===")
	fmt.Println("Server config: presents its certificate to clients.")
	fmt.Println("Server does NOT require a certificate from the client (one-way TLS).")
	fmt.Println()

	server, err := CreateServer(state.serverCert, state.serverPrivateKey)
	if err != nil {
		return fmt.Errorf("error creating server: %w", err)
	}
	server.StartTLS()

	state.server = server
	state.serverURL = server.URL

	fmt.Printf("[SERVER] Listening on %s\n", state.serverURL)
	fmt.Println()
	return nil
}
