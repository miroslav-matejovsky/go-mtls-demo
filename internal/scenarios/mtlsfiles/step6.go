package mtlsfiles

import "fmt"

// step6InspectFiles prints the final directory layout to show which party owns each file.
func step6InspectFiles(opCfg OperatorConfig, serverCfg ServerConfig, clientCfg ClientConfig, untrustedCfg UntrustedClientConfig) {
	fmt.Println("=== Step 6/6: Inspect files on disk ===")
	fmt.Println("Each directory represents a security boundary — parties only share public certificates:")
	printDirTree(opCfg, serverCfg, clientCfg, untrustedCfg)
}

func printDirTree(opCfg OperatorConfig, serverCfg ServerConfig, clientCfg ClientConfig, untrustedCfg UntrustedClientConfig) {
	entries := []struct{ file, note string }{
		{opCfg.CertFile, "public — the CA's own copy"},
		{serverCfg.CertFile, "public — presented to clients during handshake"},
		{serverCfg.KeyFile, "private — never leaves the server machine"},
		{serverCfg.CACertFile, "public — copy received from operator, used to verify client certs"},
		{clientCfg.CertFile, "public — presented to server during mTLS handshake"},
		{clientCfg.KeyFile, "private — never leaves the client machine"},
		{clientCfg.CACertFile, "public — copy received from operator, used to verify server cert"},
		{untrustedCfg.CertFile, "public — rejected by server, unknown CA"},
		{untrustedCfg.KeyFile, "private — never leaves the untrusted client"},
		{untrustedCfg.CACertFile, "public — copy of server CA, to verify server cert"},
	}
	for _, entry := range entries {
		fmt.Printf("  %-55s  %s\n", entry.file, entry.note)
	}
}
