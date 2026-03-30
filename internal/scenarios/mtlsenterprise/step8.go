package mtlsenterprise

import "fmt"

// step8InspectChain prints the certificate chain linkage and the file layout.
func step8InspectChain(state *demoState, opCfg OperatorConfig, serverCfg ServerConfig, clientCfg ClientConfig, untrustedCfg UntrustedClientConfig) {
	fmt.Println("=== Step 8/8: Inspect certificate chain and file layout ===")
	fmt.Println()

	rootCert := state.authority.TrustAnchor()
	intCert := state.authority.Intermediate()

	fmt.Println("Certificate chain (SKID → AKID linkage):")
	fmt.Printf("  Root CA          SKID: %X\n", rootCert.SubjectKeyId)
	fmt.Printf("  Intermediate CA  AKID: %X  (must match Root SKID)\n", intCert.AuthorityKeyId)
	fmt.Printf("  Intermediate CA  SKID: %X\n", intCert.SubjectKeyId)
	fmt.Println("  Leaf certs       AKID: (matches Intermediate SKID — see cert info above)")
	fmt.Println()

	fmt.Println("File layout — each directory represents a security boundary:")
	entries := []struct{ file, note string }{
		{opCfg.RootCA.CertFile, "public — root CA certificate (offline)"},
		{opCfg.IntermediateCA.CertFile, "public — intermediate CA certificate"},
		{serverCfg.ChainFile, "public — server leaf + intermediate CA bundle"},
		{serverCfg.KeyFile, "private — never leaves the server machine"},
		{serverCfg.RootCertFile, "public — root CA copy, used to verify client chains"},
		{clientCfg.ChainFile, "public — client leaf + intermediate CA bundle"},
		{clientCfg.KeyFile, "private — never leaves the client machine"},
		{clientCfg.RootCertFile, "public — root CA copy, used to verify server chain"},
		{untrustedCfg.ChainFile, "public — rejected by server, different PKI"},
		{untrustedCfg.KeyFile, "private — never leaves the untrusted client"},
		{untrustedCfg.RootCertFile, "public — trusted server's root CA copy"},
	}
	for _, entry := range entries {
		fmt.Printf("  %-60s  %s\n", entry.file, entry.note)
	}
}
