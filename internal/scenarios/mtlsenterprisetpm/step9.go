//go:build windows

package mtlsenterprisetpm

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/pwsh"
)

// step9Summary prints the certificate chain linkage, file layout, and cleanup instructions.
func step9Summary(state *demoState, opCfg OperatorConfig, serverCfg ServerConfig, clientCfg ClientConfig) error {
	fmt.Println("=== Step 9/9: Chain linkage summary and cleanup ===")
	fmt.Println()

	rootCert := state.authority.TrustAnchor()
	intCert := state.authority.Intermediate()

	fmt.Println("Certificate chain (enterprise PKI + TPM-backed client key):")
	fmt.Printf("  Root CA (SKID: %X)\n", rootCert.SubjectKeyId)
	fmt.Printf("    └── Intermediate CA (SKID: %X, AKID: %X)\n", intCert.SubjectKeyId, intCert.AuthorityKeyId)
	fmt.Printf("          ├── Server cert (expected AKID: %X) → file-based chain bundle\n", intCert.SubjectKeyId)
	fmt.Printf("          └── Client cert (expected AKID: %X) → TPM-backed key in Windows cert store\n", intCert.SubjectKeyId)
	fmt.Println()

	fmt.Println("File layout — each directory represents a security boundary:")
	entries := []struct{ file, note string }{
		{opCfg.RootCA.CertFile, "public — root CA certificate (offline)"},
		{opCfg.IntermediateCA.CertFile, "public — intermediate CA certificate"},
		{serverCfg.ChainFile, "public — server leaf + intermediate CA bundle"},
		{serverCfg.KeyFile, "private — never leaves the server machine"},
		{serverCfg.RootCertFile, "public — root CA copy, used to verify client chains"},
	}
	for _, entry := range entries {
		fmt.Printf("  %-60s  %s\n", entry.file, entry.note)
	}
	fmt.Printf("  %-60s  %s\n", "Windows CurrentUser\\My", "client cert + TPM-backed key (no file)")
	fmt.Println()

	// Cleanup
	fmt.Println("The demo can now remove the client certificate, intermediate CA copy, and NCrypt key container.")
	fmt.Println()
	fmt.Print("Run the cleanup script now? [y/N]: ")

	reader := bufio.NewReader(os.Stdin)
	answer, err := reader.ReadString('\n')
	if err != nil && len(answer) == 0 {
		return fmt.Errorf("reading cleanup response: %w", err)
	}

	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		fmt.Println()
		fmt.Println("[CLEANUP] Running scripts\\mtlsenterprisetpm-cleanup.ps1 ...")
		return pwsh.RunScriptFile(
			"scripts\\mtlsenterprisetpm-cleanup.ps1",
			"-Provider", state.provider,
			"-Container", clientCfg.Container,
			"-CN", clientCfg.CN,
			"-IntermediateCACN", opCfg.IntermediateCA.CN,
		)
	default:
		fmt.Println()
		fmt.Println("[CLEANUP] Skipped.")
		printCleanupInstructions(state.provider, clientCfg.Container, clientCfg.CN, opCfg.IntermediateCA.CN)
		return nil
	}
}

func printCleanupInstructions(provider, container, cn, intermediateCACN string) {
	fmt.Println("=== Manual Cleanup ===")
	fmt.Println("The client certificate and key were NOT removed automatically.")
	fmt.Println("You can inspect them in certmgr.msc:")
	fmt.Println("  CurrentUser → Personal → Certificates")
	fmt.Println("  CurrentUser → Intermediate Certification Authorities → Certificates")
	fmt.Println()
	fmt.Println("You can run the cleanup script:")
	fmt.Println()
	fmt.Printf("  pwsh scripts/mtlsenterprisetpm-cleanup.ps1 -Provider '%s' -Container '%s' -CN '%s' -IntermediateCACN '%s'\n", provider, container, cn, intermediateCACN)
	fmt.Println()
	fmt.Println("Or copy/paste the equivalent PowerShell commands:")
	fmt.Println()
	fmt.Println("  # 1. Remove the client certificate from CurrentUser\\My:")
	fmt.Println("  $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', 'CurrentUser')")
	fmt.Println("  $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)")
	fmt.Printf("  $store.Certificates | Where-Object { $_.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) -eq '%s' } | ForEach-Object { $store.Remove($_) }\n", cn)
	fmt.Println("  $store.Close()")
	fmt.Println()
	fmt.Println("  # 2. Remove the intermediate CA certificate from CurrentUser\\CA:")
	fmt.Println("  $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('CA', 'CurrentUser')")
	fmt.Println("  $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)")
	fmt.Printf("  $store.Certificates | Where-Object { $_.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) -eq '%s' } | ForEach-Object { $store.Remove($_) }\n", intermediateCACN)
	fmt.Println("  $store.Close()")
	fmt.Println()
	fmt.Println("  # 3. Delete the NCrypt key container from the provider:")
	fmt.Printf("  $p = New-Object System.Security.Cryptography.CngProvider('%s')\n", provider)
	fmt.Printf("  $k = [System.Security.Cryptography.CngKey]::Open('%s', $p)\n", container)
	fmt.Println("  $k.Delete()")
}
