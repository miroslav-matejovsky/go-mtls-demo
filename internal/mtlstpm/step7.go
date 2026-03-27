//go:build windows

package mtlstpm

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/pwsh"
)

// step7Cleanup prompts for cleanup and optionally runs the TPM cleanup script as the final demo step.
func step7Cleanup(provider, container, cn, caCN string) error {
	fmt.Println("=== Step 7/7: Cleanup ===")
	fmt.Println("The demo can now remove the client certificate, CA copy, and NCrypt key container.")
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
		fmt.Println("[CLEANUP] Running scripts\\mtlstpm-cleanup.ps1 ...")
		return pwsh.RunScriptFile(
			"scripts\\mtlstpm-cleanup.ps1",
			"-Provider", provider,
			"-Container", container,
			"-CN", cn,
			"-CACN", caCN,
		)
	default:
		fmt.Println()
		fmt.Println("[CLEANUP] Skipped.")
		printCleanupInstructions(provider, container, cn, caCN)
		return nil
	}
}

func printCleanupInstructions(provider, container, cn, caCN string) {
	fmt.Println("=== Manual Cleanup ===")
	fmt.Println("The client certificate and key were NOT removed automatically.")
	fmt.Println("You can inspect them in certmgr.msc:")
	fmt.Println("  CurrentUser → Personal → Certificates")
	fmt.Println("  CurrentUser → Intermediate Certification Authorities → Certificates")
	fmt.Println()
	fmt.Println("You can run the cleanup script:")
	fmt.Println()
	fmt.Printf("  pwsh scripts/mtlstpm-cleanup.ps1 -Provider '%s' -Container '%s' -CN '%s' -CACN '%s'\n", provider, container, cn, caCN)
	fmt.Println()
	fmt.Println("Or copy/paste the equivalent PowerShell commands:")
	fmt.Println()
	fmt.Println("  # 1. Remove the client certificate from CurrentUser\\My:")
	fmt.Println("  $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', 'CurrentUser')")
	fmt.Println("  $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)")
	fmt.Printf("  $store.Certificates | Where-Object { $_.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) -eq '%s' } | ForEach-Object { $store.Remove($_) }\n", cn)
	fmt.Println("  $store.Close()")
	fmt.Println()
	fmt.Println("  # 2. Remove the CA certificate from CurrentUser\\CA:")
	fmt.Println("  $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('CA', 'CurrentUser')")
	fmt.Println("  $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)")
	fmt.Printf("  $store.Certificates | Where-Object { $_.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) -eq '%s' } | ForEach-Object { $store.Remove($_) }\n", caCN)
	fmt.Println("  $store.Close()")
	fmt.Println()
	fmt.Println("  # 3. Delete the NCrypt key container from the provider:")
	fmt.Printf("  $p = New-Object System.Security.Cryptography.CngProvider('%s')\n", provider)
	fmt.Printf("  $k = [System.Security.Cryptography.CngKey]::Open('%s', $p)\n", container)
	fmt.Println("  $k.Delete()")
}
