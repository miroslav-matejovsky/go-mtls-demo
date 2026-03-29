//go:build windows

package mtlstpm

import (
	"fmt"
	"strings"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/tpm"
)

// step2CheckTPM detects whether a TPM-backed provider can be used or whether the demo should fall back to software storage.
func step2CheckTPM(state *demoState, clientCfg ClientConfig) error {
	fmt.Println("=== Step 2/7: Check TPM availability ===")
	fmt.Println("Querying the system's Trusted Platform Module (TPM) via native Windows APIs.")
	fmt.Println("If available, the client private key will be generated inside the TPM and never exported.")
	fmt.Println()

	if clientCfg.Store.ProviderOverride != "" {
		state.provider = clientCfg.Store.ProviderOverride
		fmt.Printf("  [TPM] Provider override set in config: %s\n", state.provider)
		fmt.Println("  [TPM] Skipping TPM auto-detection.")
		fmt.Println()
		return nil
	}

	tpmAvailable, tpmDetails, tpmErr := tpm.CheckTPM()
	if tpmErr != nil {
		fmt.Printf("  [TPM] Warning: could not query TPM — %v\n", tpmErr)
		fmt.Println("  [TPM] Falling back to Microsoft Software Key Storage Provider.")
		tpmAvailable = false
	} else {
		for _, line := range strings.Split(tpmDetails, "\n") {
			fmt.Printf("  %s\n", line)
		}
	}

	if tpmAvailable {
		state.provider = tpm.SelectProvider("", true)
		fmt.Println("  [TPM] TPM 2.0 present and enabled.")
		fmt.Printf("  [TPM] Provider selected: %s\n", state.provider)
		fmt.Println("  [TPM] The private key will be bound to this machine's TPM — it cannot be exported.")
	} else {
		state.provider = tpm.SelectProvider("", false)
		fmt.Println("  [TPM] TPM not available or not ready.")
		fmt.Printf("  [TPM] Provider selected: %s\n", state.provider)
		fmt.Println("  [TPM] The private key will be stored in NCrypt software key storage.")
	}
	fmt.Println()
	return nil
}
