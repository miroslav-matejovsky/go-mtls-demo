//go:build windows

package mtlsenterprisetpm

import (
	"fmt"
	"strings"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/pwsh"
	"github.com/miroslav-matejovsky/go-mtls-demo/internal/tpm"
)

// step4GenerateClientKey checks TPM availability, opens the Windows cert store, and generates the client key.
func step4GenerateClientKey(state *demoState, clientCfg ClientConfig, opCfg OperatorConfig) error {
	fmt.Println("=== Step 4/9: Generate client key in Windows Certificate Store ===")
	fmt.Println("Querying the system's TPM via Get-Tpm. If available, the key will be TPM-bound.")
	fmt.Println()

	// Detect or override the KSP provider
	if clientCfg.Store.ProviderOverride != "" {
		state.provider = clientCfg.Store.ProviderOverride
		fmt.Printf("  [TPM] Provider override set in config: %s\n", state.provider)
		fmt.Println("  [TPM] Skipping TPM auto-detection.")
		fmt.Println()
	} else {
		tpmAvailable, tpmDetails, tpmErr := pwsh.CheckTPM()
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
	}

	// Open the Windows cert store — filter by intermediate CA CN (direct issuer)
	fmt.Printf("Opening CurrentUser\\My via provider=%q  container=%q\n", state.provider, clientCfg.Container)
	fmt.Println("Generating an ECDSA P-256 key pair. The private key is created by the provider.")
	fmt.Println("certtostore returns a crypto.Signer — operations use the provider, raw bytes stay inside.")
	fmt.Println()

	store, err := tpm.OpenCurrentUserStore(tpm.OpenCurrentUserStoreOptions{
		Provider:          state.provider,
		Container:         clientCfg.Container,
		IssuerCommonNames: []string{opCfg.IntermediateCA.CN},
	})
	if err != nil {
		return fmt.Errorf("error opening Windows cert store: %w", err)
	}

	signer, err := store.GenerateECDSAP256()
	if err != nil {
		store.Close()
		return fmt.Errorf("error generating key in Windows cert store: %w", err)
	}

	state.store = store
	state.clientSigner = signer

	fmt.Printf("  [CLIENT] Key generated — algorithm: ECDSA P-256, provider: %s\n", state.provider)
	fmt.Println("  [CLIENT] Private key lives inside the provider — no .key file is written.")
	fmt.Println()
	return nil
}
