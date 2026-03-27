//go:build windows

package mtlstpm

import (
	"fmt"
	"strings"

	"github.com/google/certtostore"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/pwsh"
)

// step4ImportClientCertificate stores the signed certificate, inspects the cert store entry, and re-derives the key for runtime use.
func step4ImportClientCertificate(state *demoState, clientCfg ClientConfig) error {
	fmt.Println("=== Step 4/6: Import client certificate into Windows Certificate Store ===")
	fmt.Printf("Linking signed certificate to key container %q in CurrentUser\\My.\n", clientCfg.Container)
	fmt.Println()

	if err := state.store.StoreWithDisposition(state.clientCert, state.operator.CACert(), certStoreAddReplaceExisting); err != nil {
		return fmt.Errorf("error storing client certificate: %w", err)
	}
	fmt.Printf("  [CLIENT] Certificate stored in CurrentUser\\My\n")

	if storeInfo, err := pwsh.ShowCertsInStore(clientCfg.CN); err != nil {
		fmt.Printf("  [CLIENT] Warning: could not query cert store — %v\n", err)
	} else if storeInfo != "" {
		fmt.Println("  [CLIENT] Cert store entry:")
		for _, line := range strings.Split(storeInfo, "\n") {
			fmt.Printf("    %s\n", line)
		}
	}
	fmt.Println()

	// Simulate runtime lookup: open the cert by issuer, then derive its key
	// from the CertContext. This is what a real application does on startup —
	// it has no signer in memory, it must re-derive it from the store.
	fmt.Println("  [CLIENT] Simulating runtime key lookup (re-deriving key from CertContext) ...")
	storedCert, ctx, _, err := state.store.CertByCommonName(clientCfg.CN)
	if err != nil {
		return fmt.Errorf("error looking up cert from store by CN: %w", err)
	}
	defer certtostore.FreeCertContext(ctx)

	storeKey, err := state.store.CertKey(ctx)
	if err != nil {
		return fmt.Errorf("error deriving key from cert context: %w", err)
	}

	state.storedClientCert = storedCert
	state.storeKey = storeKey

	fmt.Println("  [CLIENT] Key successfully retrieved via CertKey — ready for TLS.")
	fmt.Println()
	return nil
}
