//go:build windows

package mtlsenterprisetpm

import (
	"fmt"
	"strings"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/tpm"
)

// step6ImportClientCert stores the signed certificate in the Windows cert store,
// inspects the store entry, and re-derives the signer for runtime use.
func step6ImportClientCert(state *demoState, clientCfg ClientConfig) error {
	fmt.Println("=== Step 6/9: Import certificate into Windows Certificate Store ===")
	fmt.Printf("Linking signed certificate to key container %q in CurrentUser\\My.\n", clientCfg.Container)
	fmt.Println()

	// StoreWithDisposition: second arg is the CA cert (intermediate, the direct issuer)
	if err := state.store.StoreCertificate(state.clientCert, state.authority.Intermediate()); err != nil {
		return fmt.Errorf("error storing client certificate: %w", err)
	}
	fmt.Printf("  [CLIENT] Certificate stored in CurrentUser\\My\n")

	if storeInfo, err := tpm.ShowCertsInStore(clientCfg.CN); err != nil {
		fmt.Printf("  [CLIENT] Warning: could not query cert store — %v\n", err)
	} else if storeInfo != "" {
		fmt.Println("  [CLIENT] Cert store entry:")
		for _, line := range strings.Split(storeInfo, "\n") {
			fmt.Printf("    %s\n", line)
		}
	}
	fmt.Println()

	// Simulate runtime lookup: find cert by CN, then derive the signer from the CertContext.
	fmt.Println("  [CLIENT] Simulating runtime key lookup (re-deriving key from CertContext) ...")
	storedCert, storeKey, err := state.store.LoadCertificateByCommonName(clientCfg.CN)
	if err != nil {
		return fmt.Errorf("error looking up cert from store by CN: %w", err)
	}

	state.storedClientCert = storedCert
	state.storeKey = storeKey

	fmt.Println("  [CLIENT] Key successfully retrieved via CertKey — ready for TLS.")
	fmt.Println()
	return nil
}
