//go:build windows

package mtlstpm

import (
	"fmt"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/kpi"
	"github.com/miroslav-matejovsky/go-mtls-demo/internal/tpm"
)

// step3GenerateClientKey opens the Windows certificate store, generates the provider-backed key, and gets a signed client certificate.
func step3GenerateClientKey(state *demoState, opCfg OperatorConfig, clientCfg ClientConfig) error {
	fmt.Println("=== Step 3/7: Generate client key in Windows Certificate Store ===")
	fmt.Printf("Opening CurrentUser\\My via provider=%q  container=%q\n", state.provider, clientCfg.Container)
	fmt.Println("Generating an ECDSA P-256 key pair. The private key is created by the provider.")
	fmt.Println("certtostore returns a crypto.Signer — operations use the provider, raw bytes stay inside.")
	fmt.Println()

	store, err := tpm.OpenCurrentUserStore(tpm.OpenCurrentUserStoreOptions{
		Provider:          state.provider,
		Container:         clientCfg.Container,
		IssuerCommonNames: []string{opCfg.CN},
	})
	if err != nil {
		return fmt.Errorf("error opening Windows cert store: %w", err)
	}

	signer, err := store.GenerateECDSAP256()
	if err != nil {
		store.Close()
		return fmt.Errorf("error generating key in Windows cert store: %w", err)
	}

	clientCert, err := state.operator.SignCertForKey(signer.Public(), clientCfg.CN)
	if err != nil {
		store.Close()
		return fmt.Errorf("error signing client certificate: %w", err)
	}

	state.store = store
	state.clientCert = clientCert

	fmt.Printf("  [CLIENT] Key generated — algorithm: ECDSA P-256, provider: %s\n", state.provider)
	kpi.PrintCertificateInfo(clientCert)
	fmt.Println("  [CLIENT] Private key lives inside the provider — no .key file is written.")
	fmt.Println()
	return nil
}
