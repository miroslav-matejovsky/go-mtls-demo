//go:build windows

package mtlsenterprisetpm

import (
	"fmt"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/kpi"
)

// step5SignClientCert signs a client certificate with the enterprise intermediate CA
// using the public key generated in the Windows cert store.
func step5SignClientCert(state *demoState, clientCfg ClientConfig) error {
	fmt.Println("=== Step 5/9: Sign client certificate with enterprise intermediate CA ===")
	fmt.Println("The intermediate CA issues a ClientAuth leaf cert for the TPM-backed public key.")
	fmt.Println()

	clientCert, err := state.operator.SignClientCertForKey(state.clientSigner.Public(), clientCfg.CN)
	if err != nil {
		return fmt.Errorf("error signing client certificate: %w", err)
	}
	state.clientCert = clientCert

	fmt.Println("[OPERATOR] Client certificate:")
	kpi.PrintCertificateInfo(clientCert)
	fmt.Printf("  [CLIENT] EKU    : ClientAuth only\n")
	fmt.Printf("  [CLIENT] Issuer : %s (intermediate CA)\n", clientCert.Issuer.CommonName)
	fmt.Println("  [CLIENT] Private key lives inside the provider — no .key file is written.")
	fmt.Println()
	return nil
}
