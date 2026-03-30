//go:build windows

package mtlsenterprisetpm

import (
	"bytes"
	"fmt"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/ca"
)

// step2CreateIntermediateCA prints the intermediate CA info and shows SKID/AKID linkage.
func step2CreateIntermediateCA(state *demoState) error {
	fmt.Println("=== Step 2/9: Create Intermediate CA (signed by Root) ===")
	fmt.Println("The intermediate CA is the operational issuer. MaxPathLen: 0 prevents sub-intermediates.")
	fmt.Println()

	intCert := state.operator.Intermediate()
	rootCert := state.operator.TrustAnchor()

	fmt.Println("[OPERATOR] Intermediate CA certificate:")
	ca.PrintCertificateInfo(intCert)

	fmt.Printf("  [OPERATOR] SKID/AKID linkage:\n")
	fmt.Printf("    Root SKID         : %X\n", rootCert.SubjectKeyId)
	fmt.Printf("    Intermediate AKID : %X\n", intCert.AuthorityKeyId)
	fmt.Printf("    Match             : %t\n", bytes.Equal(rootCert.SubjectKeyId, intCert.AuthorityKeyId))
	fmt.Println()
	return nil
}
