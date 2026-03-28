package mtlsenterprise

import (
	"bytes"
	"fmt"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/cert"
)

// step2CreateIntermediateCA prints the intermediate CA info and shows SKID/AKID linkage.
func step2CreateIntermediateCA(state *demoState) error {
	fmt.Println("=== Step 2/8: Create Intermediate CA (signed by Root) ===")
	fmt.Println("The intermediate CA is the operational issuer. MaxPathLen: 0 prevents sub-intermediates.")
	fmt.Println()

	intCert := state.operator.IntermediateCert()
	rootCert := state.operator.RootCert()

	fmt.Println("[OPERATOR] Intermediate CA certificate:")
	cert.PrintCertificateInfo(intCert)

	fmt.Printf("  [OPERATOR] SKID/AKID linkage:\n")
	fmt.Printf("    Root SKID         : %X\n", rootCert.SubjectKeyId)
	fmt.Printf("    Intermediate AKID : %X\n", intCert.AuthorityKeyId)
	fmt.Printf("    Match             : %t\n", bytes.Equal(rootCert.SubjectKeyId, intCert.AuthorityKeyId))
	fmt.Println()
	return nil
}
