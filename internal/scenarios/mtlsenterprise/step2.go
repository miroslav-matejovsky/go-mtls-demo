package mtlsenterprise

import (
	"bytes"
	"fmt"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/ca"
	"github.com/miroslav-matejovsky/go-mtls-demo/internal/operator"
)

// step2CreateIntermediateCA creates an intermediate CA CSR, has the root CA sign it,
// persists the intermediate certificate, and builds the leaf-issuing authority.
func step2CreateIntermediateCA(state *demoState, opCfg OperatorConfig) error {
	fmt.Println("=== Step 2/8: Create Intermediate CA (signed by Root via CSR) ===")
	fmt.Println("The intermediate CA generates a CSR. The root CA signs it applying CA policy (IsCA, MaxPathLen:0).")
	fmt.Println("CA policy extensions are NOT in the CSR — they are applied by the signer.")
	fmt.Println()

	intValidity, err := opCfg.IntermediateCA.ParseValidity()
	if err != nil {
		return err
	}

	intCSR, intKey, err := ca.CreateIntermediateCSR(opCfg.IntermediateCA.CN)
	if err != nil {
		return fmt.Errorf("error creating intermediate CA CSR: %w", err)
	}
	fmt.Printf("  [OPERATOR] Intermediate CA CSR created (Subject: %s)\n", intCSR.Subject.CommonName)

	intCert, err := state.rootAuthority.SignIntermediateCSR(intCSR, intValidity)
	if err != nil {
		return fmt.Errorf("error signing intermediate CA CSR: %w", err)
	}
	fmt.Printf("  [OPERATOR] Root CA signed intermediate CSR → issued intermediate CA certificate\n")

	if err := operator.WriteCert(opCfg.IntermediateCA.CertFile, intCert); err != nil {
		return fmt.Errorf("error writing intermediate CA certificate: %w", err)
	}

	issuer, err := ca.NewIssuer(state.rootAuthority.TrustAnchor(), intCert, intKey, intValidity)
	if err != nil {
		return fmt.Errorf("error creating leaf issuer: %w", err)
	}
	state.authority = issuer

	rootCert := state.rootAuthority.TrustAnchor()
	fmt.Println("[OPERATOR] Intermediate CA certificate:")
	ca.PrintCertificateInfo(intCert)
	fmt.Printf("  [OPERATOR] Intermediate CA cert → %s\n", opCfg.IntermediateCA.CertFile)
	fmt.Printf("  [OPERATOR] Intermediate CA key stays in memory — never written to disk.\n")
	fmt.Printf("  [OPERATOR] SKID/AKID linkage:\n")
	fmt.Printf("    Root SKID         : %X\n", rootCert.SubjectKeyId)
	fmt.Printf("    Intermediate AKID : %X\n", intCert.AuthorityKeyId)
	fmt.Printf("    Match             : %t\n", bytes.Equal(rootCert.SubjectKeyId, intCert.AuthorityKeyId))
	fmt.Println()
	return nil
}
