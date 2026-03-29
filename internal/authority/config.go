// Package authority provides shared certificate-authority helpers for the demo
// scenarios. It owns CA hierarchy creation, certificate issuance, and CA/chain
// distribution logic while leaving scenario orchestration to the scenario
// packages.
package authority

import (
	"fmt"
	"time"
)

// CAConfig describes a certificate authority that should be created and whose
// public certificate should be written to CertFile.
type CAConfig struct {
	CN       string
	CertFile string
	Validity time.Duration
}

// EnterpriseConfig describes a two-tier PKI consisting of a root CA and an
// operational intermediate CA.
type EnterpriseConfig struct {
	RootCA         CAConfig
	IntermediateCA CAConfig
}

func validateCAConfig(role string, cfg CAConfig) error {
	if cfg.CN == "" {
		return fmt.Errorf("creating %s: common name is required", role)
	}
	if cfg.CertFile == "" {
		return fmt.Errorf("creating %s: certificate file is required", role)
	}
	if cfg.Validity <= 0 {
		return fmt.Errorf("creating %s: validity must be greater than zero", role)
	}
	return nil
}
