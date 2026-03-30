// Package operator provides a "human operator" abstraction over the ca package.
// It orchestrates certificate authority creation, certificate issuance, and
// distribution of certificates and keys to the file system. All file I/O lives
// here; the ca package remains purely in-memory.
package operator

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
