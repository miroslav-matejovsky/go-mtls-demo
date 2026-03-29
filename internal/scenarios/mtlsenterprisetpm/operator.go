//go:build windows

package mtlsenterprisetpm

import (
	"github.com/miroslav-matejovsky/go-mtls-demo/internal/authority"
)

// Operator is the scenario-local alias for the shared enterprise authority.
type Operator = authority.Enterprise

// NewOperator adapts the scenario config to the shared authority package.
func NewOperator(cfg OperatorConfig) (*Operator, error) {
	rootValidity, err := cfg.RootCA.ParseValidity()
	if err != nil {
		return nil, err
	}
	intValidity, err := cfg.IntermediateCA.ParseValidity()
	if err != nil {
		return nil, err
	}
	return authority.NewEnterprise(authority.EnterpriseConfig{
		RootCA: authority.CAConfig{
			CN:       cfg.RootCA.CN,
			CertFile: cfg.RootCA.CertFile,
			Validity: rootValidity,
		},
		IntermediateCA: authority.CAConfig{
			CN:       cfg.IntermediateCA.CN,
			CertFile: cfg.IntermediateCA.CertFile,
			Validity: intValidity,
		},
	})
}
