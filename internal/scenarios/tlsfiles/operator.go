package tlsfiles

import "github.com/miroslav-matejovsky/go-mtls-demo/internal/authority"

// Operator is the scenario-local alias for the shared single-tier certificate authority.
type Operator = authority.Simple

// NewOperator adapts the scenario config to the shared authority package.
func NewOperator(cfg OperatorConfig) (*Operator, error) {
	validity, err := cfg.ParseValidity()
	if err != nil {
		return nil, err
	}
	return authority.NewSimple(authority.CAConfig{
		CN:       cfg.CN,
		CertFile: cfg.CertFile,
		Validity: validity,
	})
}
