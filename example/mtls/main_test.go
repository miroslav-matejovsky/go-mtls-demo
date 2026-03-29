package main

import (
	"path/filepath"
	"testing"

	"github.com/miroslav-matejovsky/go-mtls-demo/example/mtls/operator"
	"github.com/stretchr/testify/require"
)

func TestDemo(t *testing.T) {
	base := t.TempDir()
	opCfg := operator.OperatorConfig{
		RootCA: operator.RootCAConfig{
			CN:       "Test Root CA",
			CertFile: filepath.Join(base, "root-ca", "cert.crt"),
			Validity: "24h",
		},
		IntermediateCA: operator.IntermediateCAConfig{
			CN:       "Test Intermediate CA",
			CertFile: filepath.Join(base, "intermediate-ca", "cert.crt"),
			Validity: "24h",
		},
	}
	serverCfg := operator.ServerConfig{
		Address:      "127.0.0.1:0",
		CN:           "Test Server",
		ChainFile:    filepath.Join(base, "server", "chain.crt"),
		KeyFile:      filepath.Join(base, "server", "server.key"),
		RootCertFile: filepath.Join(base, "server", "root-ca.crt"),
		DNSNames:     []string{"localhost"},
	}
	clientCfg := operator.ClientConfig{
		CN:           "Test Client",
		ChainFile:    filepath.Join(base, "client", "chain.crt"),
		KeyFile:      filepath.Join(base, "client", "client.key"),
		RootCertFile: filepath.Join(base, "client", "root-ca.crt"),
	}
	untrustedCfg := operator.UntrustedClientConfig{
		RootCACN:         "Untrusted Root CA",
		IntermediateCACN: "Untrusted Intermediate CA",
		CN:               "Untrusted Client",
		ChainFile:        filepath.Join(base, "untrusted", "chain.crt"),
		KeyFile:          filepath.Join(base, "untrusted", "client.key"),
		RootCertFile:     filepath.Join(base, "untrusted", "root-ca.crt"),
	}
	require.NoError(t, runDemo(opCfg, serverCfg, clientCfg, untrustedCfg))
}
