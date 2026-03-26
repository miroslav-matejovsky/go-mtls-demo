package tlsfiles

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDemo(t *testing.T) {
	base := t.TempDir()
	cfg := Config{
		CA: CAConfig{
			CN:       "go TLS Demo CA",
			CertFile: filepath.Join(base, "ca", "cert.crt"),
			Validity: "24h",
		},
		Server: ServerConfig{
			Address:  "127.0.0.1:0",
			CN:       "go TLS Demo Server",
			CertFile: filepath.Join(base, "server", "server.crt"),
			KeyFile:  filepath.Join(base, "server", "server.key"),
		},
		Client: ClientConfig{
			CACertFile: filepath.Join(base, "client", "ca.crt"),
		},
	}
	require.NoError(t, runDemo(cfg))
}
