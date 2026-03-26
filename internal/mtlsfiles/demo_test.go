package mtlsfiles

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDemo(t *testing.T) {
	base := t.TempDir()
	cfg := Config{
		CA: CAConfig{
			CN:       "go mTLS Demo CA",
			CertFile: filepath.Join(base, "ca", "cert.crt"),
			Validity: "24h",
		},
		Server: ServerConfig{
			Address:    "127.0.0.1:0",
			CN:         "go mTLS Demo Server",
			CertFile:   filepath.Join(base, "server", "server.crt"),
			KeyFile:    filepath.Join(base, "server", "server.key"),
			CACertFile: filepath.Join(base, "server", "ca.crt"),
		},
		Client: ClientConfig{
			CN:         "go mTLS Demo Client",
			CertFile:   filepath.Join(base, "client", "client.crt"),
			KeyFile:    filepath.Join(base, "client", "client.key"),
			CACertFile: filepath.Join(base, "client", "ca.crt"),
		},
		Untrusted: UntrustedConfig{
			CACN:       "go mTLS Untrusted CA",
			CN:         "go mTLS Untrusted Client",
			CertFile:   filepath.Join(base, "untrusted", "client.crt"),
			KeyFile:    filepath.Join(base, "untrusted", "client.key"),
			CACertFile: filepath.Join(base, "untrusted", "ca.crt"),
		},
	}
	require.NoError(t, runDemo(cfg))
}
