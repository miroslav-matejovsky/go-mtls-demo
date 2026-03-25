package tls

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTlsDemo(t *testing.T) {
	err := RunDemoTLS()
	require.NoError(t, err)
}
