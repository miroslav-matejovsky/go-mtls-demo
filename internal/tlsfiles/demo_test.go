package tlsfiles

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDemo(t *testing.T) {
	err := runDemo(t.TempDir())
	require.NoError(t, err)
}
