package mtls

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDemo(t *testing.T) {
	err := RunDemo()
	require.NoError(t, err)
}
