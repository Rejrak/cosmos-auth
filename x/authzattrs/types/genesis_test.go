package types_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"alpha/x/authzattrs/types"
)

func TestGenesisState(t *testing.T) {
	require.Equal(t, types.DefaultParams(), types.DefaultGenesis().Params)
	require.NoError(t, types.DefaultGenesis().Validate())
}
