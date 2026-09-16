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

func TestGenesisRejectsDuplicateLogicalKey(t *testing.T) {
	record := validAuthorization()
	replacement := record
	replacement.AuthorizationId = "auth-2"
	genesis := types.GenesisState{
		Params:         types.DefaultParams(),
		Authorizations: []types.AuthorizationRecord{record, replacement},
	}
	require.Error(t, genesis.Validate())
}
