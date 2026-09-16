package keeper_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"alpha/x/authzattrs/types"
)

func TestGenesisInitExport(t *testing.T) {
	f := initFixture(t)
	want := *types.DefaultGenesis()
	want.Authorizations = []types.AuthorizationRecord{record()}
	require.NoError(t, f.keeper.InitGenesis(f.ctx, want))
	got, err := f.keeper.ExportGenesis(f.ctx)
	require.NoError(t, err)
	require.Equal(t, &want, got)
}
