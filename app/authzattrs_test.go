package app

import (
	"testing"

	"cosmossdk.io/log"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/client/flags"
	simtestutil "github.com/cosmos/cosmos-sdk/testutil/sims"
	"github.com/stretchr/testify/require"

	authzattrskeeper "alpha/x/authzattrs/keeper"
	authzattrstypes "alpha/x/authzattrs/types"
)

func TestAuthzAttrsModuleMounted(t *testing.T) {
	db := dbm.NewMemDB()
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	appOptions := make(simtestutil.AppOptionsMap)
	appOptions[flags.FlagHome] = t.TempDir()

	application := New(log.NewNopLogger(), db, nil, true, appOptions)
	require.Contains(t, application.ModuleManager.Modules, authzattrstypes.ModuleName)
	require.NotNil(t, application.GetKey(authzattrstypes.StoreKey))
	require.NotEmpty(t, application.AuthzAttrsKeeper.GetAuthority())
	genesis := application.DefaultGenesis()
	require.Contains(t, genesis, authzattrstypes.ModuleName)

	ctx := application.NewUncachedContext(false, cmtproto.Header{Height: 1})
	require.NoError(t, application.AuthzAttrsKeeper.InitGenesis(ctx, *authzattrstypes.DefaultGenesis()))
	response, err := authzattrskeeper.NewQueryServerImpl(application.AuthzAttrsKeeper).Params(ctx, &authzattrstypes.QueryParamsRequest{})
	require.NoError(t, err)
	require.Equal(t, authzattrstypes.DefaultParams(), response.Params)
}
