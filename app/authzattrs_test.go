package app

import (
	"bytes"
	"testing"

	"cosmossdk.io/log"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/client/flags"
	simtestutil "github.com/cosmos/cosmos-sdk/testutil/sims"
	sdk "github.com/cosmos/cosmos-sdk/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	authzattrskeeper "alpha/x/authzattrs/keeper"
	authzattrstypes "alpha/x/authzattrs/types"
)

type authzAttrsTestTx struct{ msgs []sdk.Msg }

func (tx authzAttrsTestTx) GetMsgs() []sdk.Msg               { return tx.msgs }
func (authzAttrsTestTx) GetMsgsV2() ([]proto.Message, error) { return nil, nil }

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

func TestAuthzAttrsAnteEnforcementMounted(t *testing.T) {
	db := dbm.NewMemDB()
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	appOptions := make(simtestutil.AppOptionsMap)
	appOptions[flags.FlagHome] = t.TempDir()
	application := New(log.NewNopLogger(), db, nil, true, appOptions)

	from := sdk.AccAddress(bytes.Repeat([]byte{1}, 20)).String()
	to := sdk.AccAddress(bytes.Repeat([]byte{2}, 20)).String()
	tx := authzAttrsTestTx{msgs: []sdk.Msg{&banktypes.MsgSend{
		FromAddress: from,
		ToAddress:   to,
		Amount:      sdk.NewCoins(sdk.NewInt64Coin("stake", 1)),
	}}}
	ctx := application.NewUncachedContext(false, cmtproto.Header{Height: 1})
	_, err := application.AnteHandler()(ctx, tx, false)
	require.ErrorContains(t, err, authzattrstypes.ReasonNotFound)
}
