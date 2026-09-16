package keeper_test

import (
	"context"
	"testing"

	"cosmossdk.io/core/address"
	storetypes "cosmossdk.io/store/types"
	addresscodec "github.com/cosmos/cosmos-sdk/codec/address"
	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/testutil"
	sdk "github.com/cosmos/cosmos-sdk/types"
	moduletestutil "github.com/cosmos/cosmos-sdk/types/module/testutil"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/stretchr/testify/require"

	"alpha/x/authzattrs/keeper"
	module "alpha/x/authzattrs/module"
	"alpha/x/authzattrs/types"
)

type fixture struct {
	ctx          context.Context
	keeper       keeper.Keeper
	addressCodec address.Codec
}

func initFixture(t *testing.T) *fixture {
	t.Helper()
	encCfg := moduletestutil.MakeTestEncodingConfig(module.AppModule{})
	addressCodec := addresscodec.NewBech32Codec(sdk.GetConfig().GetBech32AccountAddrPrefix())
	storeKey := storetypes.NewKVStoreKey(types.StoreKey)
	storeService := runtime.NewKVStoreService(storeKey)
	ctx := testutil.DefaultContextWithDB(t, storeKey, storetypes.NewTransientStoreKey("transient_test")).Ctx
	k := keeper.NewKeeper(storeService, encCfg.Codec, addressCodec, authtypes.NewModuleAddress(types.GovModuleName))
	return &fixture{ctx: ctx, keeper: k, addressCodec: addressCodec}
}

func TestKeeperInitialization(t *testing.T) {
	f := initFixture(t)
	require.NoError(t, f.keeper.Params.Set(f.ctx, types.DefaultParams()))
	params, err := f.keeper.Params.Get(f.ctx)
	require.NoError(t, err)
	require.Equal(t, types.DefaultParams(), params)
}

func TestAuthorizationStorageUsesLogicalKey(t *testing.T) {
	f := initFixture(t)
	first := record()
	require.NoError(t, f.keeper.SetAuthorization(f.ctx, first))

	found, err := f.keeper.HasAuthorization(f.ctx, first.Subject, first.MsgTypeUrl)
	require.NoError(t, err)
	require.True(t, found)

	got, found, err := f.keeper.GetAuthorization(f.ctx, first.Subject, first.MsgTypeUrl)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, first, got)

	replacement := first
	replacement.AuthorizationId = "auth-2"
	require.NoError(t, f.keeper.SetAuthorization(f.ctx, replacement))
	got, found, err = f.keeper.GetAuthorization(f.ctx, first.Subject, first.MsgTypeUrl)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, replacement, got)

	revoked := replacement
	revoked.Revoked = true
	require.NoError(t, f.keeper.SetAuthorization(f.ctx, revoked))
	got, found, err = f.keeper.GetAuthorization(f.ctx, first.Subject, first.MsgTypeUrl)
	require.NoError(t, err)
	require.True(t, found)
	require.True(t, got.Revoked)

	_, found, err = f.keeper.GetAuthorization(f.ctx, addrString(3), first.MsgTypeUrl)
	require.NoError(t, err)
	require.False(t, found)
}
