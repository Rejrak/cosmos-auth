package keeper_test

import (
	"context"
	"crypto/ed25519"
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

func TestIssuerSetStorageAndValidation(t *testing.T) {
	f := initFixture(t)
	valid := validIssuerSet()
	valid.Active = false
	require.NoError(t, f.keeper.SetIssuerSet(f.ctx, valid))

	got, found, err := f.keeper.GetIssuerSet(f.ctx, valid.IssuerSetId)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, valid, got)

	invalid := []types.IssuerSet{
		{PolicyId: valid.PolicyId, MsgTypeUrl: valid.MsgTypeUrl, ThresholdWeight: 1},
		{IssuerSetId: 1, MsgTypeUrl: valid.MsgTypeUrl, ThresholdWeight: 1},
		{IssuerSetId: 1, PolicyId: valid.PolicyId, MsgTypeUrl: "/unsupported", ThresholdWeight: 1},
		{IssuerSetId: 1, PolicyId: valid.PolicyId, MsgTypeUrl: valid.MsgTypeUrl},
	}
	for _, issuerSet := range invalid {
		require.Error(t, f.keeper.SetIssuerSet(f.ctx, issuerSet))
	}
}

func TestIssuerStorageAndValidation(t *testing.T) {
	f := initFixture(t)
	valid := validIssuer()
	valid.Active = false
	require.NoError(t, f.keeper.SetIssuer(f.ctx, valid))

	got, found, err := f.keeper.GetIssuer(f.ctx, valid.IssuerSetId, valid.IssuerId)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, valid, got)

	invalidKey := valid
	invalidKey.PublicKey = make([]byte, ed25519.PublicKeySize-1)
	require.Error(t, f.keeper.SetIssuer(f.ctx, invalidKey))

	invalidType := valid
	invalidType.KeyType = types.IssuerKeyType_ISSUER_KEY_TYPE_UNSPECIFIED
	require.Error(t, f.keeper.SetIssuer(f.ctx, invalidType))
}

func TestIssuerIdentityIsScopedByIssuerSet(t *testing.T) {
	f := initFixture(t)
	first := validIssuer()
	require.NoError(t, f.keeper.SetIssuer(f.ctx, first))

	replacement := first
	replacement.Weight = 2
	require.NoError(t, f.keeper.SetIssuer(f.ctx, replacement))

	secondSet := first
	secondSet.IssuerSetId = 2
	secondSet.Weight = 3
	require.NoError(t, f.keeper.SetIssuer(f.ctx, secondSet))

	gotFirst, found, err := f.keeper.GetIssuer(f.ctx, first.IssuerSetId, first.IssuerId)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, replacement, gotFirst)

	gotSecond, found, err := f.keeper.GetIssuer(f.ctx, secondSet.IssuerSetId, secondSet.IssuerId)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, secondSet, gotSecond)
}

func TestCurrentIssuerSetStorageAndValidation(t *testing.T) {
	f := initFixture(t)
	active := validIssuerSet()
	require.NoError(t, f.keeper.SetIssuerSet(f.ctx, active))
	require.NoError(t, f.keeper.SetCurrentIssuerSet(f.ctx, active.PolicyId, active.MsgTypeUrl, active.IssuerSetId))

	got, found, err := f.keeper.GetCurrentIssuerSet(f.ctx, active.PolicyId, active.MsgTypeUrl)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, active.IssuerSetId, got)

	_, found, err = f.keeper.GetCurrentIssuerSet(f.ctx, "missing-policy", types.MsgSendTypeURL)
	require.NoError(t, err)
	require.False(t, found)

	require.Error(t, f.keeper.SetCurrentIssuerSet(f.ctx, active.PolicyId, active.MsgTypeUrl, 999))

	inactive := active
	inactive.IssuerSetId = 2
	inactive.Active = false
	require.NoError(t, f.keeper.SetIssuerSet(f.ctx, inactive))
	require.Error(t, f.keeper.SetCurrentIssuerSet(f.ctx, inactive.PolicyId, inactive.MsgTypeUrl, inactive.IssuerSetId))

	require.Error(t, f.keeper.SetCurrentIssuerSet(f.ctx, "wrong-policy", active.MsgTypeUrl, active.IssuerSetId))
	require.Error(t, f.keeper.SetCurrentIssuerSet(f.ctx, active.PolicyId, "/unsupported", active.IssuerSetId))
}

func validIssuerSet() types.IssuerSet {
	return types.IssuerSet{
		IssuerSetId: 1, Active: true, PolicyId: "policy-bank-send",
		MsgTypeUrl: types.MsgSendTypeURL, ThresholdWeight: 1,
	}
}

func validIssuer() types.Issuer {
	return types.Issuer{
		IssuerSetId: 1, IssuerId: "issuer-a",
		KeyType:   types.IssuerKeyType_ISSUER_KEY_TYPE_ED25519,
		PublicKey: make([]byte, ed25519.PublicKeySize), Weight: 1, Active: true,
		ValidFromHeight: 1, ValidUntilHeight: 100,
	}
}
