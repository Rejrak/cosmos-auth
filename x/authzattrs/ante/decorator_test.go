package ante_test

import (
	"bytes"
	"testing"

	storetypes "cosmossdk.io/store/types"
	addresscodec "github.com/cosmos/cosmos-sdk/codec/address"
	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/testutil"
	sdk "github.com/cosmos/cosmos-sdk/types"
	moduletestutil "github.com/cosmos/cosmos-sdk/types/module/testutil"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"alpha/x/authzattrs/ante"
	"alpha/x/authzattrs/keeper"
	module "alpha/x/authzattrs/module"
	"alpha/x/authzattrs/types"
)

type testTx struct{ msgs []sdk.Msg }

func (tx testTx) GetMsgs() []sdk.Msg               { return tx.msgs }
func (testTx) GetMsgsV2() ([]proto.Message, error) { return nil, nil }

func TestAnteUsesCommittedStateWithoutMiddleware(t *testing.T) {
	encCfg := moduletestutil.MakeTestEncodingConfig(module.AppModule{})
	addressCodec := addresscodec.NewBech32Codec(sdk.GetConfig().GetBech32AccountAddrPrefix())
	storeKey := storetypes.NewKVStoreKey(types.StoreKey)
	ctx := testutil.DefaultContextWithDB(t, storeKey, storetypes.NewTransientStoreKey("transient_test")).Ctx.WithBlockHeight(10)
	k := keeper.NewKeeper(runtime.NewKVStoreService(storeKey), encCfg.Codec, addressCodec, authtypes.NewModuleAddress(types.GovModuleName))

	from := sdk.AccAddress(bytes.Repeat([]byte{1}, 20)).String()
	to := sdk.AccAddress(bytes.Repeat([]byte{2}, 20)).String()
	record := types.AuthorizationRecord{
		AuthorizationId:  "auth-1",
		Subject:          from,
		MsgTypeUrl:       types.MsgSendTypeURL,
		PolicyId:         "policy-1",
		PolicyVersion:    1,
		IssuerSetId:      1,
		ValidFromHeight:  10,
		ValidUntilHeight: 10,
		BankSendConstraints: types.BankSendConstraints{
			Denom:     "stake",
			Receiver:  to,
			MaxAmount: "10",
		},
	}
	require.NoError(t, k.SetAuthorization(ctx, record))

	decorator := ante.NewAuthzDecorator(k)
	nextCalled := false
	next := func(nextCtx sdk.Context, _ sdk.Tx, _ bool) (sdk.Context, error) {
		nextCalled = true
		return nextCtx, nil
	}

	allowedTx := testTx{msgs: []sdk.Msg{&banktypes.MsgSend{FromAddress: from, ToAddress: to, Amount: sdk.NewCoins(sdk.NewInt64Coin("stake", 10))}}}
	resultCtx, err := decorator.AnteHandle(ctx, allowedTx, false, next)
	require.NoError(t, err)
	require.True(t, nextCalled)
	require.Equal(t, types.ReasonOK, resultCtx.EventManager().Events()[0].Attributes[6].Value)

	nextCalled = false
	deniedTx := testTx{msgs: []sdk.Msg{&banktypes.MsgSend{FromAddress: from, ToAddress: to, Amount: sdk.NewCoins(sdk.NewInt64Coin("stake", 11))}}}
	_, err = decorator.AnteHandle(ctx.WithEventManager(sdk.NewEventManager()), deniedTx, false, next)
	require.ErrorContains(t, err, types.ReasonAmountExceeded)
	require.False(t, nextCalled)
}
