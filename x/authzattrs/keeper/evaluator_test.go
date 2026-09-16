package keeper_test

import (
	"bytes"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/stretchr/testify/require"

	"alpha/x/authzattrs/keeper"
	"alpha/x/authzattrs/types"
)

func addrString(value byte) string {
	return sdk.AccAddress(bytes.Repeat([]byte{value}, 20)).String()
}

func record() types.AuthorizationRecord {
	return types.AuthorizationRecord{
		AuthorizationId:  "auth-1",
		Subject:          addrString(1),
		MsgTypeUrl:       types.MsgSendTypeURL,
		PolicyId:         "policy-1",
		PolicyVersion:    1,
		IssuerSetId:      1,
		ValidFromHeight:  10,
		ValidUntilHeight: 20,
		BankSendConstraints: types.BankSendConstraints{
			Denom:     "stake",
			Receiver:  addrString(2),
			MaxAmount: "100",
		},
	}
}

func msg(amount int64) *banktypes.MsgSend {
	return &banktypes.MsgSend{FromAddress: addrString(1), ToAddress: addrString(2), Amount: sdk.NewCoins(sdk.NewInt64Coin("stake", amount))}
}

func TestEvaluateMsgSend(t *testing.T) {
	tests := []struct {
		name   string
		height int64
		record func() *types.AuthorizationRecord
		msg    func() *banktypes.MsgSend
		reason string
		allow  bool
	}{
		{"amount below max", 15, func() *types.AuthorizationRecord { r := record(); return &r }, func() *banktypes.MsgSend { return msg(99) }, types.ReasonOK, true},
		{"amount equal max", 15, func() *types.AuthorizationRecord { r := record(); return &r }, func() *banktypes.MsgSend { return msg(100) }, types.ReasonOK, true},
		{"valid from inclusive", 10, func() *types.AuthorizationRecord { r := record(); return &r }, func() *banktypes.MsgSend { return msg(1) }, types.ReasonOK, true},
		{"valid until inclusive", 20, func() *types.AuthorizationRecord { r := record(); return &r }, func() *banktypes.MsgSend { return msg(1) }, types.ReasonOK, true},
		{"missing", 15, func() *types.AuthorizationRecord { return nil }, func() *banktypes.MsgSend { return msg(1) }, types.ReasonNotFound, false},
		{"revoked", 15, func() *types.AuthorizationRecord { r := record(); r.Revoked = true; return &r }, func() *banktypes.MsgSend { return msg(1) }, types.ReasonRevoked, false},
		{"not yet valid", 9, func() *types.AuthorizationRecord { r := record(); return &r }, func() *banktypes.MsgSend { return msg(1) }, types.ReasonNotYetValid, false},
		{"expired", 21, func() *types.AuthorizationRecord { r := record(); return &r }, func() *banktypes.MsgSend { return msg(1) }, types.ReasonExpired, false},
		{"receiver mismatch", 15, func() *types.AuthorizationRecord { r := record(); return &r }, func() *banktypes.MsgSend { m := msg(1); m.ToAddress = addrString(3); return m }, types.ReasonReceiverMismatch, false},
		{"denom mismatch", 15, func() *types.AuthorizationRecord { r := record(); return &r }, func() *banktypes.MsgSend {
			return &banktypes.MsgSend{FromAddress: addrString(1), ToAddress: addrString(2), Amount: sdk.NewCoins(sdk.NewInt64Coin("other", 1))}
		}, types.ReasonDenomMismatch, false},
		{"amount exceeded", 15, func() *types.AuthorizationRecord { r := record(); return &r }, func() *banktypes.MsgSend { return msg(101) }, types.ReasonAmountExceeded, false},
		{"multi coin", 15, func() *types.AuthorizationRecord { r := record(); return &r }, func() *banktypes.MsgSend {
			return &banktypes.MsgSend{FromAddress: addrString(1), ToAddress: addrString(2), Amount: sdk.NewCoins(sdk.NewInt64Coin("other", 1), sdk.NewInt64Coin("stake", 1))}
		}, types.ReasonUnsupportedMsgShape, false},
		{"non-positive coin", 15, func() *types.AuthorizationRecord { r := record(); return &r }, func() *banktypes.MsgSend {
			return &banktypes.MsgSend{FromAddress: addrString(1), ToAddress: addrString(2), Amount: sdk.Coins{sdk.NewInt64Coin("stake", 0)}}
		}, types.ReasonUnsupportedMsgShape, false},
		{"malformed record", 15, func() *types.AuthorizationRecord { r := record(); r.PolicyId = ""; return &r }, func() *banktypes.MsgSend { return msg(1) }, types.ReasonInvalidRecord, false},
		{"malformed max amount", 15, func() *types.AuthorizationRecord { r := record(); r.BankSendConstraints.MaxAmount = "01"; return &r }, func() *banktypes.MsgSend { return msg(1) }, types.ReasonInvalidRecord, false},
		{"invalid record precedes revoked", 15, func() *types.AuthorizationRecord { r := record(); r.PolicyId = ""; r.Revoked = true; return &r }, func() *banktypes.MsgSend { return msg(1) }, types.ReasonInvalidRecord, false},
		{"revoked precedes height", 9, func() *types.AuthorizationRecord { r := record(); r.Revoked = true; return &r }, func() *banktypes.MsgSend { return msg(1) }, types.ReasonRevoked, false},
		{"receiver precedes denom", 15, func() *types.AuthorizationRecord { r := record(); return &r }, func() *banktypes.MsgSend {
			return &banktypes.MsgSend{FromAddress: addrString(1), ToAddress: addrString(3), Amount: sdk.NewCoins(sdk.NewInt64Coin("other", 1))}
		}, types.ReasonReceiverMismatch, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			first := keeper.EvaluateMsgSend(test.height, test.record(), test.msg())
			second := keeper.EvaluateMsgSend(test.height, test.record(), test.msg())
			require.Equal(t, types.Decision{Allowed: test.allow, ReasonCode: test.reason}, first)
			require.Equal(t, first, second)
		})
	}
}

func TestCommittedAuthorizationWithoutMiddleware(t *testing.T) {
	f := initFixture(t)
	record := record()

	missingMsg := msg(1)
	missingMsg.FromAddress = addrString(3)
	missing, _, err := f.keeper.AuthorizeMsgSend(f.ctx, 15, missingMsg)
	require.NoError(t, err)
	require.Equal(t, types.ReasonNotFound, missing.ReasonCode)

	require.NoError(t, f.keeper.SetAuthorization(f.ctx, record))

	first, stored, err := f.keeper.AuthorizeMsgSend(f.ctx, 15, msg(100))
	require.NoError(t, err)
	require.Equal(t, types.ReasonOK, first.ReasonCode)
	require.True(t, first.Allowed)
	require.Equal(t, &record, stored)

	second, _, err := f.keeper.AuthorizeMsgSend(f.ctx, 15, msg(101))
	require.NoError(t, err)
	require.Equal(t, types.ReasonAmountExceeded, second.ReasonCode)
	require.False(t, second.Allowed)
}
