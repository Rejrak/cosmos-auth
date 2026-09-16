package types_test

import (
	"bytes"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	"alpha/x/authzattrs/types"
)

func testAddress(value byte) string {
	return sdk.AccAddress(bytes.Repeat([]byte{value}, 20)).String()
}

func validAuthorization() types.AuthorizationRecord {
	return types.AuthorizationRecord{
		AuthorizationId:  "auth-1",
		Subject:          testAddress(1),
		MsgTypeUrl:       types.MsgSendTypeURL,
		PolicyId:         "policy-1",
		PolicyVersion:    1,
		IssuerSetId:      1,
		ValidFromHeight:  10,
		ValidUntilHeight: 20,
		BankSendConstraints: types.BankSendConstraints{
			Denom:     "stake",
			Receiver:  testAddress(2),
			MaxAmount: "100",
		},
	}
}

func TestAuthorizationRecordValidate(t *testing.T) {
	require.NoError(t, validAuthorization().Validate())

	tests := map[string]func(*types.AuthorizationRecord){
		"authorization id": func(r *types.AuthorizationRecord) { r.AuthorizationId = "" },
		"subject":          func(r *types.AuthorizationRecord) { r.Subject = "" },
		"message type":     func(r *types.AuthorizationRecord) { r.MsgTypeUrl = "/other.Msg" },
		"policy id":        func(r *types.AuthorizationRecord) { r.PolicyId = "" },
		"policy version":   func(r *types.AuthorizationRecord) { r.PolicyVersion = 0 },
		"issuer set":       func(r *types.AuthorizationRecord) { r.IssuerSetId = 0 },
		"from height":      func(r *types.AuthorizationRecord) { r.ValidFromHeight = 0 },
		"height range":     func(r *types.AuthorizationRecord) { r.ValidUntilHeight = 9 },
		"denom":            func(r *types.AuthorizationRecord) { r.BankSendConstraints.Denom = "bad denom" },
		"receiver":         func(r *types.AuthorizationRecord) { r.BankSendConstraints.Receiver = "" },
		"max amount":       func(r *types.AuthorizationRecord) { r.BankSendConstraints.MaxAmount = "01" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			record := validAuthorization()
			mutate(&record)
			require.Error(t, record.Validate())
		})
	}
}

func TestParseCanonicalAmount(t *testing.T) {
	for _, value := range []string{"1", "100", "999999999999999999999999999999"} {
		_, ok := types.ParseCanonicalAmount(value)
		require.True(t, ok, value)
	}
	for _, value := range []string{"", "0", "01", "+1", "-1", "1.0", "1e3"} {
		_, ok := types.ParseCanonicalAmount(value)
		require.False(t, ok, value)
	}
}
