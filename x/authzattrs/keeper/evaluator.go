package keeper

import (
	"context"

	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"

	"alpha/x/authzattrs/types"
)

func EvaluateMsgSend(height int64, record *types.AuthorizationRecord, msg *banktypes.MsgSend) types.Decision {
	if !isSupportedMsgSend(msg) {
		return deny(types.ReasonUnsupportedMsgShape)
	}
	if record == nil {
		return deny(types.ReasonNotFound)
	}
	if err := record.Validate(); err != nil || record.Subject != msg.FromAddress || record.MsgTypeUrl != types.MsgSendTypeURL {
		return deny(types.ReasonInvalidRecord)
	}
	if record.Revoked {
		return deny(types.ReasonRevoked)
	}
	if height < record.ValidFromHeight {
		return deny(types.ReasonNotYetValid)
	}
	if height > record.ValidUntilHeight {
		return deny(types.ReasonExpired)
	}
	if record.BankSendConstraints.Receiver != msg.ToAddress {
		return deny(types.ReasonReceiverMismatch)
	}
	coin := msg.Amount[0]
	if record.BankSendConstraints.Denom != coin.Denom {
		return deny(types.ReasonDenomMismatch)
	}
	maxAmount, ok := types.ParseCanonicalAmount(record.BankSendConstraints.MaxAmount)
	if !ok {
		return deny(types.ReasonInvalidRecord)
	}
	if coin.Amount.GT(maxAmount) {
		return deny(types.ReasonAmountExceeded)
	}
	return types.Decision{Allowed: true, ReasonCode: types.ReasonOK}
}

func (k Keeper) AuthorizeMsgSend(ctx context.Context, height int64, msg *banktypes.MsgSend) (types.Decision, *types.AuthorizationRecord, error) {
	if !isSupportedMsgSend(msg) {
		return deny(types.ReasonUnsupportedMsgShape), nil, nil
	}
	record, found, err := k.GetAuthorization(ctx, msg.FromAddress, types.MsgSendTypeURL)
	if err != nil {
		return types.Decision{}, nil, err
	}
	if !found {
		return deny(types.ReasonNotFound), nil, nil
	}
	return EvaluateMsgSend(height, &record, msg), &record, nil
}

func deny(reason string) types.Decision {
	return types.Decision{ReasonCode: reason}
}

func isSupportedMsgSend(msg *banktypes.MsgSend) bool {
	return msg != nil && len(msg.Amount) == 1 && !msg.Amount[0].Amount.IsNil() && msg.Amount[0].Amount.IsPositive()
}
