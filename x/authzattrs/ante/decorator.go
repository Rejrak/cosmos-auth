package ante

import (
	"strconv"

	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"

	"alpha/x/authzattrs/keeper"
	"alpha/x/authzattrs/types"
)

type AuthzDecorator struct {
	keeper keeper.Keeper
}

func NewAuthzDecorator(k keeper.Keeper) AuthzDecorator {
	return AuthzDecorator{keeper: k}
}

func (d AuthzDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (sdk.Context, error) {
	for _, msg := range tx.GetMsgs() {
		msgSend, ok := msg.(*banktypes.MsgSend)
		if !ok {
			continue
		}
		decision, record, err := d.keeper.AuthorizeMsgSend(ctx, ctx.BlockHeight(), msgSend)
		if err != nil {
			return ctx, err
		}
		emitDecision(ctx, msgSend.FromAddress, record, decision)
		if !decision.Allowed {
			return ctx, errorsmod.Wrap(sdkerrors.ErrUnauthorized, decision.ReasonCode)
		}
	}
	return next(ctx, tx, simulate)
}

func emitDecision(ctx sdk.Context, subject string, record *types.AuthorizationRecord, decision types.Decision) {
	policyID, policyVersion, authorizationID := "", "", ""
	if record != nil {
		policyID = record.PolicyId
		policyVersion = strconv.FormatUint(record.PolicyVersion, 10)
		authorizationID = record.AuthorizationId
	}
	outcome := "DENY"
	if decision.Allowed {
		outcome = "ALLOW"
	}
	ctx.EventManager().EmitEvent(sdk.NewEvent(
		"authz_decision",
		sdk.NewAttribute("subject", subject),
		sdk.NewAttribute("msg_type", types.MsgSendTypeURL),
		sdk.NewAttribute("policy_id", policyID),
		sdk.NewAttribute("policy_version", policyVersion),
		sdk.NewAttribute("authorization_id", authorizationID),
		sdk.NewAttribute("outcome", outcome),
		sdk.NewAttribute("reason_code", decision.ReasonCode),
		sdk.NewAttribute("height", strconv.FormatInt(ctx.BlockHeight(), 10)),
	))
}
