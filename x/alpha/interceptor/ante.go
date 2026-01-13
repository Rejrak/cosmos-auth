package interceptor

import (
	"fmt"
	"strconv"
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"
	authztypes "github.com/cosmos/cosmos-sdk/x/authz"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	ibctransfertypes "github.com/cosmos/ibc-go/v10/modules/apps/transfer/types"

	errorsmod "cosmossdk.io/errors"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

type AuthAnteDecorator struct {
	Enabled bool
	client  *Client
}

func NewAuthAnteDecorator(enabled bool) AuthAnteDecorator {
	var cl *Client
	if enabled {
		cl = NewClient("0.0.0.0:6000")
		cl.SetLogger(func(format string, args ...any) {
			fmt.Printf(format+"\n", args...)
		})
		cl.Start()
	}
	return AuthAnteDecorator{Enabled: enabled, client: cl}
}

func (d AuthAnteDecorator) AnteHandle(
	ctx sdk.Context,
	tx sdk.Tx,
	simulate bool,
	next sdk.AnteHandler,
) (sdk.Context, error) {
	if ctx.IsCheckTx() || ctx.IsReCheckTx() || simulate {
		return next(ctx, tx, simulate)
	}
	if !d.Enabled {
		return next(ctx, tx, simulate)
	}

	const authTimeout = 800 * time.Millisecond
	for _, m := range tx.GetMsgs() {
		msgInfo := ExtractMsgInfo(m)
		if msgInfo.Sender == "" {
			ctx.Logger().Info("auth-block: no sender, skipping",
				"op", sdk.MsgTypeURL(m),
				"height", ctx.BlockHeight(),
				"simulate", simulate,
			)
			continue
		}

		if isAuthRelevantMsg(m) {

			ctx.Logger().Info("auth-block: calling external auth",
				"op", sdk.MsgTypeURL(m),
				"sender", msgInfo.Sender,
				"height", ctx.BlockHeight(),
				"simulate", simulate,
			)
			sr := time.Now()
			ok, serverMsg, err := d.client.RequestAuth(msgInfo.Sender, sdk.MsgTypeURL(m), authTimeout)
			if err != nil {
				// block on error/timeout
				// return ctx, errorsmod.Wrapf(sdkerrors.ErrUnauthorized,
				// 	"auth service error for %s: %v", msgInfo.Sender, err)
			}
			rtt := time.Since(sr)
			us := rtt.Microseconds()
			ns := rtt.Nanoseconds()
			ms := float64(ns) / 1e6

			ctx.EventManager().EmitEvent(
				sdk.NewEvent("external_auth",
					sdk.NewAttribute("rtt_us", strconv.FormatInt(us, 10)),
					sdk.NewAttribute("rtt_ns", strconv.FormatInt(ns, 10)),
					sdk.NewAttribute("rtt_ms", fmt.Sprintf("%.3f", ms)),
					sdk.NewAttribute("ok", strconv.FormatBool(err == nil && ok)),
					sdk.NewAttribute("op", sdk.MsgTypeURL(m)),
				),
			)

			if !ok {
				if serverMsg == "" {
					serverMsg = "rejected by external auth service"
				}
				ctx.Logger().Info("auth-block: REJECTED",
					"op", sdk.MsgTypeURL(m),
					"sender", msgInfo.Sender,
					"height", ctx.BlockHeight(),
					"reason", serverMsg,
				)
				return ctx, errorsmod.Wrapf(sdkerrors.ErrUnauthorized,
					"sender %s rejected: %s", msgInfo.Sender, serverMsg)
			}
			continue
		}

		ctx.Logger().Info("auth-block: allowed",
			"op", sdk.MsgTypeURL(m),
			"sender", msgInfo.Sender,
			"height", ctx.BlockHeight(),
		)
	}

	return next(ctx, tx, simulate)
}

func isAuthRelevantMsg(m sdk.Msg) bool {
	switch m.(type) {
	case *banktypes.MsgSend, *ibctransfertypes.MsgTransfer:
		return true
	default:
		return false
	}
}

type MsgInfo struct {
	TypeURL  string
	Signers  []string
	Summary  string
	Sender   string
	Receiver string
}

func ExtractMsgInfo(msg sdk.Msg) MsgInfo {
	mi := MsgInfo{TypeURL: sdk.MsgTypeURL(msg)}
	// Signers (in v0.53 i Msg implementano GetSigners)
	// for _, s := range msg.GetSigners() {
	// 	mi.Signers = append(mi.Signers, s.String())
	// }

	switch m := msg.(type) {

	case *ibctransfertypes.MsgTransfer:
		mi.Sender = m.Sender
		mi.Receiver = m.Receiver
		mi.Summary = fmt.Sprintf("IBC transfer %s via %s/%s (timeout: h=%s ts=%d)",
			m.Token.String(), m.SourcePort, m.SourceChannel, m.TimeoutHeight.String(), m.TimeoutTimestamp)

	// Bank send
	case *banktypes.MsgSend:
		mi.Sender = m.FromAddress
		mi.Receiver = m.ToAddress
		mi.Summary = fmt.Sprintf("Bank send %s", sdk.NewCoins(m.Amount...).String())

	// Authz exec "wrapped" messages
	case *authztypes.MsgExec:
		mi.Summary = fmt.Sprintf("Authz exec: %d msgs", len(m.Msgs))

	default:
		if pb, ok := msg.(interface{ ProtoReflect() interface{} }); ok {
			_ = pb
		}
		// bz, _ := protojson.Marshal(msg)
		mi.Summary = fmt.Sprintf("Unknown msg; json=%v", msg)
	}

	return mi
}
