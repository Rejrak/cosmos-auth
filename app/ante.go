package app

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
	authante "github.com/cosmos/cosmos-sdk/x/auth/ante"

	authzattrsante "alpha/x/authzattrs/ante"
)

// newV2AwareAnteHandler preserves the SDK v0.53.3 default chain, inserting V2
// after account signature verification and before sequence increment.
func (app *App) newV2AwareAnteHandler() sdk.AnteHandler {
	core := sdk.ChainAnteDecorators(
		authante.NewSetUpContextDecorator(),
		authante.NewExtensionOptionsDecorator(authzattrsante.V2ExtensionOptionChecker),
		authante.NewValidateBasicDecorator(),
		authante.NewTxTimeoutHeightDecorator(),
		authante.NewValidateMemoDecorator(app.AuthKeeper),
		authante.NewConsumeGasForTxSizeDecorator(app.AuthKeeper),
		authante.NewDeductFeeDecorator(app.AuthKeeper, app.BankKeeper, app.FeeGrantKeeper, nil),
		authante.NewSetPubKeyDecorator(app.AuthKeeper),
		authante.NewValidateSigCountDecorator(app.AuthKeeper),
		authante.NewSigGasConsumeDecorator(app.AuthKeeper, authante.DefaultSigVerificationGasConsumer),
		authante.NewSigVerificationDecorator(app.AuthKeeper, app.txConfig.SignModeHandler()),
		authzattrsante.NewV2CertificateDecorator(app.AuthzAttrsKeeper, app.AuthKeeper, app.appCodec),
		authante.NewIncrementSequenceDecorator(app.AuthKeeper),
	)
	v1 := authzattrsante.NewAuthzDecorator(app.AuthzAttrsKeeper)
	return func(ctx sdk.Context, tx sdk.Tx, simulate bool) (sdk.Context, error) {
		if authzattrsante.ClassifyV2Transaction(tx) == authzattrsante.V1Route {
			return v1.AnteHandle(ctx, tx, simulate, core)
		}
		// V2 and malformed V2 presentations never enter the V1 CURRENT path.
		// The core's SetUpContext still meters/rejects malformed presentations.
		return core(ctx, tx, simulate)
	}
}
