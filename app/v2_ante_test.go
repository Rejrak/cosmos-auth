package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"

	"cosmossdk.io/log"
	storetypes "cosmossdk.io/store/types"
	feegrant "cosmossdk.io/x/feegrant"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	simtestutil "github.com/cosmos/cosmos-sdk/testutil/sims"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	minttypes "github.com/cosmos/cosmos-sdk/x/mint/types"
	"github.com/stretchr/testify/require"

	"alpha/x/authzattrs/types"
	"alpha/x/authzattrs/v2"
)

const v2AppChainID = "alpha-v2-ante-test"

type v2AppAnteFixture struct {
	t           *testing.T
	app         *App
	ctx         sdk.Context
	clientKey   *secp256k1.PrivKey
	subject     sdk.AccAddress
	receiver    sdk.AccAddress
	accountNum  uint64
	issuerKeys  []ed25519.PrivateKey
	fee         sdk.Coins
	certificate *v2.AuthorizationCertificateV2
}

func newV2AppAnteFixture(t *testing.T) *v2AppAnteFixture {
	t.Helper()
	db := dbm.NewMemDB()
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	options := simtestutil.AppOptionsMap{flags.FlagHome: t.TempDir()}
	application := New(log.NewNopLogger(), db, nil, true, options)
	ctx := application.NewUncachedContext(false, cmtproto.Header{ChainID: v2AppChainID, Height: 105}).WithIsSigverifyTx(true)
	require.NoError(t, application.AuthKeeper.Params.Set(ctx, authtypes.DefaultParams()))

	clientKey := secp256k1.GenPrivKeyFromSecret([]byte("v2 app ante client test fixture"))
	subject := sdk.AccAddress(clientKey.PubKey().Address())
	receiver := sdk.AccAddress(bytes.Repeat([]byte{0x42}, 20))
	account := application.AuthKeeper.NewAccountWithAddress(ctx, subject)
	application.AuthKeeper.SetAccount(ctx, account)
	application.AuthKeeper.GetModuleAccount(ctx, minttypes.ModuleName)
	application.AuthKeeper.GetModuleAccount(ctx, authtypes.FeeCollectorName)
	initialFunds := sdk.NewCoins(sdk.NewInt64Coin("stake", 1000000))
	require.NoError(t, application.BankKeeper.MintCoins(ctx, minttypes.ModuleName, initialFunds))
	require.NoError(t, application.BankKeeper.SendCoinsFromModuleToAccount(ctx, minttypes.ModuleName, subject, initialFunds))

	require.NoError(t, application.AuthzAttrsKeeper.SetIssuerSet(ctx, types.IssuerSet{
		IssuerSetId: 9, Active: true, PolicyId: "policy-bank-send", MsgTypeUrl: types.MsgSendTypeURL, ThresholdWeight: 5,
	}))
	issuerKeys := make([]ed25519.PrivateKey, 2)
	for i, issuerID := range []string{"issuer-alpha", "issuer-beta"} {
		// TEST-ONLY deterministic keys; never use these derivation labels in production.
		seed := sha256.Sum256([]byte("v2 app ante " + issuerID + " test fixture only"))
		issuerKeys[i] = ed25519.NewKeyFromSeed(seed[:])
		weight := uint64(2)
		if i == 1 {
			weight = 3
		}
		require.NoError(t, application.AuthzAttrsKeeper.SetIssuer(ctx, types.Issuer{
			IssuerSetId: 9, IssuerId: issuerID, KeyType: types.IssuerKeyType_ISSUER_KEY_TYPE_ED25519,
			PublicKey: issuerKeys[i].Public().(ed25519.PublicKey), Weight: weight, Active: true,
			ValidFromHeight: 100, ValidUntilHeight: 110,
		}))
	}
	require.NoError(t, application.AuthzAttrsKeeper.SetCurrentIssuerSet(ctx, "policy-bank-send", types.MsgSendTypeURL, 9))
	f := &v2AppAnteFixture{t: t, app: application, ctx: ctx, clientKey: clientKey, subject: subject,
		receiver: receiver, accountNum: account.GetAccountNumber(), issuerKeys: issuerKeys,
		fee: sdk.NewCoins(sdk.NewInt64Coin("stake", 100)),
	}
	f.certificate = f.newCertificate(0)
	return f
}

func (f *v2AppAnteFixture) newCertificate(sequence uint64) *v2.AuthorizationCertificateV2 {
	f.t.Helper()
	hash := sha256.Sum256([]byte("v2 app ante policy test fixture"))
	certificate := &v2.AuthorizationCertificateV2{SignDoc: &v2.AuthorizationCertificateSignDocV2{
		Domain: v2.CertificateDomainV2,
		Intent: &v2.AuthorizationIntentV2{
			ChainId: v2AppChainID, Subject: f.subject.String(), Receiver: f.receiver.String(),
			Denom: "token", Amount: "1000", AccountNumber: f.accountNum, Sequence: sequence,
			TimeoutHeight: 110, Memo: "v2 app ante", FeeAmount: []*v2.FeeCoinV2{{Denom: "stake", Amount: "100"}}, GasLimit: 500000,
		},
		PolicyId: "policy-bank-send", PolicyVersion: 2, PolicyHash: hash[:], IssuerSetId: 9,
		ValidFromHeight: 100, ValidUntilHeight: 110,
	}}
	signBytes, _, err := v2.CanonicalCertificateSignBytesV2(certificate.SignDoc, f.app.AuthKeeper.AddressCodec())
	require.NoError(f.t, err)
	for i, issuerID := range []string{"issuer-alpha", "issuer-beta"} {
		certificate.Signatures = append(certificate.Signatures, &v2.IssuerSignatureV2{
			IssuerId: issuerID, Signature: ed25519.Sign(f.issuerKeys[i], signBytes),
		})
	}
	return certificate
}

func (f *v2AppAnteFixture) signedTx(certificate *v2.AuthorizationCertificateV2, sequence uint64, edit func(client.TxBuilder)) (sdk.Tx, []byte) {
	f.t.Helper()
	builder := f.app.TxConfig().NewTxBuilder()
	require.NoError(f.t, builder.SetMsgs(&banktypes.MsgSend{
		FromAddress: f.subject.String(), ToAddress: f.receiver.String(),
		Amount: sdk.NewCoins(sdk.NewInt64Coin("token", 1000)),
	}))
	builder.SetFeeAmount(f.fee)
	builder.SetGasLimit(500000)
	builder.SetMemo("v2 app ante")
	builder.SetTimeoutHeight(110)
	if certificate != nil {
		option, err := codectypes.NewAnyWithValue(certificate)
		require.NoError(f.t, err)
		builder.(client.ExtendedTxBuilder).SetExtensionOptions(option)
	}
	if edit != nil {
		edit(builder)
	}
	sig := signing.SignatureV2{PubKey: f.clientKey.PubKey(), Sequence: sequence,
		Data: &signing.SingleSignatureData{SignMode: signing.SignMode_SIGN_MODE_DIRECT}}
	require.NoError(f.t, builder.SetSignatures(sig))
	signerData := authsigning.SignerData{
		Address: f.subject.String(), ChainID: v2AppChainID,
		AccountNumber: f.accountNum, Sequence: sequence, PubKey: f.clientKey.PubKey(),
	}
	signBytes, err := authsigning.GetSignBytesAdapter(context.Background(), f.app.TxConfig().SignModeHandler(),
		signing.SignMode_SIGN_MODE_DIRECT, signerData, builder.GetTx())
	require.NoError(f.t, err)
	sig.Data.(*signing.SingleSignatureData).Signature, err = f.clientKey.Sign(signBytes)
	require.NoError(f.t, err)
	require.NoError(f.t, builder.SetSignatures(sig))
	raw, err := f.app.TxConfig().TxEncoder()(builder.GetTx())
	require.NoError(f.t, err)
	return builder.GetTx(), raw
}

func (f *v2AppAnteFixture) run(tx sdk.Tx, raw []byte, check, recheck bool) (sdk.Context, error) {
	f.t.Helper()
	ctx, write := f.ctx.CacheContext()
	ctx = ctx.WithTxBytes(raw).WithIsCheckTx(check).WithIsReCheckTx(recheck).WithIsSigverifyTx(true)
	result, err := f.app.AnteHandler()(ctx, tx, false)
	if err == nil {
		write() // Model BaseApp's Ante cache: only successful Ante writes persist.
	}
	return result, err
}

func (f *v2AppAnteFixture) sequence() uint64 {
	return f.app.AuthKeeper.GetAccount(f.ctx, f.subject).GetSequence()
}

func (f *v2AppAnteFixture) stake() sdk.Coin {
	return f.app.BankKeeper.GetBalance(f.ctx, f.subject, "stake")
}

func (f *v2AppAnteFixture) installV1Grant() {
	f.t.Helper()
	require.NoError(f.t, f.app.AuthzAttrsKeeper.SetAuthorization(f.ctx, types.AuthorizationRecord{
		AuthorizationId: "v1-app-test", Subject: f.subject.String(), MsgTypeUrl: types.MsgSendTypeURL,
		PolicyId: "policy-bank-send", PolicyVersion: 1, IssuerSetId: 9,
		ValidFromHeight: 100, ValidUntilHeight: 110,
		BankSendConstraints: types.BankSendConstraints{Denom: "token", Receiver: f.receiver.String(), MaxAmount: "5000"},
	}))
}

func TestV2AppAnteRealSignatureRoutingAndCache(t *testing.T) {
	t.Run("V1 missing and valid CURRENT", func(t *testing.T) {
		f := newV2AppAnteFixture(t)
		tx, raw := f.signedTx(nil, 0, nil)
		_, err := f.run(tx, raw, false, false)
		require.ErrorContains(t, err, types.ReasonNotFound)
		require.Zero(t, f.sequence())
		f.installV1Grant()
		_, err = f.run(tx, raw, false, false)
		require.NoError(t, err)
		require.Equal(t, uint64(1), f.sequence())
	})

	t.Run("V2 succeeds without V1 CURRENT and increments once", func(t *testing.T) {
		f := newV2AppAnteFixture(t)
		tx, raw := f.signedTx(f.certificate, 0, nil)
		originalCtx := f.ctx
		f.ctx = f.ctx.WithGasMeter(storetypes.NewGasMeter(1)) // SDK SetUpContext must replace this meter.
		result, err := f.run(tx, raw, false, false)
		f.ctx = originalCtx
		require.NoError(t, err)
		require.Equal(t, uint64(1), f.sequence())
		require.Greater(t, result.GasMeter().GasConsumed(), uint64(0))
		_, found, err := f.app.AuthzAttrsKeeper.GetAuthorization(f.ctx, f.subject.String(), types.MsgSendTypeURL)
		require.NoError(t, err)
		require.False(t, found)
	})

	t.Run("invalid V2 never falls back and rolls back fee pubkey sequence", func(t *testing.T) {
		f := newV2AppAnteFixture(t)
		f.installV1Grant()
		f.certificate.Signatures[0].Signature[0] ^= 1
		tx, raw := f.signedTx(f.certificate, 0, nil)
		beforeFee := f.stake()
		_, err := f.run(tx, raw, false, false)
		require.ErrorIs(t, err, v2.ErrBadSignatureV2)
		require.Equal(t, beforeFee, f.stake())
		require.Zero(t, f.sequence())
		require.Nil(t, f.app.AuthKeeper.GetAccount(f.ctx, f.subject).GetPubKey())
	})

	t.Run("invalid client signature and wrong sequence", func(t *testing.T) {
		f := newV2AppAnteFixture(t)
		_, raw := f.signedTx(f.certificate, 0, nil)
		altered := append([]byte(nil), raw...)
		altered[len(altered)-1] ^= 1
		decoded, err := f.app.TxConfig().TxDecoder()(altered)
		require.NoError(t, err)
		_, err = f.run(decoded, altered, false, false)
		require.ErrorIs(t, err, sdkerrors.ErrUnauthorized)
		require.Zero(t, f.sequence())
		wrongTx, wrongRaw := f.signedTx(f.newCertificate(1), 1, nil)
		_, err = f.run(wrongTx, wrongRaw, false, false)
		require.ErrorIs(t, err, sdkerrors.ErrWrongSequence)
		require.Zero(t, f.sequence())
	})
}

func TestV2AppAntePreservesV1Feegrant(t *testing.T) {
	f := newV2AppAnteFixture(t)
	f.installV1Grant()
	granter := sdk.AccAddress(bytes.Repeat([]byte{0x51}, 20))
	f.app.AuthKeeper.SetAccount(f.ctx, f.app.AuthKeeper.NewAccountWithAddress(f.ctx, granter))
	funds := sdk.NewCoins(sdk.NewInt64Coin("stake", 1000))
	require.NoError(t, f.app.BankKeeper.MintCoins(f.ctx, minttypes.ModuleName, funds))
	require.NoError(t, f.app.BankKeeper.SendCoinsFromModuleToAccount(f.ctx, minttypes.ModuleName, granter, funds))
	require.NoError(t, f.app.FeeGrantKeeper.GrantAllowance(f.ctx, granter, f.subject, &feegrant.BasicAllowance{SpendLimit: funds}))
	beforeSender := f.stake()
	beforeGranter := f.app.BankKeeper.GetBalance(f.ctx, granter, "stake")
	tx, raw := f.signedTx(nil, 0, func(b client.TxBuilder) { b.SetFeeGranter(granter) })
	_, err := f.run(tx, raw, false, false)
	require.NoError(t, err)
	require.Equal(t, beforeSender, f.stake())
	require.Equal(t, beforeGranter.Amount.SubRaw(100), f.app.BankKeeper.GetBalance(f.ctx, granter, "stake").Amount)
}

func TestV2AppAnteInvalidExtensionsAndPhases(t *testing.T) {
	for _, tt := range []struct {
		name string
		edit func(*v2AppAnteFixture, client.TxBuilder)
	}{
		{"duplicate critical", func(f *v2AppAnteFixture, b client.TxBuilder) {
			option, err := codectypes.NewAnyWithValue(f.certificate)
			require.NoError(f.t, err)
			b.(client.ExtendedTxBuilder).SetExtensionOptions(option, option)
		}},
		{"unknown critical", func(_ *v2AppAnteFixture, b client.TxBuilder) {
			b.(client.ExtendedTxBuilder).SetExtensionOptions(&codectypes.Any{TypeUrl: "/unknown.Extension", Value: []byte{1}})
		}},
		{"noncritical certificate", func(f *v2AppAnteFixture, b client.TxBuilder) {
			option, err := codectypes.NewAnyWithValue(f.certificate)
			require.NoError(f.t, err)
			b.(client.ExtendedTxBuilder).SetExtensionOptions()
			b.(interface{ SetNonCriticalExtensionOptions(...*codectypes.Any) }).SetNonCriticalExtensionOptions(option)
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newV2AppAnteFixture(t)
			f.installV1Grant()
			tx, raw := f.signedTx(f.certificate, 0, func(b client.TxBuilder) { tt.edit(f, b) })
			_, err := f.run(tx, raw, false, false)
			require.Error(t, err)
			require.Zero(t, f.sequence())
		})
	}

	for _, tt := range []struct {
		name           string
		check, recheck bool
	}{
		{"CheckTx", true, false}, {"ReCheckTx", true, true}, {"FinalizeBlock", false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newV2AppAnteFixture(t)
			f.certificate.Signatures[0].Signature[0] ^= 1
			tx, raw := f.signedTx(f.certificate, 0, nil)
			_, err := f.run(tx, raw, tt.check, tt.recheck)
			require.ErrorIs(t, err, v2.ErrBadSignatureV2)
		})
	}
}

func TestV2AppAnteOutOfGasRecovered(t *testing.T) {
	const gasLimit uint64 = 70000
	// A same-sized non-critical presentation reaches the V2 decorator at this
	// gas limit, proving that the normal SDK core alone does not exhaust it.
	probe := newV2AppAnteFixture(t)
	probeTx, probeRaw := probe.signedTx(probe.certificate, 0, func(b client.TxBuilder) {
		b.SetGasLimit(gasLimit)
		option, err := codectypes.NewAnyWithValue(probe.certificate)
		require.NoError(t, err)
		b.(client.ExtendedTxBuilder).SetExtensionOptions()
		b.(interface{ SetNonCriticalExtensionOptions(...*codectypes.Any) }).SetNonCriticalExtensionOptions(option)
	})
	_, probeErr := probe.run(probeTx, probeRaw, false, false)
	require.ErrorIs(t, probeErr, v2.ErrMalformedExtensionV2)

	f := newV2AppAnteFixture(t)
	f.certificate.SignDoc.Intent.GasLimit = gasLimit
	signBytes, _, err := v2.CanonicalCertificateSignBytesV2(f.certificate.SignDoc, f.app.AuthKeeper.AddressCodec())
	require.NoError(t, err)
	for i, signature := range f.certificate.Signatures {
		signature.Signature = ed25519.Sign(f.issuerKeys[i], signBytes)
	}
	tx, raw := f.signedTx(f.certificate, 0, func(b client.TxBuilder) { b.SetGasLimit(gasLimit) })
	require.Equal(t, len(probeRaw), len(raw))
	_, err = f.run(tx, raw, false, false)
	require.ErrorIs(t, err, sdkerrors.ErrOutOfGas)
	require.Zero(t, f.sequence())
}
