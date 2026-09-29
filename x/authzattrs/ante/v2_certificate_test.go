package ante_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"
	"time"

	"cosmossdk.io/core/address"
	storetypes "cosmossdk.io/store/types"
	addresscodec "github.com/cosmos/cosmos-sdk/codec/address"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/testutil"
	sdk "github.com/cosmos/cosmos-sdk/types"
	moduletestutil "github.com/cosmos/cosmos-sdk/types/module/testutil"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	authztypes "github.com/cosmos/cosmos-sdk/x/authz"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/cosmos/gogoproto/proto"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"
	protov2 "google.golang.org/protobuf/proto"

	"alpha/x/authzattrs/ante"
	"alpha/x/authzattrs/keeper"
	module "alpha/x/authzattrs/module"
	"alpha/x/authzattrs/types"
	"alpha/x/authzattrs/v2"
)

const (
	v2Subject  = "cosmos1duzpxku5atm98qk6ywvgdjzn50yzv90q7c3r44"
	v2Receiver = "cosmos1ssevndlg997a89wpw2wv9xj2vahhqcyt0gml84"
)

type extensionTestTx struct {
	critical, noncritical []*codectypes.Any
}

func (extensionTestTx) GetMsgs() []sdk.Msg                    { return nil }
func (extensionTestTx) GetMsgsV2() ([]protov2.Message, error) { return nil, nil }
func (tx extensionTestTx) GetExtensionOptions() []*codectypes.Any {
	return tx.critical
}
func (tx extensionTestTx) GetNonCriticalExtensionOptions() []*codectypes.Any {
	return tx.noncritical
}

func TestV2Classification(t *testing.T) {
	certificate := &codectypes.Any{TypeUrl: v2.CertificateTypeURLV2, Value: []byte{1}}
	unrelated := &codectypes.Any{TypeUrl: "/other.Extension", Value: []byte{1}}
	for _, tt := range []struct {
		name string
		tx   extensionTestTx
		want ante.V2TxRoute
	}{
		{"no certificate", extensionTestTx{}, ante.V1Route},
		{"unrelated noncritical alone", extensionTestTx{noncritical: []*codectypes.Any{unrelated}}, ante.V1Route},
		{"exact critical", extensionTestTx{critical: []*codectypes.Any{certificate}}, ante.V2Route},
		{"alternate type URL prefix", extensionTestTx{critical: []*codectypes.Any{{TypeUrl: "type.googleapis.com/alpha.authzattrs.v2.AuthorizationCertificateV2", Value: certificate.Value}}}, ante.InvalidV2Route},
		{"duplicate certificate", extensionTestTx{critical: []*codectypes.Any{certificate, certificate}}, ante.InvalidV2Route},
		{"unknown critical", extensionTestTx{critical: []*codectypes.Any{unrelated}}, ante.InvalidV2Route},
		{"extra critical", extensionTestTx{critical: []*codectypes.Any{certificate, unrelated}}, ante.InvalidV2Route},
		{"certificate noncritical", extensionTestTx{noncritical: []*codectypes.Any{certificate}}, ante.InvalidV2Route},
		{"certificate alias noncritical", extensionTestTx{noncritical: []*codectypes.Any{{TypeUrl: "type.googleapis.com/alpha.authzattrs.v2.AuthorizationCertificateV2", Value: certificate.Value}}}, ante.InvalidV2Route},
		{"certificate bare name noncritical", extensionTestTx{noncritical: []*codectypes.Any{{TypeUrl: "alpha.authzattrs.v2.AuthorizationCertificateV2", Value: certificate.Value}}}, ante.InvalidV2Route},
		{"extra noncritical", extensionTestTx{critical: []*codectypes.Any{certificate}, noncritical: []*codectypes.Any{unrelated}}, ante.InvalidV2Route},
		{"nil critical", extensionTestTx{critical: []*codectypes.Any{nil}}, ante.InvalidV2Route},
	} {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, ante.ClassifyV2Transaction(tt.tx))
		})
	}
	require.Equal(t, ante.InvalidV2Route, ante.ClassifyV2Transaction(nil))
	require.True(t, ante.V2ExtensionOptionChecker(certificate))
	require.False(t, ante.V2ExtensionOptionChecker(unrelated))
}

type v2Accounts struct {
	codec   address.Codec
	account sdk.AccountI
	params  authtypes.Params
}

func (a v2Accounts) GetAccount(_ context.Context, addr sdk.AccAddress) sdk.AccountI {
	if a.account.GetAddress().Equals(addr) {
		return a.account
	}
	return nil
}
func (a v2Accounts) AddressCodec() address.Codec                { return a.codec }
func (a v2Accounts) GetParams(context.Context) authtypes.Params { return a.params }

type v2TxFixture struct {
	t           *testing.T
	ctx         sdk.Context
	codec       moduletestutil.TestEncodingConfig
	decorator   ante.V2CertificateDecorator
	account     *authtypes.BaseAccount
	body        txtypes.TxBody
	authInfo    txtypes.AuthInfo
	certificate *v2.AuthorizationCertificateV2
	msg         banktypes.MsgSend
	raw         txtypes.TxRaw
}

func fixtureV2(t *testing.T, configuredParams ...authtypes.Params) *v2TxFixture {
	t.Helper()
	params := authtypes.DefaultParams()
	if len(configuredParams) != 0 {
		params = configuredParams[0]
	}
	enc := moduletestutil.MakeTestEncodingConfig(module.AppModule{})
	banktypes.RegisterInterfaces(enc.InterfaceRegistry)
	authztypes.RegisterInterfaces(enc.InterfaceRegistry)
	addrCodec := addresscodec.NewBech32Codec("cosmos")
	storeKey := storetypes.NewKVStoreKey(types.StoreKey)
	ctx := testutil.DefaultContextWithDB(t, storeKey, storetypes.NewTransientStoreKey("transient_v2")).Ctx.WithBlockHeight(105).WithChainID("alpha-1")
	k := keeper.NewKeeper(runtime.NewKVStoreService(storeKey), enc.Codec, addrCodec, authtypes.NewModuleAddress(types.GovModuleName))
	require.NoError(t, k.SetIssuerSet(ctx, types.IssuerSet{IssuerSetId: 9, Active: true, PolicyId: "policy-bank-send", MsgTypeUrl: types.MsgSendTypeURL, ThresholdWeight: 5}))
	for _, issuer := range []struct {
		id, key, signature string
		weight             uint64
	}{
		{"issuer-alpha", "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8", "b1bea693676fc45cbc80c3cf2127166238d3289466166ab3630a684e6f7bb1d800601459bb212a98d2d0b8c1f5a96e359744b1e1ce8a0430298d61dd334d6b0d", 2},
		{"issuer-beta", "29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7", "02d446a06af1329d2dba3e752a6f0689d9625c8e46a6f55b2ee4809becf1c1e133d6ad7b0196f9b15df653c97679a81250912525f88df0c39a99b4fa3efc4008", 3},
	} {
		pubkey, err := hex.DecodeString(issuer.key)
		require.NoError(t, err)
		require.NoError(t, k.SetIssuer(ctx, types.Issuer{IssuerSetId: 9, IssuerId: issuer.id, KeyType: types.IssuerKeyType_ISSUER_KEY_TYPE_ED25519, PublicKey: pubkey, Weight: issuer.weight, Active: true, ValidFromHeight: 100, ValidUntilHeight: 110}))
	}
	require.NoError(t, k.SetCurrentIssuerSet(ctx, "policy-bank-send", types.MsgSendTypeURL, 9))
	addr, err := addrCodec.StringToBytes(v2Subject)
	require.NoError(t, err)
	account := authtypes.NewBaseAccountWithAddress(sdk.AccAddress(addr))
	require.NoError(t, account.SetAccountNumber(7))
	require.NoError(t, account.SetSequence(3))
	hash, err := hex.DecodeString("5ad8c4fa036c6238f322b3bfc2c012f0f12d9c6af391ba9d26acfe08a1d01d13")
	require.NoError(t, err)
	certificate := &v2.AuthorizationCertificateV2{SignDoc: &v2.AuthorizationCertificateSignDocV2{
		Domain:   v2.CertificateDomainV2,
		Intent:   &v2.AuthorizationIntentV2{ChainId: "alpha-1", Subject: v2Subject, Receiver: v2Receiver, Denom: "token", Amount: "1000", AccountNumber: 7, Sequence: 3, TimeoutHeight: 115, Memo: "v2 golden", FeeAmount: []*v2.FeeCoinV2{{Denom: "stake", Amount: "100"}}, GasLimit: 200000},
		PolicyId: "policy-bank-send", PolicyVersion: 2, PolicyHash: hash, IssuerSetId: 9, ValidFromHeight: 100, ValidUntilHeight: 110,
	}}
	for _, item := range []struct{ id, signature string }{
		{"issuer-alpha", "b1bea693676fc45cbc80c3cf2127166238d3289466166ab3630a684e6f7bb1d800601459bb212a98d2d0b8c1f5a96e359744b1e1ce8a0430298d61dd334d6b0d"},
		{"issuer-beta", "02d446a06af1329d2dba3e752a6f0689d9625c8e46a6f55b2ee4809becf1c1e133d6ad7b0196f9b15df653c97679a81250912525f88df0c39a99b4fa3efc4008"},
	} {
		signature, err := hex.DecodeString(item.signature)
		require.NoError(t, err)
		certificate.Signatures = append(certificate.Signatures, &v2.IssuerSignatureV2{IssuerId: item.id, Signature: signature})
	}
	f := &v2TxFixture{t: t, ctx: ctx, codec: enc, account: account, certificate: certificate,
		decorator: ante.NewV2CertificateDecorator(k, v2Accounts{codec: addrCodec, account: account, params: params}, enc.Codec),
		msg:       banktypes.MsgSend{FromAddress: v2Subject, ToAddress: v2Receiver, Amount: sdk.NewCoins(sdk.NewInt64Coin("token", 1000))},
		authInfo:  txtypes.AuthInfo{SignerInfos: []*txtypes.SignerInfo{{Sequence: 3, ModeInfo: &txtypes.ModeInfo{Sum: &txtypes.ModeInfo_Single_{Single: &txtypes.ModeInfo_Single{Mode: signing.SignMode_SIGN_MODE_DIRECT}}}}}, Fee: &txtypes.Fee{Amount: sdk.NewCoins(sdk.NewInt64Coin("stake", 100)), GasLimit: 200000}},
	}
	return f
}

func (f *v2TxFixture) build() sdk.Tx {
	f.t.Helper()
	msgAny, err := codectypes.NewAnyWithValue(&f.msg)
	require.NoError(f.t, err)
	certAny, err := codectypes.NewAnyWithValue(f.certificate)
	require.NoError(f.t, err)
	f.body.Messages = []*codectypes.Any{msgAny}
	f.body.ExtensionOptions = []*codectypes.Any{certAny}
	f.body.Memo = "v2 golden"
	f.body.TimeoutHeight = 115
	return f.encode()
}

func (f *v2TxFixture) encode() sdk.Tx {
	f.t.Helper()
	if len(f.body.Messages) > 0 {
		msgAny, err := codectypes.NewAnyWithValue(&f.msg)
		require.NoError(f.t, err)
		f.body.Messages[0] = msgAny
	}
	if len(f.body.ExtensionOptions) > 0 {
		certAny, err := codectypes.NewAnyWithValue(f.certificate)
		require.NoError(f.t, err)
		f.body.ExtensionOptions[0] = certAny
	}
	bodyBytes, err := proto.Marshal(&f.body)
	require.NoError(f.t, err)
	authBytes, err := proto.Marshal(&f.authInfo)
	require.NoError(f.t, err)
	f.raw = txtypes.TxRaw{BodyBytes: bodyBytes, AuthInfoBytes: authBytes, Signatures: [][]byte{bytes.Repeat([]byte{1}, 64)}}
	rawBytes, err := proto.Marshal(&f.raw)
	require.NoError(f.t, err)
	f.ctx = f.ctx.WithTxBytes(rawBytes)
	tx, err := f.codec.TxConfig.TxDecoder()(rawBytes)
	require.NoError(f.t, err)
	return tx
}

func (f *v2TxFixture) run(tx sdk.Tx) error {
	f.t.Helper()
	return f.decorator.VerifyV2Transaction(f.ctx, tx)
}

func TestV2TransactionGoldenAndSequenceSource(t *testing.T) {
	f := fixtureV2(t)
	tx := f.build()
	require.Equal(t, ante.V2Route, ante.ClassifyV2Transaction(tx))
	require.NoError(t, f.run(tx))
	// V2 reads signed SignerInfo.sequence, never a potentially incremented
	// account object's sequence. The account number remains stable.
	require.NoError(t, f.account.SetSequence(4))
	require.NoError(t, f.run(tx))
	nextCalled := false
	_, err := f.decorator.AnteHandle(f.ctx, tx, false, func(ctx sdk.Context, _ sdk.Tx, _ bool) (sdk.Context, error) {
		nextCalled = true
		return ctx, nil
	})
	require.NoError(t, err)
	require.True(t, nextCalled)
	before := proto.Clone(f.certificate)
	require.NoError(t, f.run(tx))
	require.True(t, proto.Equal(before, f.certificate))
}

func TestV2TransactionIntentAndShapeFailures(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change func(*v2TxFixture)
		want   error
	}{
		{"wrong sender", func(f *v2TxFixture) { f.msg.FromAddress = v2Receiver }, v2.ErrUnsupportedTxV2},
		{"wrong receiver", func(f *v2TxFixture) { f.msg.ToAddress = v2Subject }, v2.ErrIntentMismatchV2},
		{"wrong denom", func(f *v2TxFixture) { f.msg.Amount[0].Denom = "stake" }, v2.ErrIntentMismatchV2},
		{"wrong amount", func(f *v2TxFixture) { f.msg.Amount[0].Amount = sdk.NewInt64Coin("token", 1001).Amount }, v2.ErrIntentMismatchV2},
		{"wrong chain", func(f *v2TxFixture) { f.ctx = f.ctx.WithChainID("other") }, v2.ErrChainIDMismatchV2},
		{"wrong account number", func(f *v2TxFixture) { require.NoError(t, f.account.SetAccountNumber(8)) }, v2.ErrIntentMismatchV2},
		{"wrong sequence", func(f *v2TxFixture) { f.authInfo.SignerInfos[0].Sequence = 4 }, v2.ErrIntentMismatchV2},
		{"wrong memo", func(f *v2TxFixture) { f.body.Memo = "other" }, v2.ErrIntentMismatchV2},
		{"wrong timeout", func(f *v2TxFixture) { f.body.TimeoutHeight = 116 }, v2.ErrIntentMismatchV2},
		{"wrong fee", func(f *v2TxFixture) { f.authInfo.Fee.Amount[0].Amount = sdk.NewInt64Coin("stake", 101).Amount }, v2.ErrIntentMismatchV2},
		{"wrong gas", func(f *v2TxFixture) { f.authInfo.Fee.GasLimit = 200001 }, v2.ErrIntentMismatchV2},
		{"two sends", func(f *v2TxFixture) { f.body.Messages = append(f.body.Messages, f.body.Messages[0]) }, v2.ErrUnsupportedTxV2},
		{"zero messages", func(f *v2TxFixture) { f.body.Messages = nil }, v2.ErrUnsupportedTxV2},
		{"send plus multisend", func(f *v2TxFixture) {
			other, err := codectypes.NewAnyWithValue(&banktypes.MsgMultiSend{})
			require.NoError(t, err)
			f.body.Messages = append(f.body.Messages, other)
		}, v2.ErrUnsupportedTxV2},
		{"send plus msgexec", func(f *v2TxFixture) {
			other, err := codectypes.NewAnyWithValue(&authztypes.MsgExec{})
			require.NoError(t, err)
			f.body.Messages = append(f.body.Messages, other)
		}, v2.ErrUnsupportedTxV2},
		{"two transfer coins", func(f *v2TxFixture) { f.msg.Amount = append(f.msg.Amount, sdk.NewInt64Coin("stake", 1)) }, v2.ErrUnsupportedTxV2},
		{"two signer infos", func(f *v2TxFixture) {
			f.authInfo.SignerInfos = append(f.authInfo.SignerInfos, f.authInfo.SignerInfos[0])
		}, v2.ErrUnsupportedTxV2},
		{"payer", func(f *v2TxFixture) { f.authInfo.Fee.Payer = v2Subject }, v2.ErrUnsupportedTxV2},
		{"granter", func(f *v2TxFixture) { f.authInfo.Fee.Granter = v2Receiver }, v2.ErrUnsupportedTxV2},
		{"tip", func(f *v2TxFixture) { f.authInfo.Tip = &txtypes.Tip{} }, v2.ErrUnsupportedTxV2},
		{"unordered", func(f *v2TxFixture) { f.body.Unordered = true }, v2.ErrUnsupportedTxV2},
		{"timeout timestamp", func(f *v2TxFixture) { timestamp := time.Unix(1, 0); f.body.TimeoutTimestamp = &timestamp }, v2.ErrUnsupportedTxV2},
		{"non-direct", func(f *v2TxFixture) {
			f.authInfo.SignerInfos[0].ModeInfo.GetSingle().Mode = signing.SignMode_SIGN_MODE_LEGACY_AMINO_JSON
		}, v2.ErrUnsupportedTxV2},
		{"multi sign mode", func(f *v2TxFixture) {
			f.authInfo.SignerInfos[0].ModeInfo = &txtypes.ModeInfo{Sum: &txtypes.ModeInfo_Multi_{Multi: &txtypes.ModeInfo_Multi{}}}
		}, v2.ErrUnsupportedTxV2},
		{"bad issuer signature", func(f *v2TxFixture) { f.certificate.Signatures[0].Signature[0] ^= 1 }, v2.ErrBadSignatureV2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := fixtureV2(t)
			tx := f.build()
			tt.change(f)
			if tt.name != "wrong chain" && tt.name != "wrong account number" {
				tx = f.encode()
			}
			require.ErrorIs(t, f.run(tx), tt.want)
		})
	}
}

func TestV2DecoratorNeverFallsBack(t *testing.T) {
	f := fixtureV2(t)
	f.ctx = f.ctx.WithGasMeter(storetypes.NewGasMeter(1))
	called := false
	next := func(ctx sdk.Context, _ sdk.Tx, _ bool) (sdk.Context, error) { called = true; return ctx, nil }
	_, err := f.decorator.AnteHandle(f.ctx, extensionTestTx{}, false, next)
	require.NoError(t, err)
	require.True(t, called)
	require.Zero(t, f.ctx.GasMeter().GasConsumed())
	called = false
	_, err = f.decorator.AnteHandle(f.ctx, extensionTestTx{critical: []*codectypes.Any{{TypeUrl: "/other"}}}, false, next)
	require.ErrorIs(t, err, v2.ErrMalformedExtensionV2)
	require.False(t, called)
}

func TestV2VerificationGasUsesAuthParams(t *testing.T) {
	var previousGas uint64
	for _, cost := range []uint64{3, 11} {
		params := authtypes.DefaultParams()
		params.TxSizeCostPerByte = cost
		params.SigVerifyCostED25519 = 41
		f := fixtureV2(t, params)
		tx := f.build()
		f.ctx = f.ctx.WithGasMeter(storetypes.NewGasMeter(100000))
		require.NoError(t, f.run(tx))
		gas := f.ctx.GasMeter().GasConsumed()
		require.Positive(t, gas)
		if previousGas != 0 {
			require.Equal(t, uint64(len(f.ctx.TxBytes()))*(11-3), gas-previousGas)
		}
		previousGas = gas
	}
	// Even a rejected raw protobuf is charged before recursive inspection.
	params := authtypes.DefaultParams()
	params.TxSizeCostPerByte = 3
	f := fixtureV2(t, params)
	tx := f.build()
	f.ctx = f.ctx.WithTxBytes(appendUnknown(f.ctx.TxBytes())).WithGasMeter(storetypes.NewGasMeter(100000))
	require.ErrorIs(t, f.run(tx), v2.ErrInvalidRawTxV2)
	require.Equal(t, uint64(len(f.ctx.TxBytes()))*params.TxSizeCostPerByte, f.ctx.GasMeter().GasConsumed())
}

func TestV2VerificationGasChargesEachSuppliedSignature(t *testing.T) {
	for _, tt := range []struct {
		name  string
		count int
		bad   bool
		want  error
	}{
		{"one valid but no quorum", 1, false, v2.ErrQuorumNotMetV2},
		{"two valid", 2, false, nil},
		{"early bad signature", 2, true, v2.ErrBadSignatureV2},
		{"too many signatures", 17, false, v2.ErrInvalidCertificateV2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var previousGas uint64
			for _, cost := range []uint64{41, 67} {
				params := authtypes.DefaultParams()
				params.TxSizeCostPerByte = 3
				params.SigVerifyCostED25519 = cost
				f := fixtureV2(t, params)
				if tt.count == 1 {
					f.certificate.Signatures = f.certificate.Signatures[:1]
				} else if tt.count == 17 {
					for len(f.certificate.Signatures) < 17 {
						f.certificate.Signatures = append(f.certificate.Signatures, f.certificate.Signatures[0])
					}
				}
				if tt.bad {
					f.certificate.Signatures[0].Signature[0] ^= 1
				}
				tx := f.build()
				f.ctx = f.ctx.WithGasMeter(storetypes.NewGasMeter(100000))
				err := f.run(tx)
				if tt.want == nil {
					require.NoError(t, err)
				} else {
					require.ErrorIs(t, err, tt.want)
				}
				gas := f.ctx.GasMeter().GasConsumed()
				if previousGas != 0 {
					charged := uint64(tt.count)
					if tt.count > v2.MaxSignaturesV2 {
						charged = 0
					}
					require.Equal(t, charged*(67-41), gas-previousGas)
				}
				previousGas = gas
			}
		})
	}
}

func TestV2VerificationGasOutOfGasPanics(t *testing.T) {
	f := fixtureV2(t)
	tx := f.build()
	params := authtypes.DefaultParams()
	rawGas := uint64(len(f.ctx.TxBytes())) * params.TxSizeCostPerByte
	f.ctx = f.ctx.WithGasMeter(storetypes.NewGasMeter(rawGas + params.SigVerifyCostED25519 - 1))
	require.PanicsWithValue(t, storetypes.ErrorOutOfGas{Descriptor: "v2 issuer Ed25519 verification"}, func() {
		_ = f.run(tx)
	})
}

func TestV2RawStrictness(t *testing.T) {
	for _, tt := range []struct {
		name string
		edit func(*v2TxFixture)
		want error
	}{
		{"certificate too large", func(f *v2TxFixture) { f.body.ExtensionOptions[0].Value = bytes.Repeat([]byte{1}, 4097) }, v2.ErrMalformedExtensionV2},
		{"malformed certificate", func(f *v2TxFixture) { f.body.ExtensionOptions[0].Value = []byte{0xff} }, v2.ErrInvalidRawTxV2},
		{"unknown certificate field", func(f *v2TxFixture) {
			f.body.ExtensionOptions[0].Value = appendUnknown(f.body.ExtensionOptions[0].Value)
		}, v2.ErrInvalidRawTxV2},
		{"unknown sign doc field", func(f *v2TxFixture) {
			f.body.ExtensionOptions[0].Value = replaceFirstBytesField(t, f.body.ExtensionOptions[0].Value, 1, appendUnknown)
		}, v2.ErrInvalidRawTxV2},
		{"unknown intent field", func(f *v2TxFixture) {
			f.body.ExtensionOptions[0].Value = replaceFirstBytesField(t, f.body.ExtensionOptions[0].Value, 1, func(doc []byte) []byte {
				return replaceFirstBytesField(t, doc, 2, appendUnknown)
			})
		}, v2.ErrInvalidRawTxV2},
		{"unknown fee coin field", func(f *v2TxFixture) {
			f.body.ExtensionOptions[0].Value = replaceFirstBytesField(t, f.body.ExtensionOptions[0].Value, 1, func(doc []byte) []byte {
				return replaceFirstBytesField(t, doc, 2, func(intent []byte) []byte {
					return replaceFirstBytesField(t, intent, 10, appendUnknown)
				})
			})
		}, v2.ErrInvalidRawTxV2},
		{"unknown issuer signature field", func(f *v2TxFixture) {
			f.body.ExtensionOptions[0].Value = replaceFirstBytesField(t, f.body.ExtensionOptions[0].Value, 2, appendUnknown)
		}, v2.ErrInvalidRawTxV2},
		{"unknown message field", func(f *v2TxFixture) { f.body.Messages[0].Value = appendUnknown(f.body.Messages[0].Value) }, v2.ErrInvalidRawTxV2},
		{"unknown transfer coin field", func(f *v2TxFixture) {
			f.body.Messages[0].Value = replaceFirstBytesField(t, f.body.Messages[0].Value, 3, appendUnknown)
		}, v2.ErrInvalidRawTxV2},
		{"unknown body field", func(f *v2TxFixture) { f.raw.BodyBytes = appendUnknown(f.raw.BodyBytes) }, v2.ErrInvalidRawTxV2},
		{"unknown certificate Any field", func(f *v2TxFixture) {
			f.raw.BodyBytes = replaceFirstBytesField(t, f.raw.BodyBytes, 1023, appendUnknown)
		}, v2.ErrInvalidRawTxV2},
		{"unknown auth info field", func(f *v2TxFixture) { f.raw.AuthInfoBytes = appendUnknown(f.raw.AuthInfoBytes) }, v2.ErrInvalidRawTxV2},
		{"unknown fee field", func(f *v2TxFixture) {
			f.raw.AuthInfoBytes = replaceFirstBytesField(t, f.raw.AuthInfoBytes, 2, appendUnknown)
		}, v2.ErrInvalidRawTxV2},
		{"unknown signer info field", func(f *v2TxFixture) {
			f.raw.AuthInfoBytes = replaceFirstBytesField(t, f.raw.AuthInfoBytes, 1, appendUnknown)
		}, v2.ErrInvalidRawTxV2},
		{"unknown raw field", func(f *v2TxFixture) { f.ctx = f.ctx.WithTxBytes(appendUnknown(f.ctx.TxBytes())) }, v2.ErrInvalidRawTxV2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := fixtureV2(t)
			tx := f.build()
			tt.edit(f)
			if tt.name != "unknown raw field" {
				if tt.name != "unknown body field" && tt.name != "unknown auth info field" && tt.name != "unknown fee field" && tt.name != "unknown signer info field" && tt.name != "unknown certificate Any field" {
					bodyBytes, err := proto.Marshal(&f.body)
					require.NoError(t, err)
					f.raw.BodyBytes = bodyBytes
				}
				rawBytes, err := proto.Marshal(&f.raw)
				require.NoError(t, err)
				f.ctx = f.ctx.WithTxBytes(rawBytes)
			}
			require.ErrorIs(t, f.run(tx), tt.want)
		})
	}
}

func appendUnknown(value []byte) []byte {
	value = protowire.AppendTag(append([]byte(nil), value...), 3000, protowire.VarintType)
	return protowire.AppendVarint(value, 1)
}

func replaceFirstBytesField(t *testing.T, input []byte, target protowire.Number, replace func([]byte) []byte) []byte {
	t.Helper()
	var output []byte
	replaced := false
	for len(input) > 0 {
		number, wireType, tagSize := protowire.ConsumeTag(input)
		require.Positive(t, tagSize)
		_, _, fieldSize := protowire.ConsumeField(input)
		require.Positive(t, fieldSize)
		if !replaced && number == target && wireType == protowire.BytesType {
			value, valueSize := protowire.ConsumeBytes(input[tagSize:])
			require.Positive(t, valueSize)
			output = protowire.AppendTag(output, number, protowire.BytesType)
			output = protowire.AppendBytes(output, replace(value))
			replaced = true
		} else {
			output = append(output, input[:fieldSize]...)
		}
		input = input[fieldSize:]
	}
	require.True(t, replaced)
	return output
}

func TestV2EquivalentTxBodyFieldOrder(t *testing.T) {
	f := fixtureV2(t)
	_ = f.build()
	msgAny, err := proto.Marshal(f.body.Messages[0])
	require.NoError(t, err)
	certAny, err := proto.Marshal(f.body.ExtensionOptions[0])
	require.NoError(t, err)
	body := protowire.AppendTag(nil, 2, protowire.BytesType)
	body = protowire.AppendString(body, f.body.Memo)
	body = protowire.AppendTag(body, 1023, protowire.BytesType)
	body = protowire.AppendBytes(body, certAny)
	body = protowire.AppendTag(body, 3, protowire.VarintType)
	body = protowire.AppendVarint(body, f.body.TimeoutHeight)
	body = protowire.AppendTag(body, 1, protowire.BytesType)
	body = protowire.AppendBytes(body, msgAny)
	f.raw.BodyBytes = body
	feeBytes, err := proto.Marshal(f.authInfo.Fee)
	require.NoError(t, err)
	signerBytes, err := proto.Marshal(f.authInfo.SignerInfos[0])
	require.NoError(t, err)
	auth := protowire.AppendTag(nil, 2, protowire.BytesType)
	auth = protowire.AppendBytes(auth, feeBytes)
	auth = protowire.AppendTag(auth, 1, protowire.BytesType)
	auth = protowire.AppendBytes(auth, signerBytes)
	f.raw.AuthInfoBytes = auth
	rawBytes, err := proto.Marshal(&f.raw)
	require.NoError(t, err)
	f.ctx = f.ctx.WithTxBytes(rawBytes)
	tx, err := f.codec.TxConfig.TxDecoder()(rawBytes)
	require.NoError(t, err)
	require.NoError(t, f.run(tx))
}

func TestV2RejectsOtherDirectMessages(t *testing.T) {
	for _, tt := range []struct {
		name string
		msg  sdk.Msg
	}{
		{"MsgMultiSend", &banktypes.MsgMultiSend{}},
		{"MsgExec", &authztypes.MsgExec{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := fixtureV2(t)
			_ = f.build()
			anyMsg, err := codectypes.NewAnyWithValue(tt.msg)
			require.NoError(t, err)
			f.body.Messages = []*codectypes.Any{anyMsg}
			f.raw.BodyBytes, err = proto.Marshal(&f.body)
			require.NoError(t, err)
			rawBytes, err := proto.Marshal(&f.raw)
			require.NoError(t, err)
			f.ctx = f.ctx.WithTxBytes(rawBytes)
			tx, err := f.codec.TxConfig.TxDecoder()(rawBytes)
			require.NoError(t, err)
			require.ErrorIs(t, f.run(tx), v2.ErrUnsupportedTxV2)
		})
	}
}

func TestV2RawCoinAmountCannotBeNormalized(t *testing.T) {
	f := fixtureV2(t)
	_ = f.build()
	coin := protowire.AppendTag(nil, 1, protowire.BytesType)
	coin = protowire.AppendString(coin, "token")
	coin = protowire.AppendTag(coin, 2, protowire.BytesType)
	coin = protowire.AppendString(coin, "01000")
	msgBytes := protowire.AppendTag(nil, 1, protowire.BytesType)
	msgBytes = protowire.AppendString(msgBytes, v2Subject)
	msgBytes = protowire.AppendTag(msgBytes, 2, protowire.BytesType)
	msgBytes = protowire.AppendString(msgBytes, v2Receiver)
	msgBytes = protowire.AppendTag(msgBytes, 3, protowire.BytesType)
	msgBytes = protowire.AppendBytes(msgBytes, coin)
	f.body.Messages[0].Value = msgBytes
	bodyBytes, err := proto.Marshal(&f.body)
	require.NoError(t, err)
	f.raw.BodyBytes = bodyBytes
	rawBytes, err := proto.Marshal(&f.raw)
	require.NoError(t, err)
	f.ctx = f.ctx.WithTxBytes(rawBytes)
	tx, err := f.codec.TxConfig.TxDecoder()(rawBytes)
	require.NoError(t, err)
	require.ErrorIs(t, f.run(tx), v2.ErrUnsupportedTxV2)
}

func TestV2RawFeeAmountCannotBeNormalized(t *testing.T) {
	f := fixtureV2(t)
	_ = f.build()
	f.raw.AuthInfoBytes = replaceFirstBytesField(t, f.raw.AuthInfoBytes, 2, func(fee []byte) []byte {
		return replaceFirstBytesField(t, fee, 1, func(coin []byte) []byte {
			return replaceFirstBytesField(t, coin, 2, func([]byte) []byte { return []byte("0100") })
		})
	})
	rawBytes, err := proto.Marshal(&f.raw)
	require.NoError(t, err)
	f.ctx = f.ctx.WithTxBytes(rawBytes)
	tx, err := f.codec.TxConfig.TxDecoder()(rawBytes)
	require.NoError(t, err)
	require.ErrorIs(t, f.run(tx), v2.ErrUnsupportedTxV2)
}
