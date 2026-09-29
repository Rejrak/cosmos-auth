package ante

import (
	"bytes"
	"context"
	"fmt"
	"math/bits"
	"strings"

	"cosmossdk.io/core/address"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/codec/unknownproto"
	cryptomultisig "github.com/cosmos/cosmos-sdk/crypto/types/multisig"
	sdk "github.com/cosmos/cosmos-sdk/types"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authante "github.com/cosmos/cosmos-sdk/x/auth/ante"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/cosmos/gogoproto/proto"
	"google.golang.org/protobuf/encoding/protowire"

	"alpha/x/authzattrs/keeper"
	"alpha/x/authzattrs/v2"
)

// V2TxRoute is only a classification. A V1 route is not an authorization grant.
type V2TxRoute uint8

const (
	V1Route V2TxRoute = iota
	V2Route
	InvalidV2Route
)

// ClassifyV2Transaction is reusable by the future application Ante routing.
// An invalid presentation cannot fall back to V1.
func ClassifyV2Transaction(tx sdk.Tx) V2TxRoute {
	if tx == nil {
		return InvalidV2Route
	}
	extensions, ok := tx.(authante.HasExtensionOptionsTx)
	if !ok {
		return V1Route
	}
	return classifyV2Options(extensions.GetExtensionOptions(), extensions.GetNonCriticalExtensionOptions())
}

func classifyV2Options(critical, nonCritical []*codectypes.Any) V2TxRoute {
	for _, option := range nonCritical {
		// A different Any prefix can still name the V2 protobuf type. It is
		// never a way to present the certificate as a non-critical V1 option.
		if option != nil && (option.TypeUrl == strings.TrimPrefix(v2.CertificateTypeURLV2, "/") || strings.HasSuffix(option.TypeUrl, v2.CertificateTypeURLV2)) {
			return InvalidV2Route
		}
	}
	if len(critical) == 0 {
		return V1Route
	}
	if len(critical) != 1 || critical[0] == nil || critical[0].TypeUrl != v2.CertificateTypeURLV2 || len(nonCritical) != 0 {
		return InvalidV2Route
	}
	return V2Route
}

// V2ExtensionOptionChecker is the exact-type admission predicate for V2.1b2.
// It does not validate cardinality, payload, transaction shape or issuer trust.
func V2ExtensionOptionChecker(option *codectypes.Any) bool {
	return option != nil && option.TypeUrl == v2.CertificateTypeURLV2
}

type V2AccountKeeper interface {
	GetAccount(context.Context, sdk.AccAddress) sdk.AccountI
	GetParams(context.Context) authtypes.Params
	AddressCodec() address.Codec
}

// V2CertificateDecorator belongs after SDK SigVerificationDecorator and before
// IncrementSequenceDecorator, inside SetUpContextDecorator's recovery/gas scope.
// V2.1b1 defines it but does not install it into the application.
type V2CertificateDecorator struct {
	keeper   keeper.Keeper
	accounts V2AccountKeeper
	codec    codec.Codec
}

func NewV2CertificateDecorator(k keeper.Keeper, accounts V2AccountKeeper, cdc codec.Codec) V2CertificateDecorator {
	return V2CertificateDecorator{keeper: k, accounts: accounts, codec: cdc}
}

func (d V2CertificateDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (sdk.Context, error) {
	switch ClassifyV2Transaction(tx) {
	case V1Route:
		return next(ctx, tx, simulate)
	case InvalidV2Route:
		return ctx, v2.ErrMalformedExtensionV2
	default:
		if err := d.VerifyV2Transaction(ctx, tx); err != nil {
			return ctx, err
		}
		return next(ctx, tx, simulate)
	}
}

// VerifyV2Transaction validates the final transaction's raw and decoded
// semantics, then delegates issuer/quorum verification to the V2 keeper.
func (d V2CertificateDecorator) VerifyV2Transaction(ctx sdk.Context, tx sdk.Tx) error {
	if ClassifyV2Transaction(tx) != V2Route || d.codec == nil || d.accounts == nil {
		return v2.ErrMalformedExtensionV2
	}
	rawBytes := ctx.TxBytes()
	if len(rawBytes) == 0 {
		return v2.ErrInvalidRawTxV2
	}
	params := d.accounts.GetParams(ctx)
	hi, rawGas := bits.Mul64(uint64(len(rawBytes)), params.TxSizeCostPerByte)
	if hi != 0 {
		panic(storetypes.ErrorGasOverflow{Descriptor: "v2 strict raw validation"})
	}
	ctx.GasMeter().ConsumeGas(rawGas, "v2 strict raw validation")
	registry := d.codec.InterfaceRegistry()
	var raw txtypes.TxRaw
	if err := unknownproto.RejectUnknownFieldsStrict(rawBytes, &raw, registry); err != nil {
		return fmt.Errorf("%w: TxRaw: %v", v2.ErrInvalidRawTxV2, err)
	}
	if err := proto.Unmarshal(rawBytes, &raw); err != nil || len(raw.BodyBytes) == 0 || len(raw.AuthInfoBytes) == 0 {
		return v2.ErrInvalidRawTxV2
	}
	var body txtypes.TxBody
	if err := proto.Unmarshal(raw.BodyBytes, &body); err != nil {
		return fmt.Errorf("%w: TxBody: %v", v2.ErrInvalidRawTxV2, err)
	}
	if classifyV2Options(body.ExtensionOptions, body.NonCriticalExtensionOptions) != V2Route {
		return v2.ErrMalformedExtensionV2
	}
	option := body.ExtensionOptions[0]
	if len(option.Value) == 0 || len(option.Value) > v2.MaxCertificateBytesV2 {
		return v2.ErrMalformedExtensionV2
	}
	// SDK DefaultTxDecoder already enforces ADR-027 on TxRaw. Strict traversal
	// additionally rejects the non-critical body fields it otherwise permits,
	// including unknown fields nested inside MsgSend and certificate Any values.
	if err := unknownproto.RejectUnknownFieldsStrict(raw.BodyBytes, &body, registry); err != nil {
		return fmt.Errorf("%w: TxBody: %v", v2.ErrInvalidRawTxV2, err)
	}
	var authInfo txtypes.AuthInfo
	if err := unknownproto.RejectUnknownFieldsStrict(raw.AuthInfoBytes, &authInfo, registry); err != nil {
		return fmt.Errorf("%w: AuthInfo: %v", v2.ErrInvalidRawTxV2, err)
	}
	if err := proto.Unmarshal(raw.AuthInfoBytes, &authInfo); err != nil {
		return fmt.Errorf("%w: AuthInfo: %v", v2.ErrInvalidRawTxV2, err)
	}
	var certificate v2.AuthorizationCertificateV2
	if err := proto.Unmarshal(option.Value, &certificate); err != nil {
		return fmt.Errorf("%w: certificate: %v", v2.ErrMalformedExtensionV2, err)
	}
	if certificate.SignDoc == nil || certificate.SignDoc.Intent == nil {
		return v2.ErrInvalidCertificateV2
	}
	if len(body.Messages) != 1 || body.Messages[0] == nil || body.Messages[0].TypeUrl != "/cosmos.bank.v1beta1.MsgSend" ||
		body.Unordered || (body.TimeoutTimestamp != nil && !body.TimeoutTimestamp.IsZero()) ||
		len(authInfo.SignerInfos) != 1 || authInfo.SignerInfos[0] == nil || len(raw.Signatures) != 1 || len(raw.Signatures[0]) == 0 ||
		authInfo.Fee == nil || authInfo.Fee.Payer != "" || authInfo.Fee.Granter != "" || authInfo.Tip != nil {
		return v2.ErrUnsupportedTxV2
	}
	info := authInfo.SignerInfos[0]
	if info.ModeInfo == nil || info.ModeInfo.GetSingle() == nil || info.ModeInfo.GetSingle().Mode != signing.SignMode_SIGN_MODE_DIRECT {
		return v2.ErrUnsupportedTxV2
	}
	var msg banktypes.MsgSend
	if err := proto.Unmarshal(body.Messages[0].Value, &msg); err != nil || len(msg.Amount) != 1 || msg.Amount[0].Amount.IsNil() || !msg.Amount[0].Amount.IsPositive() {
		return v2.ErrUnsupportedTxV2
	}
	if err := validateRawCoinAmounts(body.Messages[0].Value, raw.AuthInfoBytes, &msg, authInfo.Fee); err != nil {
		return err
	}
	sigTx, ok := tx.(authsigning.SigVerifiableTx)
	if !ok {
		return v2.ErrUnsupportedTxV2
	}
	signers, err := sigTx.GetSigners()
	if err != nil || len(signers) != 1 {
		return v2.ErrUnsupportedTxV2
	}
	subjectBytes, err := d.accounts.AddressCodec().StringToBytes(msg.FromAddress)
	if err != nil || !bytes.Equal(signers[0], subjectBytes) {
		return v2.ErrUnsupportedTxV2
	}
	account := d.accounts.GetAccount(ctx, sdk.AccAddress(signers[0]))
	if account == nil {
		return v2.ErrUnsupportedTxV2
	}
	if _, multisig := account.GetPubKey().(cryptomultisig.PubKey); multisig {
		return v2.ErrUnsupportedTxV2
	}
	fees := make([]*v2.FeeCoinV2, len(authInfo.Fee.Amount))
	for i, coin := range authInfo.Fee.Amount {
		if coin.Amount.IsNil() {
			return v2.ErrUnsupportedTxV2
		}
		fees[i] = &v2.FeeCoinV2{Denom: coin.Denom, Amount: coin.Amount.String()}
	}
	intent := &v2.AuthorizationIntentV2{
		ChainId: ctx.ChainID(), Subject: msg.FromAddress, Receiver: msg.ToAddress,
		Denom: msg.Amount[0].Denom, Amount: msg.Amount[0].Amount.String(),
		AccountNumber: account.GetAccountNumber(), Sequence: info.Sequence,
		TimeoutHeight: body.TimeoutHeight, Memo: body.Memo,
		FeeAmount: fees, GasLimit: authInfo.Fee.GasLimit,
	}
	// Canonicalization validates transfer/fee semantics. Require the actual fee
	// ordering to already be canonical, rather than silently changing the tx.
	canonical, err := v2.CanonicalizeCertificateSignDocV2(&v2.AuthorizationCertificateSignDocV2{
		Domain: certificate.SignDoc.Domain, Intent: intent,
		PolicyId: certificate.SignDoc.PolicyId, PolicyVersion: certificate.SignDoc.PolicyVersion,
		PolicyHash: certificate.SignDoc.PolicyHash, IssuerSetId: certificate.SignDoc.IssuerSetId,
		ValidFromHeight: certificate.SignDoc.ValidFromHeight, ValidUntilHeight: certificate.SignDoc.ValidUntilHeight,
	}, d.accounts.AddressCodec())
	if err != nil || !proto.Equal(canonical.Intent, intent) {
		return v2.ErrUnsupportedTxV2
	}
	if certificate.SignDoc.Intent.ChainId != ctx.ChainID() {
		return v2.ErrChainIDMismatchV2
	}
	if !proto.Equal(intent, certificate.SignDoc.Intent) {
		return v2.ErrIntentMismatchV2
	}
	if len(certificate.Signatures) > 0 && len(certificate.Signatures) <= v2.MaxSignaturesV2 {
		for range certificate.Signatures {
			ctx.GasMeter().ConsumeGas(params.SigVerifyCostED25519, "v2 issuer Ed25519 verification")
		}
	}
	_, _, err = d.keeper.VerifyCertificateV2(ctx, ctx.BlockHeight(), ctx.ChainID(), &certificate)
	return err
}

// SDK's Coin.Unmarshal parses amount into math.Int, losing lexical details
// such as leading zeros. Check the original known Coin.amount fields before
// comparing semantic values; strict unknownproto validation runs above.
func validateRawCoinAmounts(msgBytes, authInfoBytes []byte, msg *banktypes.MsgSend, fee *txtypes.Fee) error {
	msgCoins, err := byteFields(msgBytes, 3)
	if err != nil || len(msgCoins) != 1 {
		return v2.ErrInvalidRawTxV2
	}
	amounts, err := byteFields(msgCoins[0], 2)
	if err != nil || len(amounts) != 1 || string(amounts[0]) != msg.Amount[0].Amount.String() {
		return v2.ErrUnsupportedTxV2
	}
	feeFields, err := byteFields(authInfoBytes, 2)
	if err != nil || len(feeFields) != 1 {
		return v2.ErrInvalidRawTxV2
	}
	feeCoins, err := byteFields(feeFields[0], 1)
	if err != nil || len(feeCoins) != len(fee.Amount) {
		return v2.ErrInvalidRawTxV2
	}
	for i, coinBytes := range feeCoins {
		amounts, err := byteFields(coinBytes, 2)
		if err != nil || len(amounts) != 1 || fee.Amount[i].Amount.IsNil() || string(amounts[0]) != fee.Amount[i].Amount.String() {
			return v2.ErrUnsupportedTxV2
		}
	}
	return nil
}

// byteFields keeps wire order and accepts legal field ordering/varint forms.
func byteFields(input []byte, field protowire.Number) ([][]byte, error) {
	var values [][]byte
	for len(input) > 0 {
		number, wireType, tagSize := protowire.ConsumeTag(input)
		if tagSize < 0 {
			return nil, protowire.ParseError(tagSize)
		}
		input = input[tagSize:]
		if number == field && wireType == protowire.BytesType {
			value, size := protowire.ConsumeBytes(input)
			if size < 0 {
				return nil, protowire.ParseError(size)
			}
			values = append(values, value)
			input = input[size:]
			continue
		}
		size := protowire.ConsumeFieldValue(number, wireType, input)
		if size < 0 {
			return nil, protowire.ParseError(size)
		}
		input = input[size:]
	}
	return values, nil
}
