package app

import (
	"crypto/ed25519"
	"crypto/sha256"
	"testing"

	"github.com/cosmos/cosmos-sdk/client"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	minttypes "github.com/cosmos/cosmos-sdk/x/mint/types"
	"github.com/stretchr/testify/require"

	"alpha/x/authzattrs/v2"
)

type v2AnteState struct {
	sequence uint64
	stake    sdk.Coin
	sender   sdk.Coin
	receiver sdk.Coin
}

func (f *v2AppAnteFixture) negativePathState() v2AnteState {
	return v2AnteState{
		sequence: f.sequence(), stake: f.stake(),
		sender:   f.app.BankKeeper.GetBalance(f.ctx, f.subject, "token"),
		receiver: f.app.BankKeeper.GetBalance(f.ctx, f.receiver, "token"),
	}
}

func (f *v2AppAnteFixture) fundNegativePathSender() {
	f.t.Helper()
	coins := sdk.NewCoins(sdk.NewInt64Coin("token", 10000))
	require.NoError(f.t, f.app.BankKeeper.MintCoins(f.ctx, minttypes.ModuleName, coins))
	require.NoError(f.t, f.app.BankKeeper.SendCoinsFromModuleToAccount(f.ctx, minttypes.ModuleName, f.subject, coins))
}

func runDecodedV2Ante(t *testing.T, f *v2AppAnteFixture, raw []byte) (sdk.Context, error) {
	t.Helper()
	tx, err := f.app.TxConfig().TxDecoder()(raw)
	require.NoError(t, err) // These cases reach real application Ante after SDK decode.
	return f.run(tx, raw, false, false)
}

func requireNoV2AllowEvent(t *testing.T, ctx sdk.Context) {
	t.Helper()
	for _, event := range ctx.EventManager().Events() {
		require.NotEqual(t, "authz_v2_decision", event.Type)
	}
}

func requireRejectedV2Ante(t *testing.T, f *v2AppAnteFixture, raw []byte, want error) {
	t.Helper()
	before := f.negativePathState()
	ctx, err := runDecodedV2Ante(t, f, raw)
	require.ErrorIs(t, err, want)
	require.Equal(t, before, f.negativePathState())
	requireNoV2AllowEvent(t, ctx)
}

func TestV2NegativeTransactionPaths(t *testing.T) {
	t.Run("VALID_V2_CONTROL", func(t *testing.T) {
		f := newV2AppAnteFixture(t)
		f.fundNegativePathSender()
		_, raw := f.signedTx(f.certificate, 0, nil)
		before := f.negativePathState()
		ctx, err := runDecodedV2Ante(t, f, raw)
		require.NoError(t, err)
		require.Equal(t, uint64(1), f.sequence())
		require.Equal(t, before.sender, f.app.BankKeeper.GetBalance(f.ctx, f.subject, "token"))
		require.Equal(t, before.receiver, f.app.BankKeeper.GetBalance(f.ctx, f.receiver, "token"))
		var allow int
		for _, event := range ctx.EventManager().Events() {
			if event.Type == "authz_v2_decision" {
				allow++
			}
		}
		require.Equal(t, 1, allow)
	})

	t.Run("MALFORMED_V2_EXTENSION", func(t *testing.T) {
		f := newV2AppAnteFixture(t)
		f.fundNegativePathSender()
		f.installV1Grant() // Invalid V2 must not fall back to this usable V1 grant.
		malformed := f.newCertificate(0)
		malformed.SignDoc.Intent = nil
		_, raw := f.signedTx(malformed, 0, nil)
		requireRejectedV2Ante(t, f, raw, v2.ErrInvalidCertificateV2)
	})

	t.Run("DUPLICATE_V2_EXTENSION", func(t *testing.T) {
		f := newV2AppAnteFixture(t)
		f.fundNegativePathSender()
		f.installV1Grant()
		_, raw := f.signedTx(f.certificate, 0, func(builder client.TxBuilder) {
			option, err := codectypes.NewAnyWithValue(f.certificate)
			require.NoError(t, err)
			builder.(client.ExtendedTxBuilder).SetExtensionOptions(option, option)
		})
		requireRejectedV2Ante(t, f, raw, v2.ErrMalformedExtensionV2)
	})

	t.Run("EXPIRED_CERTIFICATE", func(t *testing.T) {
		f := newV2AppAnteFixture(t)
		f.fundNegativePathSender()
		f.installV1Grant()
		certificate := f.newCertificate(0)
		certificate.SignDoc.ValidUntilHeight = 104 // Ante height is 105.
		signBytes, _, err := v2.CanonicalCertificateSignBytesV2(certificate.SignDoc, f.app.AuthKeeper.AddressCodec())
		require.NoError(t, err)
		for i, signature := range certificate.Signatures {
			signature.Signature = ed25519.Sign(f.issuerKeys[i], signBytes)
		}
		_, raw := f.signedTx(certificate, 0, nil) // Wallet signs the final expired-certificate transaction.
		requireRejectedV2Ante(t, f, raw, v2.ErrExpiredV2)
	})

	t.Run("EXACT_RAW_TX_REPLAY", func(t *testing.T) {
		f := newV2AppAnteFixture(t)
		f.fundNegativePathSender()
		_, raw := f.signedTx(f.certificate, 0, nil)
		_, err := runDecodedV2Ante(t, f, raw)
		require.NoError(t, err)
		require.Equal(t, uint64(1), f.sequence())
		requireRejectedV2Ante(t, f, raw, sdkerrors.ErrWrongSequence)
	})

	t.Run("STALE_CERTIFICATE_IN_FRESH_TX", func(t *testing.T) {
		f := newV2AppAnteFixture(t)
		f.fundNegativePathSender()
		_, raw := f.signedTx(f.certificate, 0, nil)
		_, err := runDecodedV2Ante(t, f, raw)
		require.NoError(t, err)
		require.Equal(t, uint64(1), f.sequence())
		f.installV1Grant()
		_, freshRaw := f.signedTx(f.certificate, 1, nil) // Fresh wallet signature; issuer-signed intent still binds sequence 0.
		requireRejectedV2Ante(t, f, freshRaw, v2.ErrIntentMismatchV2)
	})
}

func TestV2IssuerTrustNegativePaths(t *testing.T) {
	t.Run("INVALID_ISSUER_SIGNATURE", func(t *testing.T) {
		f := newV2AppAnteFixture(t)
		f.fundNegativePathSender()
		certificate := f.newCertificate(0)
		certificate.Signatures[0].Signature[0] ^= 1 // Known issuer, raw 64-byte signature, invalid cryptography only.
		require.Len(t, certificate.Signatures[0].Signature, ed25519.SignatureSize)
		_, raw := f.signedTx(certificate, 0, nil)
		requireRejectedV2Ante(t, f, raw, v2.ErrBadSignatureV2)
	})

	t.Run("INSUFFICIENT_QUORUM", func(t *testing.T) {
		f := newV2AppAnteFixture(t)
		f.fundNegativePathSender()
		certificate := f.newCertificate(0)
		certificate.Signatures = certificate.Signatures[:1] // issuer-alpha weight 2; threshold 5.
		signBytes, _, err := v2.CanonicalCertificateSignBytesV2(certificate.SignDoc, f.app.AuthKeeper.AddressCodec())
		require.NoError(t, err)
		require.True(t, ed25519.Verify(f.issuerKeys[0].Public().(ed25519.PublicKey), signBytes, certificate.Signatures[0].Signature))
		_, raw := f.signedTx(certificate, 0, nil)
		requireRejectedV2Ante(t, f, raw, v2.ErrQuorumNotMetV2)
	})

	t.Run("UNKNOWN_ISSUER", func(t *testing.T) {
		f := newV2AppAnteFixture(t)
		f.fundNegativePathSender()
		certificate := f.newCertificate(0)
		seed := sha256.Sum256([]byte("v2 unknown issuer test fixture only"))
		unknownKey := ed25519.NewKeyFromSeed(seed[:]) // TEST-ONLY deterministic key.
		signBytes, _, err := v2.CanonicalCertificateSignBytesV2(certificate.SignDoc, f.app.AuthKeeper.AddressCodec())
		require.NoError(t, err)
		certificate.Signatures[1].IssuerId = "issuer-unknown"
		certificate.Signatures[1].Signature = ed25519.Sign(unknownKey, signBytes)
		require.True(t, ed25519.Verify(unknownKey.Public().(ed25519.PublicKey), signBytes, certificate.Signatures[1].Signature))
		_, raw := f.signedTx(certificate, 0, nil)
		requireRejectedV2Ante(t, f, raw, v2.ErrUnknownIssuerV2)
	})

	t.Run("POLICY_METADATA_MISMATCH", func(t *testing.T) {
		f := newV2AppAnteFixture(t)
		f.fundNegativePathSender()
		certificate := f.newCertificate(0)
		certificate.SignDoc.PolicyId = "policy-other" // No CurrentIssuerSet for this signed policy.
		signBytes, _, err := v2.CanonicalCertificateSignBytesV2(certificate.SignDoc, f.app.AuthKeeper.AddressCodec())
		require.NoError(t, err)
		for i, signature := range certificate.Signatures {
			signature.Signature = ed25519.Sign(f.issuerKeys[i], signBytes)
			require.True(t, ed25519.Verify(f.issuerKeys[i].Public().(ed25519.PublicKey), signBytes, signature.Signature))
		}
		_, raw := f.signedTx(certificate, 0, nil)
		requireRejectedV2Ante(t, f, raw, v2.ErrStaleIssuerSetV2)
	})

	t.Run("INACTIVE_ISSUER", func(t *testing.T) {
		f := newV2AppAnteFixture(t)
		f.fundNegativePathSender()
		issuer, found, err := f.app.AuthzAttrsKeeper.GetIssuer(f.ctx, 9, "issuer-beta")
		require.NoError(t, err)
		require.True(t, found)
		issuer.Active = false
		require.NoError(t, f.app.AuthzAttrsKeeper.SetIssuer(f.ctx, issuer))
		_, raw := f.signedTx(f.newCertificate(0), 0, nil)
		requireRejectedV2Ante(t, f, raw, v2.ErrIssuerInactiveV2)
	})
}
