package v2

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"

	"cosmossdk.io/core/address"
	addresscodec "github.com/cosmos/cosmos-sdk/codec/address"
	"github.com/cosmos/gogoproto/proto"
	"github.com/stretchr/testify/require"
)

const (
	goldenSignBytesV2 = "0a1f616c7068612e617574687a61747472732e63657274696669636174652e76321297010a07616c7068612d31122d636f736d6f733164757a70786b753561746d3938716b3679777667646a7a6e3530797a763930713763337234341a2d636f736d6f7331737365766e646c6739393761383977707732777639786a32766168687163797430676d6c38342205746f6b656e2a04313030303007380340734a09763220676f6c64656e520c0a057374616b65120331303058c09a0c1a10706f6c6963792d62616e6b2d73656e6420022a205ad8c4fa036c6238f322b3bfc2c012f0f12d9c6af391ba9d26acfe08a1d01d1330093864406e"
	goldenDigestV2    = "23d2bdf82cc29dafa3ff0ff8a42e74dc1b88864632a69cca8f9d7055387e844b"
)

func testCodecV2() address.Codec { return addresscodec.NewBech32Codec("cosmos") }

func goldenDocV2(t *testing.T) *AuthorizationCertificateSignDocV2 {
	t.Helper()
	policyHash, err := hex.DecodeString("5ad8c4fa036c6238f322b3bfc2c012f0f12d9c6af391ba9d26acfe08a1d01d13")
	require.NoError(t, err)
	return &AuthorizationCertificateSignDocV2{
		Domain: CertificateDomainV2,
		Intent: &AuthorizationIntentV2{
			ChainId: "alpha-1", Subject: "cosmos1duzpxku5atm98qk6ywvgdjzn50yzv90q7c3r44",
			Receiver: "cosmos1ssevndlg997a89wpw2wv9xj2vahhqcyt0gml84",
			Denom:    "token", Amount: "1000", AccountNumber: 7, Sequence: 3,
			TimeoutHeight: 115, Memo: "v2 golden", FeeAmount: []*FeeCoinV2{{Denom: "stake", Amount: "100"}},
			GasLimit: 200000,
		},
		PolicyId: "policy-bank-send", PolicyVersion: 2, PolicyHash: policyHash,
		IssuerSetId: 9, ValidFromHeight: 100, ValidUntilHeight: 110,
	}
}

func decodeHexV2(t *testing.T, value string) []byte {
	t.Helper()
	bz, err := hex.DecodeString(value)
	require.NoError(t, err)
	return bz
}

func TestCertificateGoldenVectorV2(t *testing.T) {
	doc := goldenDocV2(t) // Built from logical fields, never from expected bytes.
	signBytes, digest, err := CanonicalCertificateSignBytesV2(doc, testCodecV2())
	require.NoError(t, err)
	require.Equal(t, goldenSignBytesV2, hex.EncodeToString(signBytes))
	require.Equal(t, goldenDigestV2, hex.EncodeToString(digest[:]))
	for _, issuer := range []struct{ public, signature string }{
		{"03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8", "b1bea693676fc45cbc80c3cf2127166238d3289466166ab3630a684e6f7bb1d800601459bb212a98d2d0b8c1f5a96e359744b1e1ce8a0430298d61dd334d6b0d"},
		{"29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7", "02d446a06af1329d2dba3e752a6f0689d9625c8e46a6f55b2ee4809becf1c1e133d6ad7b0196f9b15df653c97679a81250912525f88df0c39a99b4fa3efc4008"},
	} {
		public, signature := decodeHexV2(t, issuer.public), decodeHexV2(t, issuer.signature)
		require.Len(t, public, ed25519.PublicKeySize)
		require.Len(t, signature, ed25519.SignatureSize)
		require.True(t, ed25519.Verify(public, signBytes, signature))
		require.False(t, ed25519.Verify(public, digest[:], signature))
		tampered := append([]byte(nil), signBytes...)
		tampered[0] ^= 1
		require.False(t, ed25519.Verify(public, tampered, signature))
	}
}

func TestCanonicalCertificateSignDocV2(t *testing.T) {
	codec := testCodecV2()
	t.Run("detached sorted fee fields", func(t *testing.T) {
		doc := goldenDocV2(t)
		doc.Intent.FeeAmount = []*FeeCoinV2{{Denom: "token", Amount: "0"}, {Denom: "stake", Amount: "100"}}
		canonical, err := CanonicalizeCertificateSignDocV2(doc, codec)
		require.NoError(t, err)
		require.Equal(t, "stake", canonical.Intent.FeeAmount[0].Denom)
		require.Equal(t, "token", doc.Intent.FeeAmount[0].Denom)
		doc.Intent.FeeAmount[1].Amount = "999"
		doc.PolicyHash[0] ^= 1
		require.Equal(t, "100", canonical.Intent.FeeAmount[0].Amount)
		require.Equal(t, byte(0x5a), canonical.PolicyHash[0])
	})
	t.Run("unknown fields do not enter sign bytes", func(t *testing.T) {
		original, _, err := CanonicalCertificateSignBytesV2(goldenDocV2(t), codec)
		require.NoError(t, err)
		wire := append(append([]byte(nil), original...), 0x98, 0x06, 0x01) // unknown field 99
		var received AuthorizationCertificateSignDocV2
		require.NoError(t, proto.Unmarshal(wire, &received))
		actual, _, err := CanonicalCertificateSignBytesV2(&received, codec)
		require.NoError(t, err)
		require.Equal(t, original, actual)
	})
	tests := []struct {
		name   string
		change func(*AuthorizationCertificateSignDocV2)
		want   error
	}{
		{"bad domain", func(d *AuthorizationCertificateSignDocV2) { d.Domain = "other" }, ErrBadDomainV2},
		{"nil intent", func(d *AuthorizationCertificateSignDocV2) { d.Intent = nil }, ErrInvalidCertificateV2},
		{"empty chain", func(d *AuthorizationCertificateSignDocV2) { d.Intent.ChainId = "" }, ErrInvalidCertificateV2},
		{"bad subject", func(d *AuthorizationCertificateSignDocV2) { d.Intent.Subject = "INVALID" }, ErrInvalidCertificateV2},
		{"bad receiver", func(d *AuthorizationCertificateSignDocV2) { d.Intent.Receiver = "INVALID" }, ErrInvalidCertificateV2},
		{"bad denom", func(d *AuthorizationCertificateSignDocV2) { d.Intent.Denom = "?" }, ErrInvalidCertificateV2},
		{"zero amount", func(d *AuthorizationCertificateSignDocV2) { d.Intent.Amount = "0" }, ErrInvalidCertificateV2},
		{"noncanonical amount", func(d *AuthorizationCertificateSignDocV2) { d.Intent.Amount = "01000" }, ErrInvalidCertificateV2},
		{"short hash", func(d *AuthorizationCertificateSignDocV2) { d.PolicyHash = d.PolicyHash[:31] }, ErrInvalidCertificateV2},
		{"bad window", func(d *AuthorizationCertificateSignDocV2) { d.ValidUntilHeight = 99 }, ErrInvalidCertificateV2},
		{"zero from height", func(d *AuthorizationCertificateSignDocV2) { d.ValidFromHeight = 0 }, ErrInvalidCertificateV2},
		{"duplicate fee", func(d *AuthorizationCertificateSignDocV2) {
			d.Intent.FeeAmount = append(d.Intent.FeeAmount, &FeeCoinV2{Denom: "stake", Amount: "1"})
		}, ErrInvalidCertificateV2},
		{"too many fees", func(d *AuthorizationCertificateSignDocV2) {
			d.Intent.FeeAmount = []*FeeCoinV2{{Denom: "aa", Amount: "1"}, {Denom: "bb", Amount: "1"}, {Denom: "cc", Amount: "1"}, {Denom: "dd", Amount: "1"}, {Denom: "ee", Amount: "1"}}
		}, ErrInvalidCertificateV2},
		{"bad fee amount", func(d *AuthorizationCertificateSignDocV2) { d.Intent.FeeAmount[0].Amount = "01" }, ErrInvalidCertificateV2},
		{"negative fee", func(d *AuthorizationCertificateSignDocV2) { d.Intent.FeeAmount[0].Amount = "-1" }, ErrInvalidCertificateV2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := goldenDocV2(t)
			tt.change(doc)
			_, err := CanonicalizeCertificateSignDocV2(doc, codec)
			require.ErrorIs(t, err, tt.want)
		})
	}
}

func TestCertificateStructureV2(t *testing.T) {
	valid := func() *AuthorizationCertificateV2 {
		return &AuthorizationCertificateV2{SignDoc: goldenDocV2(t), Signatures: []*IssuerSignatureV2{{IssuerId: "a", Signature: make([]byte, 64)}}}
	}
	for _, tt := range []struct {
		name   string
		change func(*AuthorizationCertificateV2)
		want   error
	}{
		{"missing doc", func(c *AuthorizationCertificateV2) { c.SignDoc = nil }, ErrInvalidCertificateV2},
		{"zero signatures", func(c *AuthorizationCertificateV2) { c.Signatures = nil }, ErrInvalidCertificateV2},
		{"too many signatures", func(c *AuthorizationCertificateV2) {
			for i := 0; i < 16; i++ {
				c.Signatures = append(c.Signatures, &IssuerSignatureV2{IssuerId: string(rune('b' + i)), Signature: make([]byte, 64)})
			}
		}, ErrInvalidCertificateV2},
		{"duplicate issuer", func(c *AuthorizationCertificateV2) {
			c.Signatures = append(c.Signatures, &IssuerSignatureV2{IssuerId: "a", Signature: make([]byte, 64)})
		}, ErrDuplicateSignatureV2},
		{"empty issuer", func(c *AuthorizationCertificateV2) { c.Signatures[0].IssuerId = "" }, ErrBadSignatureV2},
		{"short signature", func(c *AuthorizationCertificateV2) { c.Signatures[0].Signature = make([]byte, 63) }, ErrBadSignatureV2},
		{"oversize", func(c *AuthorizationCertificateV2) { c.SignDoc.Intent.Memo = strings.Repeat("x", 5000) }, ErrInvalidCertificateV2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			certificate := valid()
			tt.change(certificate)
			_, _, err := ValidateCertificateV2(certificate, testCodecV2())
			require.ErrorIs(t, err, tt.want)
		})
	}
}
