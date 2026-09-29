package keeper_test

import (
	"encoding/hex"
	"math"
	"testing"

	"cosmossdk.io/collections"
	"github.com/stretchr/testify/require"

	"alpha/x/authzattrs/types"
	"alpha/x/authzattrs/v2"
)

const v2GoldenDigest = "23d2bdf82cc29dafa3ff0ff8a42e74dc1b88864632a69cca8f9d7055387e844b"

func v2Hex(t testing.TB, value string) []byte {
	t.Helper()
	bz, err := hex.DecodeString(value)
	require.NoError(t, err)
	return bz
}

func v2GoldenCertificate(t testing.TB) (*v2.AuthorizationCertificateV2, []types.Issuer) {
	t.Helper()
	certificate := &v2.AuthorizationCertificateV2{
		SignDoc: &v2.AuthorizationCertificateSignDocV2{
			Domain: v2.CertificateDomainV2,
			Intent: &v2.AuthorizationIntentV2{
				ChainId: "alpha-1", Subject: "cosmos1duzpxku5atm98qk6ywvgdjzn50yzv90q7c3r44",
				Receiver: "cosmos1ssevndlg997a89wpw2wv9xj2vahhqcyt0gml84",
				Denom:    "token", Amount: "1000", AccountNumber: 7, Sequence: 3,
				TimeoutHeight: 115, Memo: "v2 golden", FeeAmount: []*v2.FeeCoinV2{{Denom: "stake", Amount: "100"}},
				GasLimit: 200000,
			},
			PolicyId: "policy-bank-send", PolicyVersion: 2,
			PolicyHash:  v2Hex(t, "5ad8c4fa036c6238f322b3bfc2c012f0f12d9c6af391ba9d26acfe08a1d01d13"),
			IssuerSetId: 9, ValidFromHeight: 100, ValidUntilHeight: 110,
		},
		Signatures: []*v2.IssuerSignatureV2{
			{IssuerId: "issuer-alpha", Signature: v2Hex(t, "b1bea693676fc45cbc80c3cf2127166238d3289466166ab3630a684e6f7bb1d800601459bb212a98d2d0b8c1f5a96e359744b1e1ce8a0430298d61dd334d6b0d")},
			{IssuerId: "issuer-beta", Signature: v2Hex(t, "02d446a06af1329d2dba3e752a6f0689d9625c8e46a6f55b2ee4809becf1c1e133d6ad7b0196f9b15df653c97679a81250912525f88df0c39a99b4fa3efc4008")},
		},
	}
	issuers := []types.Issuer{
		{IssuerSetId: 9, IssuerId: "issuer-alpha", KeyType: types.IssuerKeyType_ISSUER_KEY_TYPE_ED25519, PublicKey: v2Hex(t, "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"), Weight: 2, Active: true, ValidFromHeight: 100, ValidUntilHeight: 110},
		{IssuerSetId: 9, IssuerId: "issuer-beta", KeyType: types.IssuerKeyType_ISSUER_KEY_TYPE_ED25519, PublicKey: v2Hex(t, "29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7"), Weight: 3, Active: true, ValidFromHeight: 100, ValidUntilHeight: 110},
	}
	return certificate, issuers
}

func TestVerifyCertificateV2(t *testing.T) {
	tests := []struct {
		name   string
		change func(*v2.AuthorizationCertificateV2, *types.IssuerSet, []types.Issuer, *uint64, *int64, *string)
		want   error
	}{
		{name: "golden"},
		{name: "reversed signature order", change: func(c *v2.AuthorizationCertificateV2, _ *types.IssuerSet, _ []types.Issuer, _ *uint64, _ *int64, _ *string) {
			c.Signatures[0], c.Signatures[1] = c.Signatures[1], c.Signatures[0]
		}},
		{name: "lower inclusive height", change: func(_ *v2.AuthorizationCertificateV2, _ *types.IssuerSet, _ []types.Issuer, _ *uint64, h *int64, _ *string) {
			*h = 100
		}},
		{name: "upper inclusive height", change: func(_ *v2.AuthorizationCertificateV2, _ *types.IssuerSet, _ []types.Issuer, _ *uint64, h *int64, _ *string) {
			*h = 110
		}},
		{name: "not yet valid", want: v2.ErrNotYetValidV2, change: func(_ *v2.AuthorizationCertificateV2, _ *types.IssuerSet, _ []types.Issuer, _ *uint64, h *int64, _ *string) {
			*h = 99
		}},
		{name: "expired", want: v2.ErrExpiredV2, change: func(_ *v2.AuthorizationCertificateV2, _ *types.IssuerSet, _ []types.Issuer, _ *uint64, h *int64, _ *string) {
			*h = 111
		}},
		{name: "wrong chain", want: v2.ErrChainIDMismatchV2, change: func(_ *v2.AuthorizationCertificateV2, _ *types.IssuerSet, _ []types.Issuer, _ *uint64, _ *int64, chain *string) {
			*chain = "wrong"
		}},
		{name: "bad domain", want: v2.ErrBadDomainV2, change: func(c *v2.AuthorizationCertificateV2, _ *types.IssuerSet, _ []types.Issuer, _ *uint64, _ *int64, _ *string) {
			c.SignDoc.Domain = "wrong"
		}},
		{name: "tampered policy hash", want: v2.ErrBadSignatureV2, change: func(c *v2.AuthorizationCertificateV2, _ *types.IssuerSet, _ []types.Issuer, _ *uint64, _ *int64, _ *string) {
			c.SignDoc.PolicyHash[0] ^= 1
		}},
		{name: "tampered amount", want: v2.ErrBadSignatureV2, change: func(c *v2.AuthorizationCertificateV2, _ *types.IssuerSet, _ []types.Issuer, _ *uint64, _ *int64, _ *string) {
			c.SignDoc.Intent.Amount = "1001"
		}},
		{name: "missing current selection", want: v2.ErrStaleIssuerSetV2, change: func(_ *v2.AuthorizationCertificateV2, _ *types.IssuerSet, _ []types.Issuer, current *uint64, _ *int64, _ *string) {
			*current = 0
		}},
		{name: "stale current selection", want: v2.ErrStaleIssuerSetV2, change: func(_ *v2.AuthorizationCertificateV2, _ *types.IssuerSet, _ []types.Issuer, current *uint64, _ *int64, _ *string) {
			*current = 10
		}},
		{name: "inactive set", want: v2.ErrIssuerInactiveV2, change: func(_ *v2.AuthorizationCertificateV2, set *types.IssuerSet, _ []types.Issuer, _ *uint64, _ *int64, _ *string) {
			set.Active = false
		}},
		{name: "wrong policy scope", want: v2.ErrIssuerOutOfScopeV2, change: func(_ *v2.AuthorizationCertificateV2, set *types.IssuerSet, _ []types.Issuer, _ *uint64, _ *int64, _ *string) {
			set.PolicyId = "other"
		}},
		{name: "wrong message scope", want: v2.ErrIssuerOutOfScopeV2, change: func(_ *v2.AuthorizationCertificateV2, set *types.IssuerSet, _ []types.Issuer, _ *uint64, _ *int64, _ *string) {
			set.MsgTypeUrl = "/other"
		}},
		{name: "unknown issuer", want: v2.ErrUnknownIssuerV2, change: func(c *v2.AuthorizationCertificateV2, _ *types.IssuerSet, _ []types.Issuer, _ *uint64, _ *int64, _ *string) {
			c.Signatures[1].IssuerId = "unknown"
		}},
		{name: "inactive issuer", want: v2.ErrIssuerInactiveV2, change: func(_ *v2.AuthorizationCertificateV2, _ *types.IssuerSet, issuers []types.Issuer, _ *uint64, _ *int64, _ *string) {
			issuers[1].Active = false
		}},
		{name: "issuer before window", want: v2.ErrIssuerInactiveV2, change: func(_ *v2.AuthorizationCertificateV2, _ *types.IssuerSet, issuers []types.Issuer, _ *uint64, _ *int64, _ *string) {
			issuers[1].ValidFromHeight = 106
		}},
		{name: "issuer after window", want: v2.ErrIssuerInactiveV2, change: func(_ *v2.AuthorizationCertificateV2, _ *types.IssuerSet, issuers []types.Issuer, _ *uint64, _ *int64, _ *string) {
			issuers[1].ValidUntilHeight = 104
		}},
		{name: "issuer wrong set", want: v2.ErrIssuerOutOfScopeV2, change: func(_ *v2.AuthorizationCertificateV2, _ *types.IssuerSet, issuers []types.Issuer, _ *uint64, _ *int64, _ *string) {
			issuers[1].IssuerSetId = 10
		}},
		{name: "bad public key", want: v2.ErrInvalidCertificateV2, change: func(_ *v2.AuthorizationCertificateV2, _ *types.IssuerSet, issuers []types.Issuer, _ *uint64, _ *int64, _ *string) {
			issuers[1].PublicKey = issuers[1].PublicKey[:31]
		}},
		{name: "bad key type", want: v2.ErrInvalidCertificateV2, change: func(_ *v2.AuthorizationCertificateV2, _ *types.IssuerSet, issuers []types.Issuer, _ *uint64, _ *int64, _ *string) {
			issuers[1].KeyType = 0
		}},
		{name: "zero weight", want: v2.ErrInvalidCertificateV2, change: func(_ *v2.AuthorizationCertificateV2, _ *types.IssuerSet, issuers []types.Issuer, _ *uint64, _ *int64, _ *string) {
			issuers[1].Weight = 0
		}},
		{name: "bad extra after quorum", want: v2.ErrBadSignatureV2, change: func(c *v2.AuthorizationCertificateV2, set *types.IssuerSet, _ []types.Issuer, _ *uint64, _ *int64, _ *string) {
			set.ThresholdWeight = 2
			c.Signatures[1].Signature[0] ^= 1
		}},
		{name: "unknown extra after quorum", want: v2.ErrUnknownIssuerV2, change: func(c *v2.AuthorizationCertificateV2, _ *types.IssuerSet, _ []types.Issuer, _ *uint64, _ *int64, _ *string) {
			c.Signatures = append(c.Signatures, &v2.IssuerSignatureV2{IssuerId: "unknown", Signature: make([]byte, 64)})
		}},
		{name: "short signature", want: v2.ErrBadSignatureV2, change: func(c *v2.AuthorizationCertificateV2, _ *types.IssuerSet, _ []types.Issuer, _ *uint64, _ *int64, _ *string) {
			c.Signatures[1].Signature = c.Signatures[1].Signature[:63]
		}},
		{name: "duplicate issuer", want: v2.ErrDuplicateSignatureV2, change: func(c *v2.AuthorizationCertificateV2, _ *types.IssuerSet, _ []types.Issuer, _ *uint64, _ *int64, _ *string) {
			c.Signatures = append(c.Signatures, c.Signatures[0])
		}},
		{name: "insufficient quorum", want: v2.ErrQuorumNotMetV2, change: func(_ *v2.AuthorizationCertificateV2, set *types.IssuerSet, _ []types.Issuer, _ *uint64, _ *int64, _ *string) {
			set.ThresholdWeight = 6
		}},
		{name: "weight overflow", want: v2.ErrInvalidCertificateV2, change: func(_ *v2.AuthorizationCertificateV2, _ *types.IssuerSet, issuers []types.Issuer, _ *uint64, _ *int64, _ *string) {
			issuers[0].Weight = math.MaxUint64
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := initFixture(t)
			require.NoError(t, f.keeper.Params.Set(f.ctx, types.DefaultParams()))
			certificate, issuers := v2GoldenCertificate(t)
			set := types.IssuerSet{IssuerSetId: 9, Active: true, PolicyId: certificate.SignDoc.PolicyId, MsgTypeUrl: types.MsgSendTypeURL, ThresholdWeight: 5}
			current, height, chain := uint64(9), int64(105), "alpha-1"
			if tt.change != nil {
				tt.change(certificate, &set, issuers, &current, &height, &chain)
			}
			// Direct writes intentionally exercise malformed committed registry state.
			require.NoError(t, f.keeper.IssuerSets.Set(f.ctx, 9, set))
			for _, issuer := range issuers {
				require.NoError(t, f.keeper.Issuers.Set(f.ctx, collections.Join(uint64(9), issuer.IssuerId), issuer))
			}
			if current != 0 {
				require.NoError(t, f.keeper.CurrentIssuerSets.Set(f.ctx, collections.Join(certificate.SignDoc.PolicyId, types.MsgSendTypeURL), current))
			}
			require.NoError(t, f.keeper.SetLastAppliedBatchID(f.ctx, 9, 999))
			before, err := f.keeper.ExportGenesis(f.ctx)
			require.NoError(t, err)
			weight, digest, err := f.keeper.VerifyCertificateV2(f.ctx, height, chain, certificate)
			if tt.want != nil {
				require.ErrorIs(t, err, tt.want)
				require.Zero(t, weight)
			} else {
				require.NoError(t, err)
				require.Equal(t, uint64(5), weight)
				require.Equal(t, v2GoldenDigest, hex.EncodeToString(digest[:]))
			}
			after, exportErr := f.keeper.ExportGenesis(f.ctx)
			require.NoError(t, exportErr)
			require.Equal(t, before, after) // No registry, authorization or replay mutation.
		})
	}
}

func TestVerifyCertificateV2MissingSelectedSet(t *testing.T) {
	f := initFixture(t)
	certificate, _ := v2GoldenCertificate(t)
	require.NoError(t, f.keeper.CurrentIssuerSets.Set(f.ctx, collections.Join(certificate.SignDoc.PolicyId, types.MsgSendTypeURL), uint64(9)))
	_, _, err := f.keeper.VerifyCertificateV2(f.ctx, 105, "alpha-1", certificate)
	require.ErrorIs(t, err, v2.ErrStaleIssuerSetV2)
}

func TestVerifyCertificateV2MissingEnvelope(t *testing.T) {
	f := initFixture(t)
	for _, certificate := range []*v2.AuthorizationCertificateV2{nil, {}, {SignDoc: &v2.AuthorizationCertificateSignDocV2{}}} {
		_, _, err := f.keeper.VerifyCertificateV2(f.ctx, 105, "alpha-1", certificate)
		require.ErrorIs(t, err, v2.ErrInvalidCertificateV2)
	}
}
