package keeper_test

import (
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"testing"

	"cosmossdk.io/collections"
	"github.com/stretchr/testify/require"

	"alpha/x/authzattrs/types"
)

func TestVerifyBatchSignaturesAndQuorum(t *testing.T) {
	tests := []struct {
		name   string
		change func(*types.AuthorizationBatch, *types.IssuerSet, []types.Issuer, *uint64, *int64, *string)
		want   error
	}{
		{name: "golden"},
		{name: "reversed signatures", change: func(b *types.AuthorizationBatch, _ *types.IssuerSet, _ []types.Issuer, _ *uint64, _ *int64, _ *string) {
			b.Signatures[0], b.Signatures[1] = b.Signatures[1], b.Signatures[0]
		}},
		{name: "duplicate", want: types.ErrBatchDuplicateSignature, change: func(b *types.AuthorizationBatch, _ *types.IssuerSet, _ []types.Issuer, _ *uint64, _ *int64, _ *string) {
			b.Signatures = append(b.Signatures, b.Signatures[0])
		}},
		{name: "unknown extra after quorum", want: types.ErrBatchUnknownIssuer, change: func(b *types.AuthorizationBatch, _ *types.IssuerSet, _ []types.Issuer, _ *uint64, _ *int64, _ *string) {
			b.Signatures = append(b.Signatures, &types.BatchSignature{IssuerId: "unknown", Signature: make([]byte, 64)})
		}},
		{name: "inactive extra after quorum", want: types.ErrBatchIssuerInactive, change: func(_ *types.AuthorizationBatch, s *types.IssuerSet, i []types.Issuer, _ *uint64, _ *int64, _ *string) {
			s.ThresholdWeight = 2
			i[1].Active = false
		}},
		{name: "below height", want: types.ErrBatchIssuerInactive, change: func(_ *types.AuthorizationBatch, _ *types.IssuerSet, _ []types.Issuer, _ *uint64, h *int64, _ *string) {
			*h = 99
		}},
		{name: "above height", want: types.ErrBatchIssuerInactive, change: func(_ *types.AuthorizationBatch, _ *types.IssuerSet, _ []types.Issuer, _ *uint64, h *int64, _ *string) {
			*h = 201
		}},
		{name: "lower inclusive", change: func(_ *types.AuthorizationBatch, _ *types.IssuerSet, _ []types.Issuer, _ *uint64, h *int64, _ *string) {
			*h = 100
		}},
		{name: "upper inclusive", change: func(_ *types.AuthorizationBatch, _ *types.IssuerSet, _ []types.Issuer, _ *uint64, h *int64, _ *string) {
			*h = 200
		}},
		{name: "inactive set", want: types.ErrBatchIssuerInactive, change: func(_ *types.AuthorizationBatch, s *types.IssuerSet, _ []types.Issuer, _ *uint64, _ *int64, _ *string) {
			s.Active = false
		}},
		{name: "policy scope", want: types.ErrBatchIssuerOutOfScope, change: func(_ *types.AuthorizationBatch, s *types.IssuerSet, _ []types.Issuer, _ *uint64, _ *int64, _ *string) {
			s.PolicyId = "other"
		}},
		{name: "message scope", want: types.ErrBatchIssuerOutOfScope, change: func(_ *types.AuthorizationBatch, s *types.IssuerSet, _ []types.Issuer, _ *uint64, _ *int64, _ *string) {
			s.MsgTypeUrl = "/other"
		}},
		{name: "missing current", want: types.ErrBatchStaleIssuerSet, change: func(_ *types.AuthorizationBatch, _ *types.IssuerSet, _ []types.Issuer, c *uint64, _ *int64, _ *string) {
			*c = 0
		}},
		{name: "stale current", want: types.ErrBatchStaleIssuerSet, change: func(_ *types.AuthorizationBatch, _ *types.IssuerSet, _ []types.Issuer, c *uint64, _ *int64, _ *string) {
			*c = 10
		}},
		{name: "short signature", want: types.ErrBatchBadSignature, change: func(b *types.AuthorizationBatch, _ *types.IssuerSet, _ []types.Issuer, _ *uint64, _ *int64, _ *string) {
			b.Signatures[0].Signature = b.Signatures[0].Signature[:63]
		}},
		{name: "invalid extra after quorum", want: types.ErrBatchBadSignature, change: func(b *types.AuthorizationBatch, s *types.IssuerSet, _ []types.Issuer, _ *uint64, _ *int64, _ *string) {
			s.ThresholdWeight = 2
			b.Signatures[1].Signature[0] ^= 1
		}},
		{name: "insufficient", want: types.ErrBatchQuorumNotMet, change: func(_ *types.AuthorizationBatch, s *types.IssuerSet, _ []types.Issuer, _ *uint64, _ *int64, _ *string) {
			s.ThresholdWeight = 6
		}},
		{name: "overflow", want: types.ErrInvalidBatchSignDoc, change: func(_ *types.AuthorizationBatch, _ *types.IssuerSet, i []types.Issuer, _ *uint64, _ *int64, _ *string) {
			i[0].Weight = math.MaxUint64
		}},
		{name: "wrong chain", want: types.ErrBatchChainIDMismatch, change: func(_ *types.AuthorizationBatch, _ *types.IssuerSet, _ []types.Issuer, _ *uint64, _ *int64, c *string) {
			*c = "other"
		}},
		{name: "empty chain", want: types.ErrBatchChainIDMismatch, change: func(b *types.AuthorizationBatch, _ *types.IssuerSet, _ []types.Issuer, _ *uint64, _ *int64, _ *string) {
			b.SignDoc.ChainId = ""
		}},
		{name: "wrong domain", want: types.ErrBatchBadDomain, change: func(b *types.AuthorizationBatch, _ *types.IssuerSet, _ []types.Issuer, _ *uint64, _ *int64, _ *string) {
			b.SignDoc.Domain = "other"
		}},
		{name: "empty signatures", want: types.ErrBatchQuorumNotMet, change: func(b *types.AuthorizationBatch, _ *types.IssuerSet, _ []types.Issuer, _ *uint64, _ *int64, _ *string) {
			b.Signatures = nil
		}},
		{name: "nil signature", want: types.ErrBatchBadSignature, change: func(b *types.AuthorizationBatch, _ *types.IssuerSet, _ []types.Issuer, _ *uint64, _ *int64, _ *string) {
			b.Signatures[0] = nil
		}},
		{name: "empty issuer identity", want: types.ErrBatchBadSignature, change: func(b *types.AuthorizationBatch, _ *types.IssuerSet, _ []types.Issuer, _ *uint64, _ *int64, _ *string) {
			b.Signatures[0].IssuerId = ""
		}},
		{name: "invalid public key", want: types.ErrInvalidBatchSignDoc, change: func(_ *types.AuthorizationBatch, _ *types.IssuerSet, i []types.Issuer, _ *uint64, _ *int64, _ *string) {
			i[0].PublicKey = i[0].PublicKey[:31]
		}},
		{name: "invalid key type", want: types.ErrInvalidBatchSignDoc, change: func(_ *types.AuthorizationBatch, _ *types.IssuerSet, i []types.Issuer, _ *uint64, _ *int64, _ *string) {
			i[0].KeyType = 0
		}},
		{name: "zero weight", want: types.ErrInvalidBatchSignDoc, change: func(_ *types.AuthorizationBatch, _ *types.IssuerSet, i []types.Issuer, _ *uint64, _ *int64, _ *string) {
			i[0].Weight = 0
		}},
		{name: "issuer wrong set", want: types.ErrBatchIssuerOutOfScope, change: func(_ *types.AuthorizationBatch, _ *types.IssuerSet, i []types.Issuer, _ *uint64, _ *int64, _ *string) {
			i[0].IssuerSetId = 10
		}},
		{name: "zero threshold", want: types.ErrInvalidBatchSignDoc, change: func(_ *types.AuthorizationBatch, s *types.IssuerSet, _ []types.Issuer, _ *uint64, _ *int64, _ *string) {
			s.ThresholdWeight = 0
		}},
		{name: "nonpositive height", want: types.ErrInvalidBatchSignDoc, change: func(_ *types.AuthorizationBatch, _ *types.IssuerSet, _ []types.Issuer, _ *uint64, h *int64, _ *string) {
			*h = 0
		}},
		{name: "duplicate record", want: types.ErrDuplicateRecord, change: func(b *types.AuthorizationBatch, _ *types.IssuerSet, _ []types.Issuer, _ *uint64, _ *int64, _ *string) {
			b.SignDoc.Records = append(b.SignDoc.Records, b.SignDoc.Records[0])
		}},
		{name: "policy metadata mismatch", want: types.ErrBatchPolicyMismatch, change: func(b *types.AuthorizationBatch, _ *types.IssuerSet, _ []types.Issuer, _ *uint64, _ *int64, _ *string) {
			b.SignDoc.Records[0].PolicyVersion++
		}},
		{name: "invalid canonical batch", want: types.ErrInvalidBatchSignDoc, change: func(b *types.AuthorizationBatch, _ *types.IssuerSet, _ []types.Issuer, _ *uint64, _ *int64, _ *string) {
			b.SignDoc.BatchId = 0
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := initFixture(t)
			require.NoError(t, f.keeper.Params.Set(f.ctx, types.DefaultParams()))
			batch, issuers, expectedHash := quorumGolden(t)
			set := types.IssuerSet{IssuerSetId: 9, Active: true, PolicyId: batch.SignDoc.PolicyId, MsgTypeUrl: types.MsgSendTypeURL, ThresholdWeight: 5}
			current, height, chain := uint64(9), int64(150), batch.SignDoc.ChainId
			if tt.change != nil {
				tt.change(batch, &set, issuers, &current, &height, &chain)
			}
			// Direct collection writes deliberately exercise malformed stored state.
			require.NoError(t, f.keeper.IssuerSets.Set(f.ctx, 9, set))
			for _, issuer := range issuers {
				require.NoError(t, f.keeper.Issuers.Set(f.ctx, collections.Join(uint64(9), issuer.IssuerId), issuer))
			}
			if current != 0 {
				require.NoError(t, f.keeper.CurrentIssuerSets.Set(f.ctx, collections.Join("policy-bank-send", types.MsgSendTypeURL), current))
			}
			before, err := f.keeper.ExportGenesis(f.ctx)
			require.NoError(t, err)
			weight, hash, err := f.keeper.VerifyBatchSignaturesAndQuorum(f.ctx, height, chain, batch)
			if tt.want != nil {
				require.ErrorIs(t, err, tt.want)
				require.Zero(t, weight)
			} else {
				require.NoError(t, err)
				require.Equal(t, uint64(5), weight)
				require.Equal(t, expectedHash, hex.EncodeToString(hash[:]))
			}
			after, exportErr := f.keeper.ExportGenesis(f.ctx)
			require.NoError(t, exportErr)
			require.Equal(t, before, after)
		})
	}
}

func TestQuorumMissingEnvelopeAndSelectedSet(t *testing.T) {
	f := initFixture(t)
	for _, batch := range []*types.AuthorizationBatch{nil, {}} {
		_, _, err := f.keeper.VerifyBatchSignaturesAndQuorum(f.ctx, 150, "alpha-golden-1", batch)
		require.ErrorIs(t, err, types.ErrInvalidBatchSignDoc)
	}
	batch, _, _ := quorumGolden(t)
	require.NoError(t, f.keeper.CurrentIssuerSets.Set(f.ctx, collections.Join(batch.SignDoc.PolicyId, types.MsgSendTypeURL), uint64(9)))
	_, _, err := f.keeper.VerifyBatchSignaturesAndQuorum(f.ctx, 150, batch.SignDoc.ChainId, batch)
	require.ErrorIs(t, err, types.ErrBatchStaleIssuerSet)
}

func quorumGolden(t *testing.T) (*types.AuthorizationBatch, []types.Issuer, string) {
	t.Helper()
	data, err := os.ReadFile("../../../docs/authz/testdata/v1.2/canonical-batch-sign-doc.json")
	require.NoError(t, err)
	var fixture struct {
		types.AuthorizationBatchSignDoc
		PolicyHashHex string `json:"policy_hash_hex"`
		ExpectedHash  string `json:"expected_batch_hash_hex"`
		Issuers       []struct {
			ID        string `json:"issuer_id"`
			Key       string `json:"public_key_hex"`
			Signature string `json:"signature_hex"`
		} `json:"issuers"`
	}
	require.NoError(t, json.Unmarshal(data, &fixture))
	decode := func(s string) []byte { b, err := hex.DecodeString(s); require.NoError(t, err); return b }
	fixture.PolicyHash = decode(fixture.PolicyHashHex)
	batch := &types.AuthorizationBatch{SignDoc: &fixture.AuthorizationBatchSignDoc}
	var issuers []types.Issuer
	for n, i := range fixture.Issuers {
		batch.Signatures = append(batch.Signatures, &types.BatchSignature{IssuerId: i.ID, Signature: decode(i.Signature)})
		issuers = append(issuers, types.Issuer{IssuerSetId: 9, IssuerId: i.ID, KeyType: types.IssuerKeyType_ISSUER_KEY_TYPE_ED25519, PublicKey: decode(i.Key), Weight: uint64(n + 2), Active: true, ValidFromHeight: 100, ValidUntilHeight: 200})
	}
	return batch, issuers, fixture.ExpectedHash
}
