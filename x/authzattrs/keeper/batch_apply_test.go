package keeper_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"testing"

	"alpha/x/authzattrs/types"
	"github.com/cosmos/gogoproto/proto"
	"github.com/stretchr/testify/require"
)

func applyFixture(t *testing.T) (*fixture, *types.AuthorizationBatch, string) {
	t.Helper()
	f := initFixture(t)
	b, issuers, hash := quorumGolden(t)
	require.NoError(t, f.keeper.Params.Set(f.ctx, types.DefaultParams()))
	require.NoError(t, f.keeper.SetIssuerSet(f.ctx, types.IssuerSet{IssuerSetId: b.SignDoc.IssuerSetId, Active: true, PolicyId: b.SignDoc.PolicyId, MsgTypeUrl: types.MsgSendTypeURL, ThresholdWeight: 5}))
	for _, issuer := range issuers {
		require.NoError(t, f.keeper.SetIssuer(f.ctx, issuer))
	}
	require.NoError(t, f.keeper.SetCurrentIssuerSet(f.ctx, b.SignDoc.PolicyId, types.MsgSendTypeURL, b.SignDoc.IssuerSetId))
	return f, b, hash
}

// TEST-ONLY, NON-PRODUCTION seeds for altered batches; golden bytes remain unchanged.
func signApplyTestBatch(t *testing.T, f *fixture, b *types.AuthorizationBatch) {
	t.Helper()
	data, _, err := types.CanonicalBatchSignBytes(b.SignDoc)
	require.NoError(t, err)
	b.Signatures = nil
	for i := byte(1); i <= 2; i++ {
		seed := make([]byte, ed25519.SeedSize)
		seed[0] = i
		key := ed25519.NewKeyFromSeed(seed)
		id := fmt.Sprintf("apply-test-%d", i)
		require.NoError(t, f.keeper.SetIssuer(f.ctx, types.Issuer{IssuerSetId: b.SignDoc.IssuerSetId, IssuerId: id, KeyType: types.IssuerKeyType_ISSUER_KEY_TYPE_ED25519, PublicKey: key.Public().(ed25519.PublicKey), Weight: uint64(i + 1), Active: true, ValidFromHeight: 100, ValidUntilHeight: 200}))
		b.Signatures = append(b.Signatures, &types.BatchSignature{IssuerId: id, Signature: ed25519.Sign(key, data)})
	}
}

func assertAppliedRecords(t *testing.T, f *fixture, b *types.AuthorizationBatch) {
	t.Helper()
	for _, r := range b.SignDoc.Records {
		got, found, err := f.keeper.GetAuthorization(f.ctx, r.Subject, r.MsgTypeUrl)
		require.NoError(t, err)
		require.True(t, found)
		require.Equal(t, *r, got)
	}
	id, found, err := f.keeper.GetLastAppliedBatchID(f.ctx, b.SignDoc.IssuerSetId)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, b.SignDoc.BatchId, id)
}

func TestApplyGoldenBatch(t *testing.T) {
	f, b, expectedHash := applyFixture(t)
	require.NoError(t, f.keeper.SetLastAppliedBatchID(f.ctx, 123, 900))
	before := proto.Clone(b)
	weight, hash, count, err := f.keeper.ApplyAuthorizationBatch(f.ctx, 150, b.SignDoc.ChainId, b)
	require.NoError(t, err)
	require.Equal(t, uint64(5), weight)
	require.Equal(t, expectedHash, hex.EncodeToString(hash[:]))
	require.Equal(t, 2, count)
	assertAppliedRecords(t, f, b)
	require.Equal(t, before, b)
	other, found, err := f.keeper.GetLastAppliedBatchID(f.ctx, 123)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, uint64(900), other)
	_, _, _, err = f.keeper.ApplyAuthorizationBatch(f.ctx, 150, b.SignDoc.ChainId, b)
	require.ErrorIs(t, err, types.ErrBatchReplay)
}

func TestApplyBatchSequenceAndRotation(t *testing.T) {
	f, b, _ := applyFixture(t)
	for _, id := range []uint64{10, 12} {
		b.SignDoc.BatchId = id
		for _, r := range b.SignDoc.Records {
			r.AuthorizationId = fmt.Sprintf("grant-%d-%s", id, r.Subject)
			r.BankSendConstraints.MaxAmount = "500"
		}
		signApplyTestBatch(t, f, b)
		_, _, _, err := f.keeper.ApplyAuthorizationBatch(f.ctx, 150, b.SignDoc.ChainId, b)
		require.NoError(t, err)
		assertAppliedRecords(t, f, b)
	}
	b.SignDoc.BatchId = 11
	_, _, _, err := f.keeper.ApplyAuthorizationBatch(f.ctx, 150, b.SignDoc.ChainId, b)
	require.ErrorIs(t, err, types.ErrBatchReplay)
	oldSet := b.SignDoc.IssuerSetId
	b.SignDoc.IssuerSetId = oldSet + 1
	b.SignDoc.BatchId = 1 // Independent sequence after rotation.
	for _, r := range b.SignDoc.Records {
		r.IssuerSetId = b.SignDoc.IssuerSetId
		r.Revoked = true
	}
	require.NoError(t, f.keeper.SetIssuerSet(f.ctx, types.IssuerSet{IssuerSetId: b.SignDoc.IssuerSetId, Active: true, PolicyId: b.SignDoc.PolicyId, MsgTypeUrl: types.MsgSendTypeURL, ThresholdWeight: 5}))
	require.NoError(t, f.keeper.SetCurrentIssuerSet(f.ctx, b.SignDoc.PolicyId, types.MsgSendTypeURL, b.SignDoc.IssuerSetId))
	signApplyTestBatch(t, f, b)
	_, _, _, err = f.keeper.ApplyAuthorizationBatch(f.ctx, 150, b.SignDoc.ChainId, b)
	require.NoError(t, err)
	assertAppliedRecords(t, f, b)
	last, found, err := f.keeper.GetLastAppliedBatchID(f.ctx, oldSet)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, uint64(12), last)
}

func TestApplyBatchValidationFailuresWriteNothing(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*testing.T, *fixture, *types.AuthorizationBatch)
		want   error
	}{
		{"bad signature", func(_ *testing.T, _ *fixture, b *types.AuthorizationBatch) { b.Signatures[0].Signature[0] ^= 1 }, types.ErrBatchBadSignature},
		{"insufficient quorum", func(_ *testing.T, _ *fixture, b *types.AuthorizationBatch) { b.Signatures = b.Signatures[:1] }, types.ErrBatchQuorumNotMet},
		{"unknown issuer", func(_ *testing.T, _ *fixture, b *types.AuthorizationBatch) { b.Signatures[0].IssuerId = "missing" }, types.ErrBatchUnknownIssuer},
		{"stale set", func(t *testing.T, f *fixture, b *types.AuthorizationBatch) {
			s, found, err := f.keeper.GetIssuerSet(f.ctx, b.SignDoc.IssuerSetId)
			require.NoError(t, err)
			require.True(t, found)
			s.IssuerSetId++
			require.NoError(t, f.keeper.SetIssuerSet(f.ctx, s))
			require.NoError(t, f.keeper.SetCurrentIssuerSet(f.ctx, s.PolicyId, s.MsgTypeUrl, s.IssuerSetId))
		}, types.ErrBatchStaleIssuerSet},
		{"later stale revocation", func(t *testing.T, f *fixture, b *types.AuthorizationBatch) {
			canonical, err := types.CanonicalizeBatchSignDoc(b.SignDoc)
			require.NoError(t, err)
			b.SignDoc = canonical
			b.SignDoc.Records[1].Revoked = true
			signApplyTestBatch(t, f, b)
		}, types.ErrBatchStaleRevocation},
		{"later reused identity", func(t *testing.T, f *fixture, b *types.AuthorizationBatch) {
			canonical, err := types.CanonicalizeBatchSignDoc(b.SignDoc)
			require.NoError(t, err)
			require.NoError(t, f.keeper.SetAuthorization(f.ctx, *canonical.Records[1]))
		}, types.ErrInvalidBatchSignDoc},
		{"duplicate record", func(_ *testing.T, _ *fixture, b *types.AuthorizationBatch) {
			b.SignDoc.Records = append(b.SignDoc.Records, b.SignDoc.Records[0])
		}, types.ErrDuplicateRecord},
		{"policy mismatch", func(_ *testing.T, _ *fixture, b *types.AuthorizationBatch) { b.SignDoc.Records[0].PolicyVersion++ }, types.ErrBatchPolicyMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, b, _ := applyFixture(t)
			require.NoError(t, f.keeper.SetLastAppliedBatchID(f.ctx, b.SignDoc.IssuerSetId, b.SignDoc.BatchId-1))
			tc.change(t, f, b)
			before, err := f.keeper.ExportGenesis(f.ctx)
			require.NoError(t, err)
			input := proto.Clone(b)
			_, _, _, err = f.keeper.ApplyAuthorizationBatch(f.ctx, 150, b.SignDoc.ChainId, b)
			require.ErrorIs(t, err, tc.want)
			after, err := f.keeper.ExportGenesis(f.ctx)
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.Equal(t, input, b)
		})
	}
}

func TestFailedBatchIDCanBeRetried(t *testing.T) {
	f, b, _ := applyFixture(t)
	b.Signatures[0].Signature[0] ^= 1
	_, _, _, err := f.keeper.ApplyAuthorizationBatch(f.ctx, 150, b.SignDoc.ChainId, b)
	require.ErrorIs(t, err, types.ErrBatchBadSignature)
	_, found, err := f.keeper.GetLastAppliedBatchID(f.ctx, b.SignDoc.IssuerSetId)
	require.NoError(t, err)
	require.False(t, found)
	b.Signatures[0].Signature[0] ^= 1
	_, _, _, err = f.keeper.ApplyAuthorizationBatch(f.ctx, 150, b.SignDoc.ChainId, b)
	require.NoError(t, err)
	assertAppliedRecords(t, f, b)
}

func TestApplyBatchEnvelopeBeforeReplay(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*types.AuthorizationBatch) *types.AuthorizationBatch
		height int64
		want   error
	}{
		{"nil batch", func(_ *types.AuthorizationBatch) *types.AuthorizationBatch { return nil }, 150, types.ErrInvalidBatchSignDoc},
		{"nil doc", func(b *types.AuthorizationBatch) *types.AuthorizationBatch { b.SignDoc = nil; return b }, 150, types.ErrInvalidBatchSignDoc},
		{"bad domain", func(b *types.AuthorizationBatch) *types.AuthorizationBatch { b.SignDoc.Domain = "wrong"; return b }, 150, types.ErrBatchBadDomain},
		{"empty chain", func(b *types.AuthorizationBatch) *types.AuthorizationBatch { b.SignDoc.ChainId = ""; return b }, 150, types.ErrBatchChainIDMismatch},
		{"wrong chain", func(b *types.AuthorizationBatch) *types.AuthorizationBatch { b.SignDoc.ChainId = "wrong"; return b }, 150, types.ErrBatchChainIDMismatch},
		{"zero height", func(b *types.AuthorizationBatch) *types.AuthorizationBatch { return b }, 0, types.ErrInvalidBatchSignDoc},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, b, _ := applyFixture(t)
			chain := b.SignDoc.ChainId
			require.NoError(t, f.keeper.SetLastAppliedBatchID(f.ctx, b.SignDoc.IssuerSetId, b.SignDoc.BatchId))
			before, err := f.keeper.ExportGenesis(f.ctx)
			require.NoError(t, err)
			_, _, _, err = f.keeper.ApplyAuthorizationBatch(f.ctx, tc.height, chain, tc.change(b))
			require.ErrorIs(t, err, tc.want)
			after, err := f.keeper.ExportGenesis(f.ctx)
			require.NoError(t, err)
			require.Equal(t, before, after)
		})
	}
}
