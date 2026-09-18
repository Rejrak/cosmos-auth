package keeper_test

import (
	"testing"

	"alpha/x/authzattrs/types"
	"cosmossdk.io/collections"
	"github.com/cosmos/gogoproto/proto"
	"github.com/stretchr/testify/require"
)

func mutationDoc(r types.AuthorizationRecord) *types.AuthorizationBatchSignDoc {
	return &types.AuthorizationBatchSignDoc{
		Domain: types.AuthorizationBatchDomain, ChainId: "alpha-test", BatchId: 2,
		PolicyId: r.PolicyId, PolicyVersion: r.PolicyVersion, PolicyHash: make([]byte, 32),
		IssuerSetId: r.IssuerSetId, Records: []*types.AuthorizationRecord{&r},
	}
}

func TestValidateBatchRecordMutations(t *testing.T) {
	for _, tc := range []struct {
		name              string
		missing, revoke   bool
		current, incoming func(*types.AuthorizationRecord)
		want              error
	}{
		{name: "new grant", missing: true},
		{name: "replacement"},
		{name: "replacement changes constraints", incoming: func(r *types.AuthorizationRecord) { r.BankSendConstraints.MaxAmount = "200" }},
		{name: "replacement of revoked", current: func(r *types.AuthorizationRecord) { r.Revoked = true }},
		{name: "replacement reuses ID", incoming: func(r *types.AuthorizationRecord) { r.AuthorizationId = "auth-1" }, want: types.ErrInvalidBatchSignDoc},
		{name: "valid revocation", revoke: true},
		{name: "missing revocation", missing: true, revoke: true, want: types.ErrBatchStaleRevocation},
		{name: "already revoked", revoke: true, current: func(r *types.AuthorizationRecord) { r.Revoked = true }, want: types.ErrBatchStaleRevocation},
		{name: "revocation ID", revoke: true, incoming: func(r *types.AuthorizationRecord) { r.AuthorizationId = "other" }, want: types.ErrBatchStaleRevocation},
		{name: "revocation policy", revoke: true, incoming: func(r *types.AuthorizationRecord) { r.PolicyId = "other" }, want: types.ErrBatchStaleRevocation},
		{name: "revocation version", revoke: true, incoming: func(r *types.AuthorizationRecord) { r.PolicyVersion++ }, want: types.ErrBatchStaleRevocation},
		{name: "revocation from height", revoke: true, incoming: func(r *types.AuthorizationRecord) { r.ValidFromHeight++ }, want: types.ErrBatchStaleRevocation},
		{name: "revocation until height", revoke: true, incoming: func(r *types.AuthorizationRecord) { r.ValidUntilHeight++ }, want: types.ErrBatchStaleRevocation},
		{name: "revocation denom", revoke: true, incoming: func(r *types.AuthorizationRecord) { r.BankSendConstraints.Denom = "uatom" }, want: types.ErrBatchStaleRevocation},
		{name: "revocation receiver", revoke: true, incoming: func(r *types.AuthorizationRecord) { r.BankSendConstraints.Receiver = addrString(3) }, want: types.ErrBatchStaleRevocation},
		{name: "revocation amount", revoke: true, incoming: func(r *types.AuthorizationRecord) { r.BankSendConstraints.MaxAmount = "200" }, want: types.ErrBatchStaleRevocation},
		{name: "rotation revocation", revoke: true, incoming: func(r *types.AuthorizationRecord) { r.IssuerSetId = 2 }},
		{name: "malformed CURRENT grant", current: func(r *types.AuthorizationRecord) { r.BankSendConstraints.MaxAmount = "01" }, want: types.ErrInvalidBatchSignDoc},
		{name: "malformed CURRENT revocation", revoke: true, current: func(r *types.AuthorizationRecord) { r.PolicyId = "" }, want: types.ErrInvalidBatchSignDoc},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := initFixture(t)
			current, incoming := record(), record()
			if tc.current != nil {
				tc.current(&current)
			}
			if tc.revoke {
				incoming.Revoked = true
			} else {
				incoming.AuthorizationId = "auth-2"
			}
			if tc.incoming != nil {
				tc.incoming(&incoming)
			}
			if !tc.missing {
				// Deliberately bypass validation to exercise malformed committed state.
				require.NoError(t, f.keeper.Authorizations.Set(f.ctx, collections.Join(current.Subject, current.MsgTypeUrl), current))
			}
			require.NoError(t, f.keeper.SetLastAppliedBatchID(f.ctx, 1, 1))
			doc := mutationDoc(incoming)
			before := proto.Clone(doc)
			got, err := f.keeper.ValidateBatchRecordMutations(f.ctx, doc)
			if tc.want != nil {
				require.ErrorIs(t, err, tc.want)
				require.Nil(t, got)
			} else {
				require.NoError(t, err)
				require.Equal(t, []types.AuthorizationRecord{incoming}, got)
				got[0].AuthorizationId = "detached"
				got[0].BankSendConstraints.MaxAmount = "999"
			}
			require.Equal(t, before, doc)
			stored, found, err := f.keeper.GetAuthorization(f.ctx, current.Subject, current.MsgTypeUrl)
			require.NoError(t, err)
			require.Equal(t, !tc.missing, found)
			if found {
				require.Equal(t, current, stored)
			}
			last, found, err := f.keeper.GetLastAppliedBatchID(f.ctx, 1)
			require.NoError(t, err)
			require.True(t, found)
			require.Equal(t, uint64(1), last)
		})
	}
}

func TestBatchMutationsCanonicalValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*types.AuthorizationBatchSignDoc)
		want   error
	}{
		{"duplicate", func(d *types.AuthorizationBatchSignDoc) { d.Records = append(d.Records, d.Records[0]) }, types.ErrDuplicateRecord},
		{"policy mismatch", func(d *types.AuthorizationBatchSignDoc) { d.PolicyId = "other" }, types.ErrBatchPolicyMismatch},
		{"version mismatch", func(d *types.AuthorizationBatchSignDoc) { d.PolicyVersion++ }, types.ErrBatchPolicyMismatch},
		{"issuer set mismatch", func(d *types.AuthorizationBatchSignDoc) { d.IssuerSetId++ }, types.ErrBatchPolicyMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := initFixture(t)
			doc := mutationDoc(record())
			tc.change(doc)
			before := proto.Clone(doc)
			got, err := f.keeper.ValidateBatchRecordMutations(f.ctx, doc)
			require.ErrorIs(t, err, tc.want)
			require.Nil(t, got)
			require.Equal(t, before, doc)
		})
	}
}

func TestBatchMutationsCanonicalOrderAndNoPartialResult(t *testing.T) {
	f := initFixture(t)
	a, b := record(), record()
	b.Subject = addrString(3)
	if a.Subject < b.Subject {
		a, b = b, a
	}
	doc := mutationDoc(a)
	doc.Records = append(doc.Records, &b)
	before := proto.Clone(doc)
	got, err := f.keeper.ValidateBatchRecordMutations(f.ctx, doc)
	require.NoError(t, err)
	require.Equal(t, []types.AuthorizationRecord{b, a}, got)
	require.Equal(t, before, doc)
	// The later record fails after the first has passed: no partial result or writes.
	doc.Records[0].Revoked = true
	got, err = f.keeper.ValidateBatchRecordMutations(f.ctx, doc)
	require.ErrorIs(t, err, types.ErrBatchStaleRevocation)
	require.Nil(t, got)
	for _, r := range []types.AuthorizationRecord{a, b} {
		found, err := f.keeper.HasAuthorization(f.ctx, r.Subject, r.MsgTypeUrl)
		require.NoError(t, err)
		require.False(t, found)
	}
}
