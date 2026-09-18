package keeper_test

import (
	"context"
	"encoding/hex"
	"strconv"
	"testing"

	"cosmossdk.io/collections"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/gogoproto/proto"
	"github.com/stretchr/testify/require"

	"alpha/x/authzattrs/keeper"
	"alpha/x/authzattrs/types"
)

func batchMsgContext(f *fixture, chainID string, height int64) context.Context {
	sdkCtx := sdk.UnwrapSDKContext(f.ctx).WithChainID(chainID).WithBlockHeight(height).WithEventManager(sdk.NewEventManager())
	return sdk.WrapSDKContext(sdkCtx)
}

func batchAppliedEvents(ctx context.Context) []sdk.Event {
	var found []sdk.Event
	for _, event := range sdk.UnwrapSDKContext(ctx).EventManager().Events() {
		if event.Type == keeper.EventTypeAuthzBatchApplied {
			found = append(found, event)
		}
	}
	return found
}

func eventAttributes(event sdk.Event) map[string]string {
	attributes := make(map[string]string, len(event.Attributes))
	for _, attribute := range event.Attributes {
		attributes[attribute.Key] = attribute.Value
	}
	return attributes
}

func TestMsgBatchUpsertAuthorizationsSuccess(t *testing.T) {
	f, batch, expectedHash := applyFixture(t)
	ctx := batchMsgContext(f, batch.SignDoc.ChainId, 150)
	submitter := addrString(77) // Arbitrary account: neither authority nor registered issuer.
	req := &types.MsgBatchUpsertAuthorizations{Submitter: submitter, Batch: batch}
	before := proto.Clone(req)

	response, err := keeper.NewMsgServerImpl(f.keeper).BatchUpsertAuthorizations(ctx, req)
	require.NoError(t, err)
	require.Equal(t, &types.MsgBatchUpsertAuthorizationsResponse{}, response)
	assertAppliedRecords(t, f, batch)
	require.Equal(t, before, req)

	events := batchAppliedEvents(ctx)
	require.Len(t, events, 1)
	require.Equal(t, map[string]string{
		"batch_id":       strconv.FormatUint(batch.SignDoc.BatchId, 10),
		"batch_hash":     expectedHash,
		"policy_id":      batch.SignDoc.PolicyId,
		"policy_version": strconv.FormatUint(batch.SignDoc.PolicyVersion, 10),
		"issuer_set_id":  strconv.FormatUint(batch.SignDoc.IssuerSetId, 10),
		"record_count":   "2",
		"quorum_weight":  "5",
		"submitter":      submitter,
		"height":         "150",
	}, eventAttributes(events[0]))
	expectedHashBytes, err := hex.DecodeString(expectedHash)
	require.NoError(t, err)
	require.Len(t, expectedHashBytes, 32)
}

func TestMsgBatchUpsertAuthorizationsFailures(t *testing.T) {
	tests := []struct {
		name      string
		change    func(*testing.T, *fixture, *types.MsgBatchUpsertAuthorizations)
		want      error
		wantText  string
		applyOnce bool
	}{
		{name: "bad signature", want: types.ErrBatchBadSignature, change: func(_ *testing.T, _ *fixture, req *types.MsgBatchUpsertAuthorizations) {
			req.Batch.Signatures[0].Signature[0] ^= 1
		}},
		{name: "stale issuer set", want: types.ErrBatchStaleIssuerSet, change: func(t *testing.T, f *fixture, req *types.MsgBatchUpsertAuthorizations) {
			require.NoError(t, f.keeper.CurrentIssuerSets.Set(f.ctx, collections.Join(req.Batch.SignDoc.PolicyId, types.MsgSendTypeURL), uint64(999)))
		}},
		{name: "replay", want: types.ErrBatchReplay, applyOnce: true},
		{name: "invalid submitter", wantText: "invalid submitter address", change: func(_ *testing.T, _ *fixture, req *types.MsgBatchUpsertAuthorizations) { req.Submitter = "invalid" }},
		{name: "missing batch", want: types.ErrInvalidBatchSignDoc, change: func(_ *testing.T, _ *fixture, req *types.MsgBatchUpsertAuthorizations) { req.Batch = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f, batch, _ := applyFixture(t)
			server := keeper.NewMsgServerImpl(f.keeper)
			if test.applyOnce {
				ctx := batchMsgContext(f, batch.SignDoc.ChainId, 150)
				_, err := server.BatchUpsertAuthorizations(ctx, &types.MsgBatchUpsertAuthorizations{Submitter: addrString(77), Batch: batch})
				require.NoError(t, err)
			}
			req := &types.MsgBatchUpsertAuthorizations{Submitter: addrString(77), Batch: batch}
			if test.change != nil {
				test.change(t, f, req)
			}
			before, err := f.keeper.ExportGenesis(f.ctx)
			require.NoError(t, err)
			input := proto.Clone(req)
			ctx := batchMsgContext(f, batch.SignDoc.ChainId, 150)
			_, err = server.BatchUpsertAuthorizations(ctx, req)
			if test.want != nil {
				require.ErrorIs(t, err, test.want)
			} else {
				require.ErrorContains(t, err, test.wantText)
			}
			require.Empty(t, batchAppliedEvents(ctx))
			after, exportErr := f.keeper.ExportGenesis(f.ctx)
			require.NoError(t, exportErr)
			require.Equal(t, before, after)
			require.Equal(t, input, req)
		})
	}
}

func TestMsgBatchUpsertAuthorizationsNilRequest(t *testing.T) {
	f := initFixture(t)
	ctx := batchMsgContext(f, "alpha-test", 1)
	response, err := keeper.NewMsgServerImpl(f.keeper).BatchUpsertAuthorizations(ctx, nil)
	require.Nil(t, response)
	require.ErrorIs(t, err, types.ErrInvalidBatchSignDoc)
	require.Empty(t, batchAppliedEvents(ctx))
}
