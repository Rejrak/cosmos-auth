package keeper

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"alpha/x/authzattrs/types"
)

const EventTypeAuthzBatchApplied = "authz_batch_applied"

func (k msgServer) BatchUpsertAuthorizations(ctx context.Context, req *types.MsgBatchUpsertAuthorizations) (*types.MsgBatchUpsertAuthorizationsResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("%w: nil request", types.ErrInvalidBatchSignDoc)
	}
	submitter, err := k.addressCodec.StringToBytes(req.Submitter)
	if err != nil {
		return nil, fmt.Errorf("invalid submitter address: %w", err)
	}
	canonicalSubmitter, err := k.addressCodec.BytesToString(submitter)
	if err != nil || canonicalSubmitter != req.Submitter {
		return nil, fmt.Errorf("invalid submitter address")
	}

	sdkCtx := sdk.UnwrapSDKContext(ctx)
	weight, hash, count, err := k.ApplyAuthorizationBatch(ctx, sdkCtx.BlockHeight(), sdkCtx.ChainID(), req.Batch)
	if err != nil {
		return nil, err
	}
	doc := req.Batch.SignDoc
	sdkCtx.EventManager().EmitEvent(sdk.NewEvent(
		EventTypeAuthzBatchApplied,
		sdk.NewAttribute("batch_id", strconv.FormatUint(doc.BatchId, 10)),
		sdk.NewAttribute("batch_hash", hex.EncodeToString(hash[:])),
		sdk.NewAttribute("policy_id", doc.PolicyId),
		sdk.NewAttribute("policy_version", strconv.FormatUint(doc.PolicyVersion, 10)),
		sdk.NewAttribute("issuer_set_id", strconv.FormatUint(doc.IssuerSetId, 10)),
		sdk.NewAttribute("record_count", strconv.Itoa(count)),
		sdk.NewAttribute("quorum_weight", strconv.FormatUint(weight, 10)),
		sdk.NewAttribute("submitter", canonicalSubmitter),
		sdk.NewAttribute("height", strconv.FormatInt(sdkCtx.BlockHeight(), 10)),
	))
	return &types.MsgBatchUpsertAuthorizationsResponse{}, nil
}
