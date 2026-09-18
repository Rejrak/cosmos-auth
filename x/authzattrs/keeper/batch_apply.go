package keeper

import (
	"context"
	"fmt"

	"alpha/x/authzattrs/types"
)

// ApplyAuthorizationBatch validates the entire batch before writing records, then
// writes replay state last. The caller must propagate errors within a Cosmos
// transaction/cache context so low-level storage failures roll back all writes.
func (k Keeper) ApplyAuthorizationBatch(ctx context.Context, currentHeight int64, expectedChainID string, batch *types.AuthorizationBatch) (uint64, [32]byte, int, error) {
	if batch == nil || batch.SignDoc == nil {
		return 0, [32]byte{}, 0, types.ErrInvalidBatchSignDoc
	}
	doc := batch.SignDoc
	if doc.Domain != types.AuthorizationBatchDomain {
		return 0, [32]byte{}, 0, types.ErrBatchBadDomain
	}
	if doc.ChainId == "" || doc.ChainId != expectedChainID {
		return 0, [32]byte{}, 0, types.ErrBatchChainIDMismatch
	}
	if currentHeight <= 0 {
		return 0, [32]byte{}, 0, types.ErrInvalidBatchSignDoc
	}
	if err := k.ValidateBatchReplay(ctx, doc.IssuerSetId, doc.BatchId); err != nil {
		return 0, [32]byte{}, 0, err
	}
	weight, hash, err := k.VerifyBatchSignaturesAndQuorum(ctx, currentHeight, expectedChainID, batch)
	if err != nil {
		return 0, [32]byte{}, 0, err
	}
	records, err := k.ValidateBatchRecordMutations(ctx, doc)
	if err != nil {
		return 0, [32]byte{}, 0, err
	}
	for _, record := range records {
		if err := k.SetAuthorization(ctx, record); err != nil {
			return 0, [32]byte{}, 0, fmt.Errorf("write authorization: %w", err)
		}
	}
	if err := k.SetLastAppliedBatchID(ctx, doc.IssuerSetId, doc.BatchId); err != nil {
		return 0, [32]byte{}, 0, fmt.Errorf("write batch replay state: %w", err)
	}
	return weight, hash, len(records), nil
}
