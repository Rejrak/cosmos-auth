package keeper

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"math"

	"alpha/x/authzattrs/types"
)

// VerifyBatchSignaturesAndQuorum reads registry state without writing it.
// It verifies all supplied signatures over canonical sign bytes, even after
// threshold is reached. Replay and mutation checks belong to the caller.
func (k Keeper) VerifyBatchSignaturesAndQuorum(ctx context.Context, currentHeight int64, expectedChainID string, batch *types.AuthorizationBatch) (uint64, [32]byte, error) {
	if batch == nil || batch.SignDoc == nil {
		return 0, [32]byte{}, types.ErrInvalidBatchSignDoc
	}
	doc := batch.SignDoc
	if doc.Domain != types.AuthorizationBatchDomain {
		return 0, [32]byte{}, types.ErrBatchBadDomain
	}
	if doc.ChainId == "" || doc.ChainId != expectedChainID {
		return 0, [32]byte{}, types.ErrBatchChainIDMismatch
	}
	if currentHeight <= 0 {
		return 0, [32]byte{}, types.ErrInvalidBatchSignDoc
	}
	signBytes, hash, err := types.CanonicalBatchSignBytes(doc)
	if err != nil {
		return 0, [32]byte{}, err
	}
	current, found, err := k.GetCurrentIssuerSet(ctx, doc.PolicyId, types.MsgSendTypeURL)
	if err != nil {
		return 0, [32]byte{}, fmt.Errorf("%w: read current issuer set: %v", types.ErrInvalidBatchSignDoc, err)
	}
	if !found || current != doc.IssuerSetId {
		return 0, [32]byte{}, types.ErrBatchStaleIssuerSet
	}
	set, found, err := k.GetIssuerSet(ctx, current)
	if err != nil {
		return 0, [32]byte{}, fmt.Errorf("%w: read issuer set: %v", types.ErrInvalidBatchSignDoc, err)
	}
	if !found {
		return 0, [32]byte{}, types.ErrBatchStaleIssuerSet
	}
	if !set.Active {
		return 0, [32]byte{}, types.ErrBatchIssuerInactive
	}
	if set.IssuerSetId != doc.IssuerSetId || set.PolicyId != doc.PolicyId || set.MsgTypeUrl != types.MsgSendTypeURL {
		return 0, [32]byte{}, types.ErrBatchIssuerOutOfScope
	}
	if err := set.Validate(); err != nil {
		return 0, [32]byte{}, fmt.Errorf("%w: %v", types.ErrInvalidBatchSignDoc, err)
	}
	seen := make(map[string]struct{}, len(batch.Signatures))
	for _, signature := range batch.Signatures {
		if signature == nil || signature.IssuerId == "" || len(signature.Signature) != ed25519.SignatureSize {
			return 0, [32]byte{}, types.ErrBatchBadSignature
		}
		if _, duplicate := seen[signature.IssuerId]; duplicate {
			return 0, [32]byte{}, types.ErrBatchDuplicateSignature
		}
		seen[signature.IssuerId] = struct{}{}
	}
	var total uint64
	for _, signature := range batch.Signatures {
		issuer, found, err := k.GetIssuer(ctx, doc.IssuerSetId, signature.IssuerId)
		if err != nil {
			return 0, [32]byte{}, fmt.Errorf("%w: read issuer: %v", types.ErrInvalidBatchSignDoc, err)
		}
		if !found {
			return 0, [32]byte{}, types.ErrBatchUnknownIssuer
		}
		if issuer.IssuerSetId != doc.IssuerSetId || issuer.IssuerId != signature.IssuerId {
			return 0, [32]byte{}, types.ErrBatchIssuerOutOfScope
		}
		if !issuer.Active {
			return 0, [32]byte{}, types.ErrBatchIssuerInactive
		}
		if err := issuer.Validate(); err != nil {
			return 0, [32]byte{}, fmt.Errorf("%w: %v", types.ErrInvalidBatchSignDoc, err)
		}
		if currentHeight < issuer.ValidFromHeight || currentHeight > issuer.ValidUntilHeight {
			return 0, [32]byte{}, types.ErrBatchIssuerInactive
		}
		if !ed25519.Verify(ed25519.PublicKey(issuer.PublicKey), signBytes, signature.Signature) {
			return 0, [32]byte{}, types.ErrBatchBadSignature
		}
		if total > math.MaxUint64-issuer.Weight {
			return 0, [32]byte{}, types.ErrInvalidBatchSignDoc
		}
		total += issuer.Weight
	}
	if total < set.ThresholdWeight {
		return 0, [32]byte{}, types.ErrBatchQuorumNotMet
	}
	return total, hash, nil
}
