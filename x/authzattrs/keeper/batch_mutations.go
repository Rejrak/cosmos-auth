package keeper

import (
	"context"
	"fmt"

	"alpha/x/authzattrs/types"
)

// ValidateBatchRecordMutations returns detached, canonically ordered records.
// It only reads CURRENT authorizations; application and replay writes are separate.
func (k Keeper) ValidateBatchRecordMutations(ctx context.Context, signDoc *types.AuthorizationBatchSignDoc) ([]types.AuthorizationRecord, error) {
	canonical, err := types.CanonicalizeBatchSignDoc(signDoc)
	if err != nil {
		return nil, err
	}
	records := make([]types.AuthorizationRecord, 0, len(canonical.Records))
	for _, incoming := range canonical.Records {
		current, found, err := k.GetAuthorization(ctx, incoming.Subject, incoming.MsgTypeUrl)
		if err != nil {
			return nil, fmt.Errorf("%w: read CURRENT: %w", types.ErrInvalidBatchSignDoc, err)
		}
		if found {
			if err := current.Validate(); err != nil {
				return nil, fmt.Errorf("%w: malformed CURRENT: %v", types.ErrInvalidBatchSignDoc, err)
			}
		}
		if incoming.Revoked {
			if !found || current.Revoked ||
				incoming.AuthorizationId != current.AuthorizationId ||
				incoming.Subject != current.Subject ||
				incoming.MsgTypeUrl != current.MsgTypeUrl ||
				incoming.PolicyId != current.PolicyId ||
				incoming.PolicyVersion != current.PolicyVersion ||
				incoming.ValidFromHeight != current.ValidFromHeight ||
				incoming.ValidUntilHeight != current.ValidUntilHeight ||
				incoming.BankSendConstraints.Denom != current.BankSendConstraints.Denom ||
				incoming.BankSendConstraints.Receiver != current.BankSendConstraints.Receiver ||
				incoming.BankSendConstraints.MaxAmount != current.BankSendConstraints.MaxAmount {
				return nil, types.ErrBatchStaleRevocation
			}
		} else if found && incoming.AuthorizationId == current.AuthorizationId {
			return nil, types.ErrInvalidBatchSignDoc
		}
		// CanonicalizeBatchSignDoc already explicitly copies every defined record
		// and constraint field. These values cannot alias the caller's protobufs.
		records = append(records, *incoming)
	}
	return records, nil
}
