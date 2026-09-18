package keeper

import (
	"context"
	"errors"
	"fmt"

	"cosmossdk.io/collections"
	"cosmossdk.io/core/address"
	corestore "cosmossdk.io/core/store"
	"github.com/cosmos/cosmos-sdk/codec"

	"alpha/x/authzattrs/types"
)

type Keeper struct {
	addressCodec address.Codec
	authority    []byte

	Schema              collections.Schema
	Params              collections.Item[types.Params]
	Authorizations      collections.Map[collections.Pair[string, string], types.AuthorizationRecord]
	IssuerSets          collections.Map[uint64, types.IssuerSet]
	Issuers             collections.Map[collections.Pair[uint64, string], types.Issuer]
	CurrentIssuerSets   collections.Map[collections.Pair[string, string], uint64]
	LastAppliedBatchIDs collections.Map[uint64, uint64]
}

func NewKeeper(storeService corestore.KVStoreService, cdc codec.Codec, addressCodec address.Codec, authority []byte) Keeper {
	if _, err := addressCodec.BytesToString(authority); err != nil {
		panic(fmt.Sprintf("invalid authority address %s: %s", authority, err))
	}

	sb := collections.NewSchemaBuilder(storeService)
	k := Keeper{
		addressCodec: addressCodec,
		authority:    authority,
		Params:       collections.NewItem(sb, types.ParamsKey, "params", codec.CollValue[types.Params](cdc)),
		Authorizations: collections.NewMap(
			sb,
			types.AuthorizationsKey,
			"authorizations",
			collections.PairKeyCodec(collections.StringKey, collections.StringKey),
			codec.CollValue[types.AuthorizationRecord](cdc),
		),
		IssuerSets: collections.NewMap(
			sb,
			types.IssuerSetsKey,
			"issuer_sets",
			collections.Uint64Key,
			codec.CollValue[types.IssuerSet](cdc),
		),
		Issuers: collections.NewMap(
			sb,
			types.IssuersKey,
			"issuers",
			collections.PairKeyCodec(collections.Uint64Key, collections.StringKey),
			codec.CollValue[types.Issuer](cdc),
		),
		CurrentIssuerSets: collections.NewMap(
			sb,
			types.CurrentIssuerSetsKey,
			"current_issuer_sets",
			collections.PairKeyCodec(collections.StringKey, collections.StringKey),
			collections.Uint64Value,
		),
		LastAppliedBatchIDs: collections.NewMap(
			sb,
			types.LastAppliedBatchIDsKey,
			"last_applied_batch_ids",
			collections.Uint64Key,
			collections.Uint64Value,
		),
	}
	var err error
	k.Schema, err = sb.Build()
	if err != nil {
		panic(err)
	}
	return k
}

func (k Keeper) GetAuthority() []byte { return k.authority }

func authorizationKey(subject, msgTypeURL string) collections.Pair[string, string] {
	return collections.Join(subject, msgTypeURL)
}

func (k Keeper) SetAuthorization(ctx context.Context, record types.AuthorizationRecord) error {
	if err := record.Validate(); err != nil {
		return fmt.Errorf("invalid authorization record: %w", err)
	}
	return k.Authorizations.Set(ctx, authorizationKey(record.Subject, record.MsgTypeUrl), record)
}

func (k Keeper) GetAuthorization(ctx context.Context, subject, msgTypeURL string) (types.AuthorizationRecord, bool, error) {
	record, err := k.Authorizations.Get(ctx, authorizationKey(subject, msgTypeURL))
	if errors.Is(err, collections.ErrNotFound) {
		return types.AuthorizationRecord{}, false, nil
	}
	return record, err == nil, err
}

func (k Keeper) HasAuthorization(ctx context.Context, subject, msgTypeURL string) (bool, error) {
	return k.Authorizations.Has(ctx, authorizationKey(subject, msgTypeURL))
}

func (k Keeper) SetIssuerSet(ctx context.Context, issuerSet types.IssuerSet) error {
	if err := issuerSet.Validate(); err != nil {
		return fmt.Errorf("invalid issuer set: %w", err)
	}
	return k.IssuerSets.Set(ctx, issuerSet.IssuerSetId, issuerSet)
}

func (k Keeper) GetIssuerSet(ctx context.Context, issuerSetID uint64) (types.IssuerSet, bool, error) {
	issuerSet, err := k.IssuerSets.Get(ctx, issuerSetID)
	if errors.Is(err, collections.ErrNotFound) {
		return types.IssuerSet{}, false, nil
	}
	return issuerSet, err == nil, err
}

func issuerKey(issuerSetID uint64, issuerID string) collections.Pair[uint64, string] {
	return collections.Join(issuerSetID, issuerID)
}

func (k Keeper) SetIssuer(ctx context.Context, issuer types.Issuer) error {
	if err := issuer.Validate(); err != nil {
		return fmt.Errorf("invalid issuer: %w", err)
	}
	return k.Issuers.Set(ctx, issuerKey(issuer.IssuerSetId, issuer.IssuerId), issuer)
}

func (k Keeper) GetIssuer(ctx context.Context, issuerSetID uint64, issuerID string) (types.Issuer, bool, error) {
	issuer, err := k.Issuers.Get(ctx, issuerKey(issuerSetID, issuerID))
	if errors.Is(err, collections.ErrNotFound) {
		return types.Issuer{}, false, nil
	}
	return issuer, err == nil, err
}

func currentIssuerSetKey(policyID, msgTypeURL string) collections.Pair[string, string] {
	return collections.Join(policyID, msgTypeURL)
}

func (k Keeper) SetCurrentIssuerSet(ctx context.Context, policyID, msgTypeURL string, issuerSetID uint64) error {
	issuerSet, found, err := k.GetIssuerSet(ctx, issuerSetID)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("issuer set %d not found", issuerSetID)
	}
	if !issuerSet.Active {
		return fmt.Errorf("issuer set %d is inactive", issuerSetID)
	}
	if issuerSet.PolicyId != policyID || issuerSet.MsgTypeUrl != msgTypeURL {
		return fmt.Errorf("issuer set %d policy or message scope mismatch", issuerSetID)
	}
	return k.CurrentIssuerSets.Set(ctx, currentIssuerSetKey(policyID, msgTypeURL), issuerSetID)
}

func (k Keeper) GetCurrentIssuerSet(ctx context.Context, policyID, msgTypeURL string) (uint64, bool, error) {
	issuerSetID, err := k.CurrentIssuerSets.Get(ctx, currentIssuerSetKey(policyID, msgTypeURL))
	if errors.Is(err, collections.ErrNotFound) {
		return 0, false, nil
	}
	return issuerSetID, err == nil, err
}

func (k Keeper) GetLastAppliedBatchID(ctx context.Context, issuerSetID uint64) (uint64, bool, error) {
	if issuerSetID == 0 {
		return 0, false, types.ErrInvalidBatchSignDoc
	}
	batchID, err := k.LastAppliedBatchIDs.Get(ctx, issuerSetID)
	if errors.Is(err, collections.ErrNotFound) {
		return 0, false, nil
	}
	return batchID, err == nil, err
}

func (k Keeper) SetLastAppliedBatchID(ctx context.Context, issuerSetID, batchID uint64) error {
	if issuerSetID == 0 || batchID == 0 {
		return types.ErrInvalidBatchSignDoc
	}
	return k.LastAppliedBatchIDs.Set(ctx, issuerSetID, batchID)
}

// ValidateBatchReplay checks monotonicity without consuming the batch ID.
func (k Keeper) ValidateBatchReplay(ctx context.Context, issuerSetID, batchID uint64) error {
	if issuerSetID == 0 || batchID == 0 {
		return types.ErrInvalidBatchSignDoc
	}
	lastApplied, found, err := k.GetLastAppliedBatchID(ctx, issuerSetID)
	if err != nil {
		return err
	}
	if found && batchID <= lastApplied {
		return types.ErrBatchReplay
	}
	return nil
}
