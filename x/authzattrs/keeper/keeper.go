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

	Schema         collections.Schema
	Params         collections.Item[types.Params]
	Authorizations collections.Map[collections.Pair[string, string], types.AuthorizationRecord]
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
