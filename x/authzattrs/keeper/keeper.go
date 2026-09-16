package keeper

import (
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

	Schema collections.Schema
	Params collections.Item[types.Params]
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
	}
	var err error
	k.Schema, err = sb.Build()
	if err != nil {
		panic(err)
	}
	return k
}

func (k Keeper) GetAuthority() []byte { return k.authority }
