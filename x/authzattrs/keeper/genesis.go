package keeper

import (
	"context"

	"cosmossdk.io/collections"

	"alpha/x/authzattrs/types"
)

func (k Keeper) InitGenesis(ctx context.Context, genState types.GenesisState) error {
	if err := genState.Validate(); err != nil {
		return err
	}
	if err := k.Params.Set(ctx, genState.Params); err != nil {
		return err
	}
	for _, record := range genState.Authorizations {
		if err := k.SetAuthorization(ctx, record); err != nil {
			return err
		}
	}
	return nil
}

func (k Keeper) ExportGenesis(ctx context.Context) (*types.GenesisState, error) {
	params, err := k.Params.Get(ctx)
	if err != nil {
		return nil, err
	}
	genState := &types.GenesisState{Params: params, Authorizations: []types.AuthorizationRecord{}}
	err = k.Authorizations.Walk(ctx, nil, func(_ collections.Pair[string, string], record types.AuthorizationRecord) (bool, error) {
		genState.Authorizations = append(genState.Authorizations, record)
		return false, nil
	})
	return genState, err
}
