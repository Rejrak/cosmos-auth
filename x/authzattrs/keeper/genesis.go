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
	for _, issuerSet := range genState.IssuerSets {
		if err := k.SetIssuerSet(ctx, issuerSet); err != nil {
			return err
		}
	}
	for _, issuer := range genState.Issuers {
		if err := k.SetIssuer(ctx, issuer); err != nil {
			return err
		}
	}
	for _, selection := range genState.CurrentIssuerSets {
		if err := k.SetCurrentIssuerSet(ctx, selection.PolicyId, selection.MsgTypeUrl, selection.IssuerSetId); err != nil {
			return err
		}
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
	genState := &types.GenesisState{
		Params:            params,
		Authorizations:    []types.AuthorizationRecord{},
		IssuerSets:        []types.IssuerSet{},
		Issuers:           []types.Issuer{},
		CurrentIssuerSets: []types.CurrentIssuerSetSelection{},
	}
	if err := k.Authorizations.Walk(ctx, nil, func(_ collections.Pair[string, string], record types.AuthorizationRecord) (bool, error) {
		genState.Authorizations = append(genState.Authorizations, record)
		return false, nil
	}); err != nil {
		return nil, err
	}
	if err := k.IssuerSets.Walk(ctx, nil, func(_ uint64, issuerSet types.IssuerSet) (bool, error) {
		genState.IssuerSets = append(genState.IssuerSets, issuerSet)
		return false, nil
	}); err != nil {
		return nil, err
	}
	if err := k.Issuers.Walk(ctx, nil, func(_ collections.Pair[uint64, string], issuer types.Issuer) (bool, error) {
		genState.Issuers = append(genState.Issuers, issuer)
		return false, nil
	}); err != nil {
		return nil, err
	}
	if err := k.CurrentIssuerSets.Walk(ctx, nil, func(key collections.Pair[string, string], issuerSetID uint64) (bool, error) {
		genState.CurrentIssuerSets = append(genState.CurrentIssuerSets, types.CurrentIssuerSetSelection{
			PolicyId: key.K1(), MsgTypeUrl: key.K2(), IssuerSetId: issuerSetID,
		})
		return false, nil
	}); err != nil {
		return nil, err
	}
	return genState, nil
}
