package types_test

import (
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/require"

	"alpha/x/authzattrs/types"
)

func TestGenesisState(t *testing.T) {
	genesis := types.DefaultGenesis()
	require.Equal(t, types.DefaultParams(), genesis.Params)
	require.NotNil(t, genesis.IssuerSets)
	require.NotNil(t, genesis.Issuers)
	require.NotNil(t, genesis.CurrentIssuerSets)
	require.Empty(t, genesis.IssuerSets)
	require.Empty(t, genesis.Issuers)
	require.Empty(t, genesis.CurrentIssuerSets)
	require.NoError(t, genesis.Validate())
}

func TestGenesisRegistryValidation(t *testing.T) {
	tests := map[string]func(*types.GenesisState){
		"duplicate issuer set": func(genesis *types.GenesisState) {
			genesis.IssuerSets = append(genesis.IssuerSets, genesis.IssuerSets[0])
		},
		"duplicate issuer key": func(genesis *types.GenesisState) {
			genesis.Issuers = append(genesis.Issuers, genesis.Issuers[0])
		},
		"issuer missing set": func(genesis *types.GenesisState) {
			genesis.Issuers[0].IssuerSetId = 99
		},
		"duplicate current selection": func(genesis *types.GenesisState) {
			genesis.CurrentIssuerSets = append(genesis.CurrentIssuerSets, genesis.CurrentIssuerSets[0])
		},
		"current selection missing set": func(genesis *types.GenesisState) {
			genesis.CurrentIssuerSets[0].IssuerSetId = 99
		},
		"current selection inactive set": func(genesis *types.GenesisState) {
			genesis.IssuerSets[0].Active = false
		},
		"current selection policy mismatch": func(genesis *types.GenesisState) {
			genesis.CurrentIssuerSets[0].PolicyId = "other-policy"
		},
		"current selection message mismatch": func(genesis *types.GenesisState) {
			genesis.CurrentIssuerSets[0].MsgTypeUrl = "/unsupported"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			genesis := validRegistryGenesis()
			mutate(&genesis)
			require.Error(t, genesis.Validate())
		})
	}
}

func validRegistryGenesis() types.GenesisState {
	issuerSet := types.IssuerSet{
		IssuerSetId: 1, Active: true, PolicyId: "policy-bank-send",
		MsgTypeUrl: types.MsgSendTypeURL, ThresholdWeight: 1,
	}
	return types.GenesisState{
		Params:     types.DefaultParams(),
		IssuerSets: []types.IssuerSet{issuerSet},
		Issuers: []types.Issuer{{
			IssuerSetId: 1, IssuerId: "issuer-a",
			KeyType:   types.IssuerKeyType_ISSUER_KEY_TYPE_ED25519,
			PublicKey: make([]byte, ed25519.PublicKeySize), Weight: 1, Active: true,
			ValidFromHeight: 1, ValidUntilHeight: 100,
		}},
		CurrentIssuerSets: []types.CurrentIssuerSetSelection{{
			PolicyId: issuerSet.PolicyId, MsgTypeUrl: issuerSet.MsgTypeUrl, IssuerSetId: issuerSet.IssuerSetId,
		}},
	}
}

func TestGenesisRejectsDuplicateLogicalKey(t *testing.T) {
	record := validAuthorization()
	replacement := record
	replacement.AuthorizationId = "auth-2"
	genesis := types.GenesisState{
		Params:         types.DefaultParams(),
		Authorizations: []types.AuthorizationRecord{record, replacement},
	}
	require.Error(t, genesis.Validate())
}
