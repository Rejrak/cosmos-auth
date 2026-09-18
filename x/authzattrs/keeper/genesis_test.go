package keeper_test

import (
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/require"

	"alpha/x/authzattrs/types"
)

func TestGenesisInitExport(t *testing.T) {
	f := initFixture(t)
	firstSet := genesisIssuerSet(1, "policy-a")
	secondSet := genesisIssuerSet(2, "policy-b")
	input := *types.DefaultGenesis()
	input.Authorizations = []types.AuthorizationRecord{record()}
	input.IssuerSets = []types.IssuerSet{secondSet, firstSet}
	input.Issuers = []types.Issuer{genesisIssuer(2), genesisIssuer(1)}
	input.CurrentIssuerSets = []types.CurrentIssuerSetSelection{
		{PolicyId: secondSet.PolicyId, MsgTypeUrl: secondSet.MsgTypeUrl, IssuerSetId: secondSet.IssuerSetId},
		{PolicyId: firstSet.PolicyId, MsgTypeUrl: firstSet.MsgTypeUrl, IssuerSetId: firstSet.IssuerSetId},
	}
	require.NoError(t, f.keeper.InitGenesis(f.ctx, input))
	got, err := f.keeper.ExportGenesis(f.ctx)
	require.NoError(t, err)

	want := input
	want.IssuerSets = []types.IssuerSet{firstSet, secondSet}
	want.Issuers = []types.Issuer{genesisIssuer(1), genesisIssuer(2)}
	want.CurrentIssuerSets = []types.CurrentIssuerSetSelection{
		{PolicyId: firstSet.PolicyId, MsgTypeUrl: firstSet.MsgTypeUrl, IssuerSetId: firstSet.IssuerSetId},
		{PolicyId: secondSet.PolicyId, MsgTypeUrl: secondSet.MsgTypeUrl, IssuerSetId: secondSet.IssuerSetId},
	}
	require.Equal(t, &want, got)
}

func genesisIssuerSet(id uint64, policyID string) types.IssuerSet {
	return types.IssuerSet{
		IssuerSetId: id, Active: true, PolicyId: policyID,
		MsgTypeUrl: types.MsgSendTypeURL, ThresholdWeight: 1,
	}
}

func genesisIssuer(issuerSetID uint64) types.Issuer {
	return types.Issuer{
		IssuerSetId: issuerSetID, IssuerId: "issuer-shared",
		KeyType:   types.IssuerKeyType_ISSUER_KEY_TYPE_ED25519,
		PublicKey: make([]byte, ed25519.PublicKeySize), Weight: 1, Active: true,
		ValidFromHeight: 1, ValidUntilHeight: 100,
	}
}
