package keeper_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"alpha/x/authzattrs/keeper"
	"alpha/x/authzattrs/types"
)

func TestParamsQuery(t *testing.T) {
	f := initFixture(t)
	require.NoError(t, f.keeper.Params.Set(f.ctx, types.DefaultParams()))
	query := keeper.NewQueryServerImpl(f.keeper)

	response, err := query.Params(f.ctx, &types.QueryParamsRequest{})
	require.NoError(t, err)
	require.Equal(t, types.DefaultParams(), response.Params)

	_, err = query.Params(f.ctx, nil)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestAuthorizationQuery(t *testing.T) {
	f := initFixture(t)
	stored := record()
	require.NoError(t, f.keeper.SetAuthorization(f.ctx, stored))
	query := keeper.NewQueryServerImpl(f.keeper)

	response, err := query.Authorization(f.ctx, &types.QueryAuthorizationRequest{
		Subject: stored.Subject, MsgTypeUrl: stored.MsgTypeUrl,
	})
	require.NoError(t, err)
	require.True(t, response.Found)
	require.Equal(t, stored, response.Authorization)

	missing, err := query.Authorization(f.ctx, &types.QueryAuthorizationRequest{
		Subject: addrString(3), MsgTypeUrl: types.MsgSendTypeURL,
	})
	require.NoError(t, err)
	require.False(t, missing.Found)
	require.Equal(t, types.AuthorizationRecord{}, missing.Authorization)

	for _, request := range []*types.QueryAuthorizationRequest{
		{Subject: "invalid", MsgTypeUrl: types.MsgSendTypeURL},
		{Subject: strings.ToUpper(stored.Subject), MsgTypeUrl: types.MsgSendTypeURL},
		{Subject: stored.Subject, MsgTypeUrl: "/unsupported.Msg"},
	} {
		_, err = query.Authorization(f.ctx, request)
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	}

	after, found, err := f.keeper.GetAuthorization(f.ctx, stored.Subject, stored.MsgTypeUrl)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, stored, after)
}

func TestCurrentIssuerSetQuery(t *testing.T) {
	f := initFixture(t)
	issuerSet := types.IssuerSet{
		IssuerSetId: 9, Active: true, PolicyId: "policy-bank-send",
		MsgTypeUrl: types.MsgSendTypeURL, ThresholdWeight: 5,
	}
	require.NoError(t, f.keeper.SetIssuerSet(f.ctx, issuerSet))
	require.NoError(t, f.keeper.SetCurrentIssuerSet(f.ctx, issuerSet.PolicyId, issuerSet.MsgTypeUrl, issuerSet.IssuerSetId))
	query := keeper.NewQueryServerImpl(f.keeper)

	response, err := query.CurrentIssuerSet(f.ctx, &types.QueryCurrentIssuerSetRequest{
		PolicyId: issuerSet.PolicyId, MsgTypeUrl: issuerSet.MsgTypeUrl,
	})
	require.NoError(t, err)
	require.True(t, response.Found)
	require.Equal(t, issuerSet.IssuerSetId, response.IssuerSetId)

	missing, err := query.CurrentIssuerSet(f.ctx, &types.QueryCurrentIssuerSetRequest{
		PolicyId: "missing", MsgTypeUrl: types.MsgSendTypeURL,
	})
	require.NoError(t, err)
	require.False(t, missing.Found)
	require.Zero(t, missing.IssuerSetId)

	for _, request := range []*types.QueryCurrentIssuerSetRequest{
		{MsgTypeUrl: types.MsgSendTypeURL},
		{PolicyId: issuerSet.PolicyId, MsgTypeUrl: "/unsupported.Msg"},
	} {
		_, err = query.CurrentIssuerSet(f.ctx, request)
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	}

	after, found, err := f.keeper.GetCurrentIssuerSet(f.ctx, issuerSet.PolicyId, issuerSet.MsgTypeUrl)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, issuerSet.IssuerSetId, after)
}

func TestLastAppliedBatchIDQuery(t *testing.T) {
	f := initFixture(t)
	require.NoError(t, f.keeper.SetLastAppliedBatchID(f.ctx, 9, 12))
	query := keeper.NewQueryServerImpl(f.keeper)

	response, err := query.LastAppliedBatchID(f.ctx, &types.QueryLastAppliedBatchIDRequest{IssuerSetId: 9})
	require.NoError(t, err)
	require.True(t, response.Found)
	require.Equal(t, uint64(12), response.BatchId)

	missing, err := query.LastAppliedBatchID(f.ctx, &types.QueryLastAppliedBatchIDRequest{IssuerSetId: 10})
	require.NoError(t, err)
	require.False(t, missing.Found)
	require.Zero(t, missing.BatchId)

	_, err = query.LastAppliedBatchID(f.ctx, &types.QueryLastAppliedBatchIDRequest{})
	require.Equal(t, codes.InvalidArgument, status.Code(err))

	after, found, err := f.keeper.GetLastAppliedBatchID(f.ctx, 9)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, uint64(12), after)
}
