package keeper_test

import (
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
