package keeper_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"alpha/x/authzattrs/keeper"
	"alpha/x/authzattrs/types"
)

func TestMsgUpdateParams(t *testing.T) {
	f := initFixture(t)
	server := keeper.NewMsgServerImpl(f.keeper)
	authority, err := f.addressCodec.BytesToString(f.keeper.GetAuthority())
	require.NoError(t, err)

	_, err = server.UpdateParams(f.ctx, &types.MsgUpdateParams{Authority: "invalid"})
	require.ErrorContains(t, err, "invalid authority")

	_, err = server.UpdateParams(f.ctx, &types.MsgUpdateParams{Authority: authority, Params: types.DefaultParams()})
	require.NoError(t, err)
}
