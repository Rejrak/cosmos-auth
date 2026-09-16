package keeper

import "alpha/x/authzattrs/types"

type queryServer struct{ k Keeper }

func NewQueryServerImpl(k Keeper) types.QueryServer { return queryServer{k: k} }

var _ types.QueryServer = queryServer{}
