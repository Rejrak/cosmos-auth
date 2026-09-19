package authzattrs

import (
	autocliv1 "cosmossdk.io/api/cosmos/autocli/v1"

	"alpha/x/authzattrs/types"
)

func (AppModule) AutoCLIOptions() *autocliv1.ModuleOptions {
	return &autocliv1.ModuleOptions{
		Query: &autocliv1.ServiceCommandDescriptor{
			Service: types.Query_serviceDesc.ServiceName,
			RpcCommandOptions: []*autocliv1.RpcCommandOptions{{
				RpcMethod: "Params",
				Use:       "params",
				Short:     "Shows the authzattrs module parameters",
			}},
		},
		Tx: &autocliv1.ServiceCommandDescriptor{
			Service: types.Msg_serviceDesc.ServiceName,
			RpcCommandOptions: []*autocliv1.RpcCommandOptions{
				{RpcMethod: "UpdateParams", Skip: true},
				{RpcMethod: "BatchUpsertAuthorizations", Skip: true},
			},
		},
	}
}
