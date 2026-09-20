package authzattrs

import (
	autocliv1 "cosmossdk.io/api/cosmos/autocli/v1"

	"alpha/x/authzattrs/types"
)

func (AppModule) AutoCLIOptions() *autocliv1.ModuleOptions {
	return &autocliv1.ModuleOptions{
		Query: &autocliv1.ServiceCommandDescriptor{
			Service: types.Query_serviceDesc.ServiceName,
			RpcCommandOptions: []*autocliv1.RpcCommandOptions{
				{
					RpcMethod: "Params",
					Use:       "params",
					Short:     "Shows the authzattrs module parameters",
				},
				{
					RpcMethod: "Authorization",
					Use:       "authorization [subject] [msg-type-url]",
					Short:     "Shows the current authorization for a subject and message type",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{
						{ProtoField: "subject"},
						{ProtoField: "msg_type_url"},
					},
				},
				{
					RpcMethod: "CurrentIssuerSet",
					Use:       "current-issuer-set [policy-id] [msg-type-url]",
					Short:     "Shows the current issuer set for a policy and message type",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{
						{ProtoField: "policy_id"},
						{ProtoField: "msg_type_url"},
					},
				},
				{
					RpcMethod: "LastAppliedBatchID",
					Use:       "last-applied-batch-id [issuer-set-id]",
					Short:     "Shows the last applied batch ID for an issuer set",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{
						{ProtoField: "issuer_set_id"},
					},
				},
			},
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
