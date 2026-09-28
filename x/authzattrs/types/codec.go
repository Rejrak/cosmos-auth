package types

import (
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/msgservice"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"

	"alpha/x/authzattrs/v2"
)

func RegisterInterfaces(registrar codectypes.InterfaceRegistry) {
	registrar.RegisterImplementations((*sdk.Msg)(nil), &MsgUpdateParams{}, &MsgBatchUpsertAuthorizations{})
	registrar.RegisterImplementations((*txtypes.TxExtensionOptionI)(nil), &v2.AuthorizationCertificateV2{})
	msgservice.RegisterMsgServiceDesc(registrar, &_Msg_serviceDesc)
}
