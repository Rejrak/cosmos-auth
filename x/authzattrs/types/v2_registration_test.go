package types_test

import (
	"testing"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	moduletestutil "github.com/cosmos/cosmos-sdk/types/module/testutil"
	txtypes "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/stretchr/testify/require"

	module "alpha/x/authzattrs/module"
	"alpha/x/authzattrs/v2"
)

func TestV2CertificateExtensionOptionRegistration(t *testing.T) {
	registry := moduletestutil.MakeTestEncodingConfig(module.AppModule{}).InterfaceRegistry

	certificate := &v2.AuthorizationCertificateV2{}
	packed, err := codectypes.NewAnyWithValue(certificate)
	require.NoError(t, err)
	require.Equal(t, v2.CertificateTypeURLV2, packed.TypeUrl)
	var unpacked txtypes.TxExtensionOptionI
	require.NoError(t, registry.UnpackAny(packed, &unpacked))
	require.IsType(t, certificate, unpacked)

	// The same payload under a different URL is not the registered extension.
	alias := &codectypes.Any{TypeUrl: "type.googleapis.com/alpha.authzattrs.v2.AuthorizationCertificateV2", Value: packed.Value}
	var rejected txtypes.TxExtensionOptionI
	require.Error(t, registry.UnpackAny(alias, &rejected))
}
