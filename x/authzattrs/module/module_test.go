package authzattrs_test

import (
	"testing"

	moduletestutil "github.com/cosmos/cosmos-sdk/types/module/testutil"
	"github.com/stretchr/testify/require"

	"alpha/x/authzattrs/keeper"
	authzattrs "alpha/x/authzattrs/module"
)

func TestDefaultAndValidateGenesis(t *testing.T) {
	encCfg := moduletestutil.MakeTestEncodingConfig(authzattrs.AppModule{})
	module := authzattrs.NewAppModule(encCfg.Codec, keeper.Keeper{})

	require.NoError(t, module.ValidateGenesis(encCfg.Codec, encCfg.TxConfig, module.DefaultGenesis(encCfg.Codec)))
	require.Error(t, module.ValidateGenesis(encCfg.Codec, encCfg.TxConfig, []byte("{")))
}
