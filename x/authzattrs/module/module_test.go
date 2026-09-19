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

func TestValidateDemoIssuerGenesis(t *testing.T) {
	encCfg := moduletestutil.MakeTestEncodingConfig(authzattrs.AppModule{})
	module := authzattrs.NewAppModule(encCfg.Codec, keeper.Keeper{})
	genesis := []byte(`{
		"params": {},
		"authorizations": [],
		"issuer_sets": [{"issuer_set_id":"9","active":true,"policy_id":"policy-bank-send","msg_type_url":"/cosmos.bank.v1beta1.MsgSend","threshold_weight":"5"}],
		"issuers": [
			{"issuer_set_id":"9","issuer_id":"issuer-alpha","key_type":"ISSUER_KEY_TYPE_ED25519","public_key":"A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=","weight":"2","active":true,"valid_from_height":"1","valid_until_height":"9223372036854775807"},
			{"issuer_set_id":"9","issuer_id":"issuer-beta","key_type":"ISSUER_KEY_TYPE_ED25519","public_key":"Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc=","weight":"3","active":true,"valid_from_height":"1","valid_until_height":"9223372036854775807"}
		],
		"current_issuer_sets": [{"policy_id":"policy-bank-send","msg_type_url":"/cosmos.bank.v1beta1.MsgSend","issuer_set_id":"9"}],
		"last_applied_batch_ids": []
	}`)
	require.NoError(t, module.ValidateGenesis(encCfg.Codec, encCfg.TxConfig, genesis))
}
