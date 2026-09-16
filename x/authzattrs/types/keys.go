package types

import "cosmossdk.io/collections"

const (
	ModuleName    = "authzattrs"
	StoreKey      = ModuleName
	GovModuleName = "gov"
)

var ParamsKey = collections.NewPrefix("p_authzattrs")
