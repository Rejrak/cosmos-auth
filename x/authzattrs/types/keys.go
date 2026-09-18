package types

import "cosmossdk.io/collections"

const (
	ModuleName    = "authzattrs"
	StoreKey      = ModuleName
	GovModuleName = "gov"
)

var (
	ParamsKey            = collections.NewPrefix("p_authzattrs")
	AuthorizationsKey    = collections.NewPrefix("a_authzattrs")
	IssuerSetsKey        = collections.NewPrefix("s_authzattrs")
	IssuersKey           = collections.NewPrefix("i_authzattrs")
	CurrentIssuerSetsKey = collections.NewPrefix("c_authzattrs")
)
