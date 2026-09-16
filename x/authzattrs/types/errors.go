package types

import "cosmossdk.io/errors"

var ErrInvalidSigner = errors.Register(ModuleName, 1100, "expected module authority as signer")
