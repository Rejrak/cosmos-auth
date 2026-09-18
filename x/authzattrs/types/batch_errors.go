package types

import "errors"

var (
	ErrBatchBadDomain          = errors.New("AUTHZ_BATCH_BAD_DOMAIN")
	ErrBatchChainIDMismatch    = errors.New("AUTHZ_BATCH_CHAIN_ID_MISMATCH")
	ErrBatchStaleIssuerSet     = errors.New("AUTHZ_BATCH_STALE_ISSUER_SET")
	ErrBatchIssuerInactive     = errors.New("AUTHZ_BATCH_ISSUER_INACTIVE")
	ErrBatchIssuerOutOfScope   = errors.New("AUTHZ_BATCH_ISSUER_OUT_OF_SCOPE")
	ErrBatchBadSignature       = errors.New("AUTHZ_BATCH_BAD_SIGNATURE")
	ErrBatchDuplicateSignature = errors.New("AUTHZ_BATCH_DUPLICATE_SIGNATURE")
	ErrBatchUnknownIssuer      = errors.New("AUTHZ_BATCH_UNKNOWN_ISSUER")
	ErrBatchQuorumNotMet       = errors.New("AUTHZ_BATCH_QUORUM_NOT_MET")
	ErrBatchReplay             = errors.New("AUTHZ_BATCH_REPLAY")
	ErrBatchStaleRevocation    = errors.New("AUTHZ_BATCH_STALE_REVOCATION")
)
