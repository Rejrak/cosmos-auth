package v2

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"

	"cosmossdk.io/core/address"
	"cosmossdk.io/math"
	"github.com/cosmos/cosmos-sdk/types"
)

const (
	CertificateDomainV2   = "alpha.authzattrs.certificate.v2"
	CertificateTypeURLV2  = "/alpha.authzattrs.v2.AuthorizationCertificateV2"
	MaxCertificateBytesV2 = 4096
	MaxSignaturesV2       = 16
	MaxFeeCoinsV2         = 4
)

var (
	ErrInvalidCertificateV2 = errors.New("AUTHZ_V2_INVALID_CERTIFICATE")
	ErrBadDomainV2          = errors.New("AUTHZ_V2_BAD_DOMAIN")
	ErrChainIDMismatchV2    = errors.New("AUTHZ_V2_CHAIN_ID_MISMATCH")
	ErrNotYetValidV2        = errors.New("AUTHZ_V2_NOT_YET_VALID")
	ErrExpiredV2            = errors.New("AUTHZ_V2_EXPIRED")
	ErrStaleIssuerSetV2     = errors.New("AUTHZ_V2_STALE_ISSUER_SET")
	ErrUnknownIssuerV2      = errors.New("AUTHZ_V2_UNKNOWN_ISSUER")
	ErrIssuerInactiveV2     = errors.New("AUTHZ_V2_ISSUER_INACTIVE")
	ErrIssuerOutOfScopeV2   = errors.New("AUTHZ_V2_ISSUER_OUT_OF_SCOPE")
	ErrBadSignatureV2       = errors.New("AUTHZ_V2_BAD_SIGNATURE")
	ErrDuplicateSignatureV2 = errors.New("AUTHZ_V2_DUPLICATE_SIGNATURE")
	ErrQuorumNotMetV2       = errors.New("AUTHZ_V2_QUORUM_NOT_MET")
)

func canonicalAddress(codec address.Codec, value string) bool {
	if codec == nil {
		return false
	}
	bz, err := codec.StringToBytes(value)
	if err != nil {
		return false
	}
	canonical, err := codec.BytesToString(bz)
	return err == nil && canonical == value
}

func canonicalAmount(value string, positive bool) bool {
	amount, ok := math.NewIntFromString(value)
	return ok && amount.String() == value && (amount.IsPositive() || (!positive && amount.IsZero()))
}

// CanonicalizeCertificateSignDocV2 validates and rebuilds only defined fields.
// It never retains caller-owned pointers or unknown protobuf fields.
func CanonicalizeCertificateSignDocV2(input *AuthorizationCertificateSignDocV2, codec address.Codec) (*AuthorizationCertificateSignDocV2, error) {
	if input == nil || input.Intent == nil {
		return nil, ErrInvalidCertificateV2
	}
	if input.Domain != CertificateDomainV2 {
		return nil, ErrBadDomainV2
	}
	intent := input.Intent
	if intent.ChainId == "" || !canonicalAddress(codec, intent.Subject) || !canonicalAddress(codec, intent.Receiver) {
		return nil, fmt.Errorf("%w: invalid intent address or chain ID", ErrInvalidCertificateV2)
	}
	if err := types.ValidateDenom(intent.Denom); err != nil || !canonicalAmount(intent.Amount, true) {
		return nil, fmt.Errorf("%w: invalid transfer coin", ErrInvalidCertificateV2)
	}
	if input.PolicyId == "" || input.PolicyVersion == 0 || len(input.PolicyHash) != sha256.Size ||
		input.IssuerSetId == 0 || input.ValidFromHeight <= 0 || input.ValidUntilHeight < input.ValidFromHeight {
		return nil, fmt.Errorf("%w: invalid certificate metadata", ErrInvalidCertificateV2)
	}
	if len(intent.FeeAmount) > MaxFeeCoinsV2 {
		return nil, fmt.Errorf("%w: too many fee coins", ErrInvalidCertificateV2)
	}
	fees := make([]*FeeCoinV2, 0, len(intent.FeeAmount))
	for _, fee := range intent.FeeAmount {
		if fee == nil {
			return nil, fmt.Errorf("%w: nil fee coin", ErrInvalidCertificateV2)
		}
		if err := types.ValidateDenom(fee.Denom); err != nil || !canonicalAmount(fee.Amount, false) {
			return nil, fmt.Errorf("%w: invalid fee coin", ErrInvalidCertificateV2)
		}
		fees = append(fees, &FeeCoinV2{Denom: fee.Denom, Amount: fee.Amount})
	}
	sort.Slice(fees, func(i, j int) bool { return fees[i].Denom < fees[j].Denom })
	for i := 1; i < len(fees); i++ {
		if fees[i-1].Denom == fees[i].Denom {
			return nil, fmt.Errorf("%w: duplicate fee denom", ErrInvalidCertificateV2)
		}
	}
	return &AuthorizationCertificateSignDocV2{
		Domain: input.Domain,
		Intent: &AuthorizationIntentV2{
			ChainId: intent.ChainId, Subject: intent.Subject, Receiver: intent.Receiver,
			Denom: intent.Denom, Amount: intent.Amount, AccountNumber: intent.AccountNumber,
			Sequence: intent.Sequence, TimeoutHeight: intent.TimeoutHeight, Memo: intent.Memo,
			FeeAmount: fees, GasLimit: intent.GasLimit,
		},
		PolicyId: input.PolicyId, PolicyVersion: input.PolicyVersion,
		PolicyHash: append([]byte(nil), input.PolicyHash...), IssuerSetId: input.IssuerSetId,
		ValidFromHeight: input.ValidFromHeight, ValidUntilHeight: input.ValidUntilHeight,
	}, nil
}

// CanonicalCertificateSignBytesV2 returns deterministic protobuf bytes and their digest.
func CanonicalCertificateSignBytesV2(input *AuthorizationCertificateSignDocV2, codec address.Codec) ([]byte, [sha256.Size]byte, error) {
	canonical, err := CanonicalizeCertificateSignDocV2(input, codec)
	if err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	// The generated marshaler is deterministic for this rebuilt, map-free doc:
	// its only repeated field (fee_amount) was sorted above.
	signBytes, err := canonical.Marshal()
	if err != nil {
		return nil, [sha256.Size]byte{}, fmt.Errorf("%w: marshal sign doc: %v", ErrInvalidCertificateV2, err)
	}
	return signBytes, sha256.Sum256(signBytes), nil
}

// ValidateCertificateV2 checks the in-memory envelope without registry reads.
// V2.1b must additionally enforce the raw Any.value size and strict wire-field rules.
func ValidateCertificateV2(input *AuthorizationCertificateV2, codec address.Codec) ([]byte, [sha256.Size]byte, error) {
	if input == nil || input.SignDoc == nil || input.Size() > MaxCertificateBytesV2 {
		return nil, [sha256.Size]byte{}, ErrInvalidCertificateV2
	}
	signBytes, digest, err := CanonicalCertificateSignBytesV2(input.SignDoc, codec)
	if err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	if len(input.Signatures) == 0 || len(input.Signatures) > MaxSignaturesV2 {
		return nil, [sha256.Size]byte{}, ErrInvalidCertificateV2
	}
	seen := make(map[string]struct{}, len(input.Signatures))
	for _, signature := range input.Signatures {
		if signature == nil || signature.IssuerId == "" || len(signature.Signature) != ed25519.SignatureSize {
			return nil, [sha256.Size]byte{}, ErrBadSignatureV2
		}
		if _, duplicate := seen[signature.IssuerId]; duplicate {
			return nil, [sha256.Size]byte{}, ErrDuplicateSignatureV2
		}
		seen[signature.IssuerId] = struct{}{}
	}
	return signBytes, digest, nil
}
