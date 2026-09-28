package keeper

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"math"

	"alpha/x/authzattrs/types"
	"alpha/x/authzattrs/v2"
)

// VerifyCertificateV2 reads only the chain-local issuer registry. It does not
// inspect V1 authorizations or batch replay state and makes no state writes.
func (k Keeper) VerifyCertificateV2(ctx context.Context, currentHeight int64, expectedChainID string, certificate *v2.AuthorizationCertificateV2) (uint64, [32]byte, error) {
	if currentHeight <= 0 || certificate == nil || certificate.SignDoc == nil || certificate.SignDoc.Intent == nil {
		return 0, [32]byte{}, v2.ErrInvalidCertificateV2
	}
	doc := certificate.SignDoc
	if doc.Domain != v2.CertificateDomainV2 {
		return 0, [32]byte{}, v2.ErrBadDomainV2
	}
	if expectedChainID == "" || doc.Intent.ChainId != expectedChainID {
		return 0, [32]byte{}, v2.ErrChainIDMismatchV2
	}
	signBytes, digest, err := v2.ValidateCertificateV2(certificate, k.addressCodec)
	if err != nil {
		return 0, [32]byte{}, err
	}
	if currentHeight < doc.ValidFromHeight {
		return 0, [32]byte{}, v2.ErrNotYetValidV2
	}
	if currentHeight > doc.ValidUntilHeight {
		return 0, [32]byte{}, v2.ErrExpiredV2
	}
	current, found, err := k.GetCurrentIssuerSet(ctx, doc.PolicyId, types.MsgSendTypeURL)
	if err != nil {
		return 0, [32]byte{}, fmt.Errorf("%w: read current issuer set: %v", v2.ErrInvalidCertificateV2, err)
	}
	if !found || current != doc.IssuerSetId {
		return 0, [32]byte{}, v2.ErrStaleIssuerSetV2
	}
	set, found, err := k.GetIssuerSet(ctx, current)
	if err != nil {
		return 0, [32]byte{}, fmt.Errorf("%w: read issuer set: %v", v2.ErrInvalidCertificateV2, err)
	}
	if !found {
		return 0, [32]byte{}, v2.ErrStaleIssuerSetV2
	}
	if !set.Active {
		return 0, [32]byte{}, v2.ErrIssuerInactiveV2
	}
	if set.IssuerSetId != doc.IssuerSetId || set.PolicyId != doc.PolicyId || set.MsgTypeUrl != types.MsgSendTypeURL {
		return 0, [32]byte{}, v2.ErrIssuerOutOfScopeV2
	}
	if err := set.Validate(); err != nil {
		return 0, [32]byte{}, fmt.Errorf("%w: invalid issuer set: %v", v2.ErrInvalidCertificateV2, err)
	}
	var total uint64
	for _, signature := range certificate.Signatures {
		issuer, found, err := k.GetIssuer(ctx, doc.IssuerSetId, signature.IssuerId)
		if err != nil {
			return 0, [32]byte{}, fmt.Errorf("%w: read issuer: %v", v2.ErrInvalidCertificateV2, err)
		}
		if !found {
			return 0, [32]byte{}, v2.ErrUnknownIssuerV2
		}
		if issuer.IssuerSetId != doc.IssuerSetId || issuer.IssuerId != signature.IssuerId {
			return 0, [32]byte{}, v2.ErrIssuerOutOfScopeV2
		}
		if !issuer.Active || currentHeight < issuer.ValidFromHeight || currentHeight > issuer.ValidUntilHeight {
			return 0, [32]byte{}, v2.ErrIssuerInactiveV2
		}
		if err := issuer.Validate(); err != nil {
			return 0, [32]byte{}, fmt.Errorf("%w: invalid issuer: %v", v2.ErrInvalidCertificateV2, err)
		}
		if !ed25519.Verify(ed25519.PublicKey(issuer.PublicKey), signBytes, signature.Signature) {
			return 0, [32]byte{}, v2.ErrBadSignatureV2
		}
		if total > math.MaxUint64-issuer.Weight {
			return 0, [32]byte{}, v2.ErrInvalidCertificateV2
		}
		total += issuer.Weight
	}
	if total < set.ThresholdWeight {
		return 0, [32]byte{}, v2.ErrQuorumNotMetV2
	}
	return total, digest, nil
}
