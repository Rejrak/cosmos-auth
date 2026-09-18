package types

import (
	"crypto/ed25519"
	"fmt"
)

func (issuerSet IssuerSet) Validate() error {
	if issuerSet.IssuerSetId == 0 {
		return fmt.Errorf("issuer_set_id must be positive")
	}
	if issuerSet.PolicyId == "" {
		return fmt.Errorf("policy_id is empty")
	}
	if issuerSet.MsgTypeUrl != MsgSendTypeURL {
		return fmt.Errorf("unsupported msg_type_url %q", issuerSet.MsgTypeUrl)
	}
	if issuerSet.ThresholdWeight == 0 {
		return fmt.Errorf("threshold_weight must be positive")
	}
	return nil
}

func (issuer Issuer) Validate() error {
	if issuer.IssuerSetId == 0 {
		return fmt.Errorf("issuer_set_id must be positive")
	}
	if issuer.IssuerId == "" {
		return fmt.Errorf("issuer_id is empty")
	}
	if issuer.KeyType != IssuerKeyType_ISSUER_KEY_TYPE_ED25519 {
		return fmt.Errorf("unsupported key_type %s", issuer.KeyType)
	}
	if len(issuer.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("public_key must be %d bytes", ed25519.PublicKeySize)
	}
	if issuer.Weight == 0 {
		return fmt.Errorf("weight must be positive")
	}
	if issuer.ValidFromHeight <= 0 {
		return fmt.Errorf("valid_from_height must be positive")
	}
	if issuer.ValidUntilHeight < issuer.ValidFromHeight {
		return fmt.Errorf("valid_until_height must be at least valid_from_height")
	}
	return nil
}
