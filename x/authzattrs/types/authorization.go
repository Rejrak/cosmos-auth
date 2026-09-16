package types

import (
	"fmt"

	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

const MsgSendTypeURL = "/cosmos.bank.v1beta1.MsgSend"

const (
	ReasonOK                  = "AUTHZ_OK"
	ReasonNotFound            = "AUTHZ_NOT_FOUND"
	ReasonRevoked             = "AUTHZ_REVOKED"
	ReasonNotYetValid         = "AUTHZ_NOT_YET_VALID"
	ReasonExpired             = "AUTHZ_EXPIRED"
	ReasonDenomMismatch       = "AUTHZ_DENOM_MISMATCH"
	ReasonReceiverMismatch    = "AUTHZ_RECEIVER_MISMATCH"
	ReasonAmountExceeded      = "AUTHZ_AMOUNT_EXCEEDED"
	ReasonUnsupportedMsgShape = "AUTHZ_UNSUPPORTED_MSG_SHAPE"
	ReasonInvalidRecord       = "AUTHZ_INVALID_RECORD"
)

type Decision struct {
	Allowed    bool
	ReasonCode string
}

func (record AuthorizationRecord) Validate() error {
	if record.AuthorizationId == "" {
		return fmt.Errorf("authorization_id is empty")
	}
	if err := validateCanonicalAddress(record.Subject); err != nil {
		return fmt.Errorf("invalid subject: %w", err)
	}
	if record.MsgTypeUrl != MsgSendTypeURL {
		return fmt.Errorf("unsupported msg_type_url %q", record.MsgTypeUrl)
	}
	if record.PolicyId == "" {
		return fmt.Errorf("policy_id is empty")
	}
	if record.PolicyVersion == 0 {
		return fmt.Errorf("policy_version must be positive")
	}
	if record.IssuerSetId == 0 {
		return fmt.Errorf("issuer_set_id must be positive")
	}
	if record.ValidFromHeight <= 0 {
		return fmt.Errorf("valid_from_height must be positive")
	}
	if record.ValidUntilHeight < record.ValidFromHeight {
		return fmt.Errorf("valid_until_height must be at least valid_from_height")
	}
	if err := sdk.ValidateDenom(record.BankSendConstraints.Denom); err != nil {
		return fmt.Errorf("invalid denom: %w", err)
	}
	if err := validateCanonicalAddress(record.BankSendConstraints.Receiver); err != nil {
		return fmt.Errorf("invalid receiver: %w", err)
	}
	if _, ok := ParseCanonicalAmount(record.BankSendConstraints.MaxAmount); !ok {
		return fmt.Errorf("max_amount is not a canonical positive decimal")
	}
	return nil
}

func ParseCanonicalAmount(value string) (math.Int, bool) {
	amount, ok := math.NewIntFromString(value)
	return amount, ok && amount.IsPositive() && amount.String() == value
}

func validateCanonicalAddress(value string) error {
	address, err := sdk.AccAddressFromBech32(value)
	if err != nil {
		return err
	}
	if address.String() != value {
		return fmt.Errorf("address is not canonical")
	}
	return nil
}
