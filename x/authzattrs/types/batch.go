package types

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
)

const AuthorizationBatchDomain = "alpha.authzattrs.batch.v1"

var (
	ErrInvalidBatchSignDoc = errors.New("AUTHZ_BATCH_INVALID")
	ErrDuplicateRecord     = errors.New("AUTHZ_BATCH_DUPLICATE_RECORD")
	ErrBatchPolicyMismatch = errors.New("AUTHZ_BATCH_POLICY_MISMATCH")
)

// CanonicalizeBatchSignDoc validates and rebuilds a sign doc without mutating it.
func CanonicalizeBatchSignDoc(input *AuthorizationBatchSignDoc) (*AuthorizationBatchSignDoc, error) {
	if input == nil {
		return nil, fmt.Errorf("%w: nil sign doc", ErrInvalidBatchSignDoc)
	}
	if input.Domain != AuthorizationBatchDomain {
		return nil, fmt.Errorf("%w: invalid domain", ErrInvalidBatchSignDoc)
	}
	if input.ChainId == "" || input.BatchId == 0 || input.PolicyId == "" ||
		input.PolicyVersion == 0 || len(input.PolicyHash) != sha256.Size ||
		input.IssuerSetId == 0 || len(input.Records) == 0 {
		return nil, fmt.Errorf("%w: invalid sign doc fields", ErrInvalidBatchSignDoc)
	}

	records := make([]*AuthorizationRecord, 0, len(input.Records))
	seen := make(map[authorizationRecordKey]struct{}, len(input.Records))
	for _, record := range input.Records {
		if record == nil {
			return nil, fmt.Errorf("%w: nil record", ErrInvalidBatchSignDoc)
		}
		if err := record.Validate(); err != nil {
			return nil, fmt.Errorf("%w: invalid record: %v", ErrInvalidBatchSignDoc, err)
		}
		if record.PolicyId != input.PolicyId || record.PolicyVersion != input.PolicyVersion ||
			record.IssuerSetId != input.IssuerSetId {
			return nil, ErrBatchPolicyMismatch
		}

		key := authorizationRecordKey{subject: record.Subject, msgTypeURL: record.MsgTypeUrl}
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("%w: subject=%q msg_type_url=%q", ErrDuplicateRecord, key.subject, key.msgTypeURL)
		}
		seen[key] = struct{}{}
		records = append(records, cloneAuthorizationRecord(record))
	}

	sort.Slice(records, func(i, j int) bool {
		if records[i].Subject != records[j].Subject {
			return records[i].Subject < records[j].Subject
		}
		return records[i].MsgTypeUrl < records[j].MsgTypeUrl
	})

	return &AuthorizationBatchSignDoc{
		Domain:        input.Domain,
		ChainId:       input.ChainId,
		BatchId:       input.BatchId,
		PolicyId:      input.PolicyId,
		PolicyVersion: input.PolicyVersion,
		PolicyHash:    append([]byte(nil), input.PolicyHash...),
		IssuerSetId:   input.IssuerSetId,
		Records:       records,
	}, nil
}

// CanonicalBatchSignBytes returns deterministic protobuf bytes and their SHA-256 hash.
func CanonicalBatchSignBytes(input *AuthorizationBatchSignDoc) ([]byte, [sha256.Size]byte, error) {
	canonical, err := CanonicalizeBatchSignDoc(input)
	if err != nil {
		return nil, [sha256.Size]byte{}, err
	}

	// The generated protobuf marshaler is deterministic here because the rebuilt
	// sign doc has no maps and its only repeated field is canonically ordered.
	signBytes, err := canonical.Marshal()
	if err != nil {
		return nil, [sha256.Size]byte{}, fmt.Errorf("marshal canonical sign doc: %w", err)
	}
	return signBytes, sha256.Sum256(signBytes), nil
}

type authorizationRecordKey struct {
	subject    string
	msgTypeURL string
}

func cloneAuthorizationRecord(record *AuthorizationRecord) *AuthorizationRecord {
	return &AuthorizationRecord{
		AuthorizationId:  record.AuthorizationId,
		Subject:          record.Subject,
		MsgTypeUrl:       record.MsgTypeUrl,
		PolicyId:         record.PolicyId,
		PolicyVersion:    record.PolicyVersion,
		IssuerSetId:      record.IssuerSetId,
		ValidFromHeight:  record.ValidFromHeight,
		ValidUntilHeight: record.ValidUntilHeight,
		Revoked:          record.Revoked,
		BankSendConstraints: BankSendConstraints{
			Denom:     record.BankSendConstraints.Denom,
			Receiver:  record.BankSendConstraints.Receiver,
			MaxAmount: record.BankSendConstraints.MaxAmount,
		},
	}
}
