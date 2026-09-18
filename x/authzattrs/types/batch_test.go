package types

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

const goldenBatchFixturePath = "../../../docs/authz/testdata/v1.2/canonical-batch-sign-doc.json"

type goldenBatchFixture struct {
	Domain               string                 `json:"domain"`
	ChainID              string                 `json:"chain_id"`
	BatchID              uint64                 `json:"batch_id"`
	PolicyID             string                 `json:"policy_id"`
	PolicyVersion        uint64                 `json:"policy_version"`
	PolicyHashHex        string                 `json:"policy_hash_hex"`
	IssuerSetID          uint64                 `json:"issuer_set_id"`
	Records              []*AuthorizationRecord `json:"records"`
	CanonicalRecordOrder []goldenRecordKey      `json:"canonical_record_order"`
	ExpectedSignBytesHex string                 `json:"expected_sign_bytes_hex"`
	ExpectedBatchHashHex string                 `json:"expected_batch_hash_hex"`
}

type goldenRecordKey struct {
	Subject    string `json:"subject"`
	MsgTypeURL string `json:"msg_type_url"`
}

func TestCanonicalBatchSignBytesGolden(t *testing.T) {
	fixtureBytes, err := os.ReadFile(goldenBatchFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var fixture goldenBatchFixture
	if err := json.Unmarshal(fixtureBytes, &fixture); err != nil {
		t.Fatal(err)
	}
	policyHash, err := hex.DecodeString(fixture.PolicyHashHex)
	if err != nil {
		t.Fatal(err)
	}
	doc := &AuthorizationBatchSignDoc{
		Domain: fixture.Domain, ChainId: fixture.ChainID, BatchId: fixture.BatchID,
		PolicyId: fixture.PolicyID, PolicyVersion: fixture.PolicyVersion,
		PolicyHash: policyHash, IssuerSetId: fixture.IssuerSetID, Records: fixture.Records,
	}

	canonical, err := CanonicalizeBatchSignDoc(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(canonical.Records) != len(fixture.CanonicalRecordOrder) {
		t.Fatalf("canonical record count = %d", len(canonical.Records))
	}
	for i, expected := range fixture.CanonicalRecordOrder {
		actual := canonical.Records[i]
		if actual.Subject != expected.Subject || actual.MsgTypeUrl != expected.MsgTypeURL {
			t.Fatalf("canonical record %d = (%q, %q)", i, actual.Subject, actual.MsgTypeUrl)
		}
	}

	signBytes, batchHash, err := CanonicalBatchSignBytes(doc)
	if err != nil {
		t.Fatal(err)
	}
	if fixture.ExpectedSignBytesHex == "" || fixture.ExpectedBatchHashHex == "" {
		t.Fatalf("populate golden fixture: sign_bytes=%s batch_hash=%s", hex.EncodeToString(signBytes), hex.EncodeToString(batchHash[:]))
	}
	if actual := hex.EncodeToString(signBytes); actual != fixture.ExpectedSignBytesHex {
		t.Fatalf("sign bytes mismatch\n got: %s\nwant: %s", actual, fixture.ExpectedSignBytesHex)
	}
	if actual := hex.EncodeToString(batchHash[:]); actual != fixture.ExpectedBatchHashHex {
		t.Fatalf("batch hash mismatch: got %s want %s", actual, fixture.ExpectedBatchHashHex)
	}

	signBytesAgain, batchHashAgain, err := CanonicalBatchSignBytes(doc)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(signBytesAgain) != fixture.ExpectedSignBytesHex || batchHashAgain != batchHash {
		t.Fatal("identical input produced different canonical output")
	}
}

func TestCanonicalizeBatchSignDocRejectsInvalidAndDuplicateRecords(t *testing.T) {
	doc := validBatchSignDocForTest()
	doc.Records = append(doc.Records, cloneAuthorizationRecord(doc.Records[0]))
	if _, err := CanonicalizeBatchSignDoc(doc); !errors.Is(err, ErrDuplicateRecord) {
		t.Fatalf("duplicate record error = %v", err)
	}

	doc = validBatchSignDocForTest()
	doc.Records[0].BankSendConstraints.MaxAmount = "01"
	if _, err := CanonicalizeBatchSignDoc(doc); !errors.Is(err, ErrInvalidBatchSignDoc) {
		t.Fatalf("invalid record error = %v", err)
	}
}

func validBatchSignDocForTest() *AuthorizationBatchSignDoc {
	return &AuthorizationBatchSignDoc{
		Domain: AuthorizationBatchDomain, ChainId: "alpha-test-1", BatchId: 1,
		PolicyId: "policy-bank-send", PolicyVersion: 1,
		PolicyHash: make([]byte, 32), IssuerSetId: 1,
		Records: []*AuthorizationRecord{{
			AuthorizationId: "authz-1", Subject: "cosmos1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqnrql8a",
			MsgTypeUrl: MsgSendTypeURL, PolicyId: "policy-bank-send", PolicyVersion: 1,
			IssuerSetId: 1, ValidFromHeight: 1, ValidUntilHeight: 10,
			BankSendConstraints: BankSendConstraints{
				Denom: "uatom", Receiver: "cosmos1qyqszqgpqyqszqgpqyqszqgpqyqszqgpjnp7du", MaxAmount: "100",
			},
		}},
	}
}
