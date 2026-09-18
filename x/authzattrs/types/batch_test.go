package types

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

const goldenBatchFixturePath = "../../../docs/authz/testdata/v1.2/canonical-batch-sign-doc.json"

// TEST-ONLY, NON-PRODUCTION deterministic seeds. Never use these keys outside golden tests.
var goldenIssuerSeeds = []struct {
	issuerID string
	seedHex  string
}{
	{issuerID: "issuer-alpha", seedHex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"},
	{issuerID: "issuer-beta", seedHex: "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"},
}

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
	Issuers              []goldenIssuer         `json:"issuers"`
}

type goldenRecordKey struct {
	Subject    string `json:"subject"`
	MsgTypeURL string `json:"msg_type_url"`
}

type goldenIssuer struct {
	IssuerID     string `json:"issuer_id"`
	PublicKeyHex string `json:"public_key_hex"`
	SignatureHex string `json:"signature_hex"`
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

func TestEd25519GoldenSignatures(t *testing.T) {
	fixtureBytes, err := os.ReadFile(goldenBatchFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var fixture goldenBatchFixture
	if err := json.Unmarshal(fixtureBytes, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Issuers) != 2 || len(goldenIssuerSeeds) != 2 {
		t.Fatalf("golden issuer count = %d, seeds = %d", len(fixture.Issuers), len(goldenIssuerSeeds))
	}
	signBytes, err := hex.DecodeString(fixture.ExpectedSignBytesHex)
	if err != nil {
		t.Fatal(err)
	}
	batchHash, err := hex.DecodeString(fixture.ExpectedBatchHashHex)
	if err != nil {
		t.Fatal(err)
	}
	tamperedSignBytes := append([]byte(nil), signBytes...)
	tamperedSignBytes[0] ^= 0xff

	for i, testIssuer := range goldenIssuerSeeds {
		seed, err := hex.DecodeString(testIssuer.seedHex)
		if err != nil || len(seed) != ed25519.SeedSize {
			t.Fatalf("issuer %q invalid TEST-ONLY seed", testIssuer.issuerID)
		}
		privateKey := ed25519.NewKeyFromSeed(seed)
		publicKey := privateKey.Public().(ed25519.PublicKey)
		signature := ed25519.Sign(privateKey, signBytes)
		golden := fixture.Issuers[i]

		if golden.IssuerID != testIssuer.issuerID {
			t.Fatalf("issuer %d id = %q, want %q", i, golden.IssuerID, testIssuer.issuerID)
		}
		if golden.PublicKeyHex == "" || golden.SignatureHex == "" {
			t.Fatalf("populate issuer %q: public_key=%s signature=%s", golden.IssuerID, hex.EncodeToString(publicKey), hex.EncodeToString(signature))
		}
		goldenPublicKey, err := hex.DecodeString(golden.PublicKeyHex)
		if err != nil || len(goldenPublicKey) != ed25519.PublicKeySize {
			t.Fatalf("issuer %q golden public key length = %d", golden.IssuerID, len(goldenPublicKey))
		}
		goldenSignature, err := hex.DecodeString(golden.SignatureHex)
		if err != nil || len(goldenSignature) != ed25519.SignatureSize {
			t.Fatalf("issuer %q golden signature length = %d", golden.IssuerID, len(goldenSignature))
		}
		if hex.EncodeToString(publicKey) != golden.PublicKeyHex {
			t.Fatalf("issuer %q public key mismatch", golden.IssuerID)
		}
		if hex.EncodeToString(signature) != golden.SignatureHex {
			t.Fatalf("issuer %q signature mismatch", golden.IssuerID)
		}
		if !ed25519.Verify(ed25519.PublicKey(goldenPublicKey), signBytes, goldenSignature) {
			t.Fatalf("issuer %q signature does not verify over sign bytes", golden.IssuerID)
		}
		if ed25519.Verify(ed25519.PublicKey(goldenPublicKey), tamperedSignBytes, goldenSignature) {
			t.Fatalf("issuer %q signature verified over modified sign bytes", golden.IssuerID)
		}
		if ed25519.Verify(ed25519.PublicKey(goldenPublicKey), batchHash, goldenSignature) {
			t.Fatalf("issuer %q signature verified over batch hash", golden.IssuerID)
		}
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
