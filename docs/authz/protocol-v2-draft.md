# Transaction-bound authorization certificate protocol V2

Status: **Proposed / Draft** (ADR-0004). Not active; `docs/authz/CONTRACT_VERSION` stays `authz-protocol-v1.2.1`. No V1 code, record, batch or on-chain mutation rule is changed by this draft.

## 1. Scope and authority

The client obtains a certificate from the trusted off-chain gateway/policy layer, creates **one** Cosmos transaction containing exactly one direct `/cosmos.bank.v1beta1.MsgSend` and exactly one typed certificate, then signs the complete transaction with one ordinary account key in `SIGN_MODE_DIRECT`. The transaction itself is the operation. No separate batch transaction or per-operation `AuthorizationRecord CURRENT` write is required. The client/requester proposes transfer details, but cannot authoritatively choose `policy_id`, `policy_version`, `policy_hash`, `issuer_set_id`, issuer signatures or quorum. The gateway selects the policy and authorized issuer set off-chain; Alpha verifies issuer signatures and the chain-local current set/registry at execution height. Keycloak stays off-chain. Issuer signatures do not replace the normal account signature.

V2 applies only to this exact shape. It grants no authority to `MsgMultiSend`, `authz.MsgExec` (including nested `MsgSend`), IBC transfers, WASM, nested messages, multi-signer/multisig or non-`SIGN_MODE_DIRECT` modes. Other module paths retain their existing rules; they are **not** described as V2-authorized. While V1 and V2 coexist, a direct `MsgSend` with no V2 critical option follows the unchanged V1 route; a transaction presenting a V2 option is V2-only and **never** falls back to V1 if malformed or denied. Removing/changing the option **after** account signing invalidates that signature, but the chain cannot distinguish an intentional V1 choice from discarding an obtained certificate **before** signing. Thus V2 alone does not prevent pre-sign downgrade while an independently valid V1 route remains enabled. Requiring V2 for direct MsgSend needs a separate coordinated upgrade retiring/disabling V1 for that scope; no per-scope routing KV state is added here.

## 2. Typed transport and SDK requirements

Package: `alpha.authzattrs.v2`; protobuf full name `alpha.authzattrs.v2.AuthorizationCertificateV2`; exact `Any.type_url`: `/alpha.authzattrs.v2.AuthorizationCertificateV2`. It is carried **once** in SDK `TxBody.extension_options` (critical, field 1023), not in `non_critical_extension_options` (field 2047), a second Msg, memo, JSON, or transaction hash. No other critical option is accepted in V2. The sole V2 critical `Any.value` is at most 4096 bytes; the total encoded transaction remains subject to SDK/consensus limits.

SDK v0.53.3's `DefaultTxDecoder` checks unknown `TxRaw` and `AuthInfo` fields strictly, but allows bit-11 non-critical unknown fields in `TxBody`. It unpacks both extension-option lists through `TxExtensionOptionI`. The V2 generated protobuf type must be in the app interface registry for that interface and available to `Any` unpacking. In SDK `x/auth/ante`, `RejectExtensionOptionsDecorator` rejects **all** critical options unless given an `ExtensionOptionChecker`. Alpha's current `x/auth/tx/config` depinject handler has no checker, and `ante.NewAnteHandler` has no hook for inserting V2 inside its chain. V2 activation must build one SDK-equivalent `sdk.ChainAnteDecorators` chain, preserving the SDK decorators/options and supplying a checker that accepts **only** this exact type URL. A type-URL checker alone does not establish cardinality or validity. The V2 verifier must decode the actual payload, strictly reject unknown protobuf fields in its nested messages, and compare a reconstructed intent with the final transaction. It must also strictly check raw `TxBody` bytes from `sdk.Context.TxBytes()` for unknown fields rather than relying on the default decoder's non-critical allowance. An alternate type-URL prefix that happens to unpack to the same Go type is not accepted.

| Case on a direct MsgSend | V2 result |
| --- | --- |
| No certificate / no critical option | V1 route during coexistence, **not** V2 authorization; if V1 has no grant it fails closed |
| Exactly one well-formed exact-type critical certificate | Verify V2; deny on any failed check, no V1 fallback |
| Duplicate certificate, another/unknown critical option, malformed or unknown-field `Any`, empty payload | Reject before message execution |
| Certificate placed in non-critical options | Reject; it cannot select V2 or fall through to V1 |
| Any unrelated non-critical extension or unknown non-critical `TxBody` field **on a V2 transaction** | Reject; V2 has no unbound extension semantics. A no-certificate V1 transaction retains its existing behavior |

## 3. Logical protobuf schema (field numbers frozen for this draft)

```proto
syntax = "proto3";
package alpha.authzattrs.v2;

message FeeCoinV2 {
  string denom = 1;
  string amount = 2;
}
message AuthorizationIntentV2 {
  string chain_id = 1;
  string subject = 2;
  string receiver = 3;
  string denom = 4;
  string amount = 5;
  uint64 account_number = 6;
  uint64 sequence = 7;
  uint64 timeout_height = 8;
  string memo = 9;
  repeated FeeCoinV2 fee_amount = 10;
  uint64 gas_limit = 11;
}
message AuthorizationCertificateSignDocV2 {
  string domain = 1;
  AuthorizationIntentV2 intent = 2;
  string policy_id = 3;
  uint64 policy_version = 4;
  bytes policy_hash = 5;
  uint64 issuer_set_id = 6;
  int64 valid_from_height = 7;
  int64 valid_until_height = 8;
}
message IssuerSignatureV2 {
  string issuer_id = 1;
  bytes signature = 2;
}
message AuthorizationCertificateV2 {
  AuthorizationCertificateSignDocV2 sign_doc = 1;
  repeated IssuerSignatureV2 signatures = 2;
}
```

`domain` is exactly `alpha.authzattrs.certificate.v2`. `chain_id` is nonempty and equals `sdk.Context.ChainID()`. `subject` and `receiver` are canonical account-address strings under the chain address codec; `subject` equals `MsgSend.from_address` and the sole normal signer, `receiver` equals `MsgSend.to_address`. `denom` equals the sole MsgSend Coin denom; `amount` is its canonical positive base-10 integer string (no sign, leading zeros or decimal point). Account number is the committed signer account number, not a TxBody field; `sequence` is the sole `SignerInfo.sequence` and must pass SDK account-sequence checks. `timeout_height` and `memo` equal TxBody fields. `fee_amount` reproduces `AuthInfo.fee.amount` in canonical SDK Coins order, with at most four distinct, lexicographically increasing denoms and canonical nonnegative base-10 amounts; `gas_limit` equals `AuthInfo.fee.gas_limit`. Fee payer and granter must both be **empty**, so the signer pays and no third party or fee-grant authorization is introduced. `AuthInfo.tip` must be absent. `TxBody.unordered` must be false and `timeout_timestamp` absent/zero. Exactly one `SignerInfo`, one `TxRaw.signature`, one direct `MsgSend`, one MsgSend Coin, and one critical certificate are required. Signer mode must be single `SIGN_MODE_DIRECT`, not a multi-mode/multisig envelope.

The gateway issues a sign document with nonempty `policy_id`, positive `policy_version`, raw 32-byte `policy_hash`, positive `issuer_set_id`, positive `valid_from_height`, and `valid_until_height >= valid_from_height`. Policy hash is selected by the trusted off-chain policy layer and signed by issuers; Alpha validates its length but does not fetch, execute or recompute policy. Height validity is **inclusive**: `valid_from_height <= currentHeight <= valid_until_height`. Current height comes only from deterministic SDK context, never wall clock. The SDK TxBody `timeout_height` is also inclusive (the SDK rejects when `currentHeight > timeout_height`); zero means no TxBody timeout, but the certificate still expires. Certificate validity is independently checked on every authoritative evaluation.

## 4. Complete transaction-field binding

"Bound" means the verifier reconstructs the field from the **final decoded transaction or committed signer account**, and requires equality with issuer-signed intent; a fixed constraint is equally mandatory. The final account signature covers the exact raw `TxBody` and `AuthInfo` bytes even where the issuer need not bind a field.

| Final field | Status and reason |
| --- | --- |
| Context chain ID and committed account number | **BOUND BY ISSUER INTENT** (`chain_id`, `account_number`); client `SignDoc` also binds both |
| `MsgSend.from_address`, `to_address`, sole Coin denom/amount | **BOUND BY ISSUER INTENT**; any substitution changes signed intent |
| `TxBody.messages` count/type | **BOUND BY ISSUER INTENT** as exactly one direct MsgSend; every other shape rejected |
| `AuthInfo.signer_infos` count and signer sequence | **BOUND BY ISSUER INTENT** as one signer and exact `sequence` |
| `TxBody.memo`, `timeout_height` | **BOUND BY ISSUER INTENT** as exact values |
| `AuthInfo.fee.amount`, `gas_limit` | **BOUND BY ISSUER INTENT** as exact canonical coin list and gas limit |
| `AuthInfo.fee.payer`, `granter`, `tip` | **BOUND BY ISSUER INTENT** as fixed empty/absent; they cannot redirect cost to another actor |
| `TxBody.unordered`, `timeout_timestamp` | **BOUND BY ISSUER INTENT** as fixed false/absent; unordered bypasses sequence semantics, timestamp adds another clock rule |
| `TxBody.extension_options` | **BOUND BY ISSUER INTENT** as exactly one validated critical certificate; issuer signs its reconstructed sign doc (not self-referential envelope bytes) |
| `TxBody.non_critical_extension_options` and unknown body/message/certificate fields | **BOUND BY ISSUER INTENT** as absent; reject rather than accept unbound future semantics |
| `SignerInfo.mode_info` | **BOUND BY ISSUER INTENT** as single `SIGN_MODE_DIRECT` only |
| `SignerInfo.public_key` | **MAY DIFFER AFTER CERTIFICATE ISSUANCE** only if SDK validation proves it is the sole subject account key; it cannot change the sender or MsgSend authority |
| `TxRaw.signatures[0]` | **MAY DIFFER AFTER CERTIFICATE ISSUANCE** because the final account signature is necessarily made after inserting the certificate; it must verify for the bound subject over the final TxBody/AuthInfo |
| Raw protobuf field order/encoding of otherwise identical defined TxBody/AuthInfo values | **MAY DIFFER AFTER CERTIFICATE ISSUANCE**; issuer reconstruction uses defined fields, while the account signs the exact final raw bytes; strict unknown-field checks prohibit hidden semantics |

There are no other permitted TxBody/AuthInfo fields in this SDK version. Any future field needs an explicit V2 protocol revision before acceptance. One signature with a different final fee/memo/sequence/etc. cannot expand the issuer grant because reconstruction fails.

## 5. Canonical issuer sign bytes and certificate digest

Verify every defined field, normalize no user-supplied string, require exact final-tx equality, and construct a **new** `AuthorizationIntentV2` and `AuthorizationCertificateSignDocV2` from validated values. Do not serialize network-received protobuf objects or preserve unknown fields. Reject unknown fields in the certificate and relevant transaction messages. There are no maps. The fee coin list is sorted by byte-wise UTF-8 denom and rejects duplicates; signature order is irrelevant to quorum, but producers emit signatures sorted byte-wise by `issuer_id` for reproducible envelopes.

`sign_bytes = deterministic protobuf serialization(new canonical AuthorizationCertificateSignDocV2)`.

`certificate_digest = SHA256(sign_bytes)` (32 raw bytes; display lowercase hex). Ed25519 issuers sign **sign_bytes directly**, not `certificate_digest`, JSON, Amino, `TxRaw`, `SignDoc`, a transaction hash or an arbitrary concatenation. Unknown protobuf fields do not enter sign bytes. The certificate envelope itself is excluded from the intent to avoid a hash/signature cycle; its signed sign document and signatures are validated independently. Domain separation is the exact `domain` field above; V1 batch signatures use a different domain. The digest is for correlation and tests, not an extra authority input.

## 6. Issuer trust, limits and fail-closed verification

Reuse `CurrentIssuerSet[(policy_id, "/cosmos.bank.v1beta1.MsgSend")]` unchanged. Its selected set ID must equal signed `issuer_set_id` at evaluation height; a rotated-out set cannot authorize a new V2 transaction. The selected `IssuerSet` must exist, be active, match policy/type and have positive threshold. Each supplied signature must have nonempty unique `issuer_id` and a raw 64-byte Ed25519 signature. For each signer, load `Issuer[(issuer_set_id, issuer_id)]`; require expected set membership, ED25519 raw 32-byte public key, positive weight, active status and inclusive issuer height validity. Verify **every** supplied signature against canonical `sign_bytes`; unknown, malformed, inactive, out-of-scope or invalid extras reject the entire certificate even if quorum was reached earlier. Add unique issuer weights with checked `uint64` overflow, then require total `>= threshold_weight`. The requester/submitter is never an issuer merely by broadcasting. No issuer private key or gateway secret is on-chain.

Certificate `Any.value` size is at most **4096 bytes**; signature count is **1..16 distinct issuers**; intent fee coin count is **0..4**; MsgSend Coin count is exactly 1; all other repeated certificate fields are absent. These are certificate bounds, not limits on registry size, and V1 registry/quorum rules are unchanged. A `CurrentIssuerSet` is V2-usable at height `H` only if its unchanged weighted threshold can be reached with at most 16 issuers that have positive weight, are active, belong to the active selected set, match policy/message scope and are height-valid at `H`. Otherwise no valid V2 certificate exists for that selection: verification fails closed. This is a configuration/availability failure, **not** an authorization bypass. No registry field or governance message is added; a future V2 activation/rotation control surface **should** reject or warn about such a selection, but verifier safety does not rely on that check. Protocol shape/size checks and gas charging must occur in the same deterministic Ante path in CheckTx, ReCheckTx and FinalizeBlock. No HTTP, TCP, Keycloak, SQLite, filesystem, subprocess, environment or local clock may influence acceptance.

## 7. Replay and single-use semantics

V2 stores **zero** per-certificate consumption state. It binds the certificate to the signer's current account number and `SignerInfo.sequence`; the SDK core Ante checks sequence and increments it when Ante succeeds. Exact guarantees:

| Situation | Result |
| --- | --- |
| A. Same exact transaction resent before inclusion | It can be rebroadcast; a node's CheckTx state/mempool may reject a duplicate, but presentation is not globally consumed. At most one included Ante-successful tx for that account sequence can persist. |
| B. Same certificate in another tx with same sequence before inclusion | It passes issuer intent comparison only if all bound fields remain identical. Distinct permitted raw signature/encoding cannot expand the authorized operation. Competition is settled by normal account sequence: at most one included Ante-successful tx for that sequence. |
| C. Retry after CheckTx rejection | CheckTx does not commit account sequence or certificate state; a corrected/retried tx can still pass within its height window. |
| D. Retry after successful inclusion | Sequence has advanced; old signed sequence fails normal Ante. |
| E. Included transaction whose Msg execution fails | If Ante succeeded, its sequence increment (and fee) persists even though Msg state changes roll back; old certificate/sequence cannot be reused. If Ante itself failed, no sequence increment commits. |
| F. Expiration | Reject at `H > valid_until_height` or (if nonzero) `H > timeout_height`; `H ==` either upper bound remains valid. Old certificate can be retried only while both bounds and account sequence permit. |

The guarantee is **at most one included Ante-successful transaction for one account sequence**, not “consumed on first presentation.” A literal first-attempt consumption model would need additional state and denial-of-service policy; it is not V2.

## 8. Verification phases and coexistence

Use **one** Ante chain in exact SDK v0.53.3 order: `SetUpContextDecorator` (outermost recovery/gas boundary) → `ExtensionOptionsDecorator` with exact-type checker → `ValidateBasicDecorator` → `TxTimeoutHeightDecorator` → `ValidateMemoDecorator` → `ConsumeGasForTxSizeDecorator` → `DeductFeeDecorator` → `SetPubKeyDecorator` → `ValidateSigCountDecorator` → `SigGasConsumeDecorator` → `SigVerificationDecorator` → **V2 verifier** → `IncrementSequenceDecorator`. The SDK signature decorator checks the account sequence against the signed `SignerInfo.sequence` **before** increment; V2 compares `certificate.intent.sequence` to that signed sole `SignerInfo.sequence`, never to a post-increment account object. The stable account number may be read from the signer account. `SetUpContextDecorator` converts V2 out-of-gas panics to SDK errors and re-panics unrelated panics, as in normal Ante. BaseApp executes the entire chain in one Ante cache: a V2 error discards tentative fee/pubkey writes and occurs before any sequence increment. The SDK increments sequence only after V2 succeeds, in the same cache; no V2 failure consumes a sequence.

CheckTx, ReCheckTx and FinalizeBlock all run the same deterministic V2 structural and issuer verification; FinalizeBlock is authoritative and blocks Msg execution on failure. SDK ReCheckTx may skip repeat account cryptographic verification, but not V2 validation. The critical-option checker is not a substitute for verification. A V2 option never falls back to V1 CURRENT lookup upon any failure. No external service participates in the decision.

The repository currently has **no custom authorization ProcessProposal**. V2 does not require it for safety because FinalizeBlock Ante is authoritative. A later optional deterministic ProcessProposal check may preempt bad proposals, but must reuse the same rules and cannot be the only enforcement point.

The existing V1 path continues for transactions without a V2 option during coexistence. Thus “no V2 certificate” is not a V2 allow; any V1 authorization is a separate legacy authorization route. A client can discard a certificate **before** normal signing and submit a V1 transaction if it independently satisfies V1; Alpha cannot detect that history. V2-only E2E tests must therefore use a subject with **no independently valid V1 CURRENT authorization**, unless V1 has been separately disabled. Zero direct MsgSend, two MsgSends, MsgSend plus any other Msg, MsgMultiSend, nested `MsgExec`, IBC transfer or WASM message with a V2 option are denied as V2 shape violations. Without a V2 option, they remain subject to their existing module/Ante rules; this draft does **not** claim they cannot transfer value through their own paths. A later scope expansion requires explicit protocol and enforcement work.

## 9. Normal account signature versus issuer signatures

For SDK v0.53.3 `SIGN_MODE_DIRECT`, the account signs a `SignDoc` containing exact `TxRaw.body_bytes`, exact `TxRaw.auth_info_bytes`, chain ID and account number. The body bytes contain the certificate `Any` and MsgSend; auth info contains the signed sequence and fee. After the account signs, a third party cannot remove, replace or change the certificate, MsgSend, fee or memo without invalidating that account signature. Issuers separately attest the reconstructed intent and policy/set/height metadata, **not** the account signature or circular transaction hash. Both signature classes must verify; neither alone authorizes execution.

## 10. Public TEST-ONLY golden vector

This vector is for independent Alpha/middleware sign-byte parity. No production credential is included. The two Ed25519 identities use deterministic **TEST-ONLY / NON-PRODUCTION** fixture keys; private seeds are not part of this contract or the chain. The sample is a logical sign document, not a live transaction; a real transaction must still provide a matching account/signature, height and active issuer registry.

| Field | Fixture value |
| --- | --- |
| `domain` | `alpha.authzattrs.certificate.v2` |
| `intent.chain_id` | `alpha-1` |
| `intent.subject` | `cosmos1duzpxku5atm98qk6ywvgdjzn50yzv90q7c3r44` |
| `intent.receiver` | `cosmos1ssevndlg997a89wpw2wv9xj2vahhqcyt0gml84` |
| `intent.denom`, `amount` | `token`, `1000` |
| `intent.account_number`, `sequence` | `7`, `3` |
| `intent.timeout_height`, `memo` | `115`, `v2 golden` |
| `intent.fee_amount`, `gas_limit` | one `stake:100` FeeCoinV2, `200000` |
| fee payer/granter, tip, unordered, timeout timestamp | empty, empty, absent, false, absent |
| `policy_id`, `policy_version` | `policy-bank-send`, `2` |
| `policy_hash` raw SHA-256 bytes (hex) | `5ad8c4fa036c6238f322b3bfc2c012f0f12d9c6af391ba9d26acfe08a1d01d13` = SHA-256 of UTF-8 `test-only-policy-v2` (TEST-ONLY fixture policy preimage) |
| `issuer_set_id` | `9` |
| `valid_from_height`, `valid_until_height` | `100`, `110` inclusive |

Deterministic protobuf `sign_bytes` for exactly the schema above (hex, one line):

```text
0a1f616c7068612e617574687a61747472732e63657274696669636174652e76321297010a07616c7068612d31122d636f736d6f733164757a70786b753561746d3938716b3679777667646a7a6e3530797a763930713763337234341a2d636f736d6f7331737365766e646c6739393761383977707732777639786a32766168687163797430676d6c38342205746f6b656e2a04313030303007380340734a09763220676f6c64656e520c0a057374616b65120331303058c09a0c1a10706f6c6963792d62616e6b2d73656e6420022a205ad8c4fa036c6238f322b3bfc2c012f0f12d9c6af391ba9d26acfe08a1d01d1330093864406e
```

`SHA256(sign_bytes)` / `certificate_digest` (hex):

```text
23d2bdf82cc29dafa3ff0ff8a42e74dc1b88864632a69cca8f9d7055387e844b
```

Each signature below is raw Ed25519 over those exact `sign_bytes`, **not** their SHA-256 digest:

| `issuer_id` | 32-byte `public_key` hex | 64-byte `signature` hex |
| --- | --- | --- |
| `issuer-alpha` | `03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8` | `b1bea693676fc45cbc80c3cf2127166238d3289466166ab3630a684e6f7bb1d800601459bb212a98d2d0b8c1f5a96e359744b1e1ce8a0430298d61dd334d6b0d` |
| `issuer-beta` | `29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7` | `02d446a06af1329d2dba3e752a6f0689d9625c8e46a6f55b2ee4809becf1c1e133d6ad7b0196f9b15df653c97679a81250912525f88df0c39a99b4fa3efc4008` |

The logical `AuthorizationCertificateV2` envelope is `sign_doc` with the fixture fields above, followed by `signatures = [{issuer-alpha, signature-alpha}, {issuer-beta, signature-beta}]` in issuer-ID order. Its wire bytes are **not** the issuer sign bytes. The fixture was generated with protobuf wire encoding and checked against Go standard-library Ed25519 verification; independent implementations must match the listed sign bytes byte-for-byte before activation.

## 11. Open decisions

None within this draft's deliberately narrow semantics. Activation and cross-repository implementation require their own approval and golden-vector tests; they do not license alternate canonical bytes.
