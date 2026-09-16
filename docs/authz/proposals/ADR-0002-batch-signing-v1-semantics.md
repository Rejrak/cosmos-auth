# ADR-0002 — Freeze Protocol V1.2 batch signing and mutation semantics

## Status

Accepted.

## Context

Protocol V1.1 froze AuthorizationRecord and deterministic direct MsgSend
semantics. Independent M3 implementations in Alpha and middleware additionally
require one exact cryptographic envelope, canonical sign-byte algorithm, issuer
registry/quorum model, replay rule and atomic record-mutation contract.

Without these decisions, implementations could produce different signed bytes,
count different issuers, accept replays, or apply stale revocations to a newer
grant.

## Decision

Protocol V1.2 freezes the following.

### Cryptography and sign doc

1. Ed25519 is the only V1.2 issuer algorithm: raw 32-byte public keys and raw
   64-byte signatures. Private keys are never on-chain or committed; golden-test
   seeds are explicitly TEST-ONLY and NON-PRODUCTION.
2. `AuthorizationBatchSignDoc` has exactly these logical protobuf fields:

   ```text
   1 string domain
   2 string chain_id
   3 uint64 batch_id
   4 string policy_id
   5 uint64 policy_version
   6 bytes policy_hash
   7 uint64 issuer_set_id
   8 repeated AuthorizationRecord records
   ```

3. Domain is exactly `alpha.authzattrs.batch.v1`; chain ID is non-empty and must
   equal the applying chain context; batch ID is positive; records are non-empty;
   policy hash is exactly one raw 32-byte SHA-256 digest selected/calculated by
   the trusted off-chain policy layer.
4. The chain does not execute, download or hash policy content. Issuer signatures
   attest the supplied policy hash.

### Canonicalization and signing

5. Validate all records, reject duplicate `(subject, msg_type_url)` keys, then
   sort records by byte-wise ascending UTF-8 `(subject, msg_type_url)`.
6. Reconstruct every record and its typed constraints from defined fields, then
   construct a new canonical sign doc from validated fields and sorted records.
   Never serialize the received network object directly; unknown protobuf fields
   never enter sign bytes.
7. Sign bytes are deterministic protobuf serialization of the canonical sign doc.
   There are no protobuf maps, JSON, canonical JSON, Amino or ad-hoc concatenation.
8. `batch_hash = SHA256(sign_bytes)` is for tests, correlation and observability.
   Ed25519 signs `sign_bytes` directly, not the hash or Cosmos transaction bytes.

### Batch signatures

9. `BatchSignature` is `(1 string issuer_id, 2 bytes signature)` and
   `AuthorizationBatch` is `(1 AuthorizationBatchSignDoc sign_doc,
   2 repeated BatchSignature signatures)`.
10. Issuer IDs are non-empty. Duplicate issuer IDs reject the batch. Middleware
    sorts signatures by issuer ID for reproducibility; chain quorum is independent
    of signature order.
11. Every supplied signature must be trusted, in scope and valid. A bad signature
    rejects the whole batch and is never ignored to salvage quorum.

### Registry and quorum

12. An IssuerSet contains positive `issuer_set_id`, `active`, non-empty
    `policy_id`, exact V1 MsgSend type URL and positive `threshold_weight`.
13. An Issuer contains issuer-set ID, non-empty issuer ID, ED25519 key type, raw
    32-byte public key, positive weight, active flag and inclusive positive height
    interval.
14. Registry mutation is authority/governance-only. A normal account cannot
    self-register as issuer.
15. An issuer contributes its weight once only when the set and issuer are active,
    height-valid, in the expected set and policy/MsgSend scope, and its Ed25519
    signature over canonical sign bytes is valid.
16. Quorum is `sum(valid unique issuer weights) >= threshold_weight`. Registry
    state is chain-local; chain ID remains solely in the sign doc.

### Replay, consistency and mutations

17. Replay state is `last_applied_batch_id[issuer_set_id]`. Only a strictly
    greater ID is accepted; gaps are allowed. Replay state advances only after
    complete success, and failed batches consume no ID.
18. Every record matches sign-doc policy ID, policy version and issuer-set ID and
    uses exact direct MsgSend type URL.
19. A revocation requires the CURRENT logical-key record, exactly matching
    `authorization_id`, and equality of every field except `revoked`. Otherwise it
    is stale. Revocation persists `revoked=true`; it never deletes silently.
20. A non-revoked grant replacing CURRENT must use a different authorization ID.
21. Validate the complete batch, issuer signatures/quorum and all CURRENT-state
    replacement/revocation conditions before writes. Any failure leaves every
    AuthorizationRecord and replay state unchanged.

### Submitter and vectors

22. The Cosmos transaction submitter is a permissionless fee-paying broadcaster,
    not an issuer or trusted relayer. It is absent from the sign doc, contributes
    no quorum weight and selects no policy.
23. M3 adds one identical Alpha/middleware golden vector containing a chain ID,
    batch/policy/issuer-set metadata, raw policy hash, at least two intentionally
    unsorted records, canonical order, expected sign bytes and batch hash in hex,
    plus at least two Ed25519 fixture signatures/public keys.

The full normative field validation, application order and stable reason codes
are defined in `docs/authz/protocol-v1.md` and
`docs/authz/observability-contract.md` at contract version
`authz-protocol-v1.2`.

## Consequences

- Alpha and middleware can implement byte-identical sign docs independently.
- Signatures are chain-, batch-, policy-, issuer-set- and record-bound.
- Quorum cannot be inflated by duplicates or salvaged by ignoring bad signatures.
- Replay and stale-revocation checks protect committed current records.
- Batch mutation is all-or-nothing.
- Normal MsgSend remains lightweight and does not verify issuer signatures.

## Out of scope

ProcessProposal, external CheckTx prefilters, IBC, MsgExec, ZK,
per-transaction certificates, a complete scheduler, a real Cosmos publisher,
Keycloak E2E, production HSM integration and secp256k1 issuer signatures remain
outside M3.
