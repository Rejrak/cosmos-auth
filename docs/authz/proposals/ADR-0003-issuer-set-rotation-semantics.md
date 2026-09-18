# ADR-0003: Issuer-set rotation semantics

Status: Accepted

## Context

Protocol V1.2 defined issuer sets, weighted quorum, per-set replay protection,
and stale-revocation protection, but did not select which issuer set may
currently mutate records for a policy and message type. Rotation therefore
needed an explicit chain-local authority rule and precise record-mutation
semantics.

## Decision

Protocol V1.2.1 stores the authority/governance-only mapping:

```text
CurrentIssuerSet[(policy_id, msg_type_url)] -> issuer_set_id
```

A batch may mutate AuthorizationRecords only when its `issuer_set_id` equals
the current selection for its `policy_id` and
`/cosmos.bank.v1beta1.MsgSend`. Otherwise it fails with
`AUTHZ_BATCH_STALE_ISSUER_SET`.

After rotation from OLD to NEW, OLD batches cannot mutate records and NEW
batches can. Replay protection remains monotonic and independent per
`issuer_set_id`; IDs from different sets are never compared.

`AuthorizationRecord.issuer_set_id` identifies the issuer set that
authenticated the latest mutation of the CURRENT record.

For `revoked=true`, a CURRENT record must exist and the incoming
`authorization_id`, `subject`, `msg_type_url`, `policy_id`, `policy_version`,
`valid_from_height`, `valid_until_height`, and `bank_send_constraints` must
match it exactly. `revoked` may change from false to true. `issuer_set_id` may
change to the current signing issuer set, and that new value is stored.
Mismatch fails with `AUTHZ_BATCH_STALE_REVOCATION`.

For a `revoked=false` replacement, `authorization_id` must differ from CURRENT
and `issuer_set_id` must equal the current signing issuer set.

Quorum-weight addition must detect `uint64` overflow. Overflow fails with
`AUTHZ_BATCH_INVALID`; wraparound is forbidden.

## Unchanged contract

This amendment does not change sign-doc protobuf fields or field numbers, the
domain, deterministic protobuf serialization, Ed25519, `batch_hash`, the
signature schema, record ordering, per-set replay semantics, or the
permissionless submitter model.

## Consequences

Governance rotation immediately retires the old issuer set from record
mutation without rewriting existing records. A current set may revoke a record
last mutated by an older set while stale revocations remain fail-closed and
auditable.
