# ADR-0001 — Freeze AuthorizationRecord V1 semantics for deterministic MsgSend

## Status

Accepted.

## Context

M2 was blocked because Protocol V1 listed the minimum AuthorizationRecord fields
but did not define enough semantics to implement the same behavior independently
in Alpha and middleware.

The missing decisions included:
- logical lookup key;
- cardinality/current-record semantics;
- exact MsgSend shape;
- block-height boundary inclusivity;
- meaning of `authorization_id`;
- whether normal user transactions compare policy metadata;
- mutation security before signed batches exist;
- duplicate-record semantics.

Allowing the two repositories to invent these rules independently would create a
cross-repository protocol incompatibility.

## Decision

Protocol v1.1 freezes the following:

1. Direct `/cosmos.bank.v1beta1.MsgSend` only.
2. Exactly one Coin per V1 MsgSend.
3. Logical current-record key is `(subject, msg_type_url)`.
4. `authorization_id` is opaque audit/correlation metadata, not the normal lookup
   key.
5. Heights are positive and inclusive:
   `valid_from_height <= H <= valid_until_height`.
6. MsgSend constraints are public typed fields:
   `denom`, `receiver`, `max_amount`.
7. `max_amount` is canonical positive decimal text.
8. Normal user transactions do not compare requester-supplied policy metadata,
   because none exists in the user transaction.
9. Policy/issuer consistency belongs to authenticated record-update validation.
10. M2 must not expose an unauthenticated public record-write message.
11. Revocation is persisted, not implemented as silent delete.
12. Batch duplicate detection uses the logical record key, not
    `authorization_id`.
13. `batch_id` is uint64 and monotonically increases per issuer set.

## Consequences

- Alpha can implement one deterministic O(1)-style lookup and evaluator.
- Middleware can build exactly the same record semantics.
- M2 can proceed without signed-batch implementation.
- M3 has a stable record/key/replay baseline on which to define protobuf
  sign-bytes and golden vectors.
- Nested MsgExec and IBC authorization remain explicitly out of V1 M2 scope.
