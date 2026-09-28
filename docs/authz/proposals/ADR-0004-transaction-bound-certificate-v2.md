# ADR-0004: transaction-bound authorization certificate V2

Status: Proposed / Draft. This is not an activated chain protocol. `CONTRACT_VERSION` remains V1.2.1.

## Context and decision

V1 first commits a signed batch to `AuthorizationRecord CURRENT`, then authorizes a later direct `MsgSend` by KV lookup. V2 is a separate route: a trusted off-chain gateway evaluates policy and returns a certificate to the client; the client places it in the same transaction as one direct `MsgSend` and signs the completed Cosmos transaction. No preliminary batch transaction and no per-operation CURRENT record are involved. V1 code and behavior remain unchanged until a separately approved activation.

The V2 certificate is one **critical** `TxBody.extension_options` `Any` with exact type URL `/alpha.authzattrs.v2.AuthorizationCertificateV2`. Issuers sign deterministic protobuf bytes of a newly rebuilt certificate sign document containing the transaction intent and trusted policy metadata, never the final transaction hash. The normal account signature uses `SIGN_MODE_DIRECT` over the final body (including the certificate) and auth info. Thus issuer and account signatures have different, non-circular jobs.

V2 initially accepts exactly one direct `/cosmos.bank.v1beta1.MsgSend`, one Coin, one ordinary account signer, and one `SIGN_MODE_DIRECT` signature. It does not treat `MsgExec`, `MsgMultiSend`, IBC, WASM, nested messages, or multi-message transactions as V2-authorized. The exact schema, validation and fixture are in [protocol-v2-draft.md](../protocol-v2-draft.md).

## SDK v0.53.3 integration decision

The installed SDK decoder checks unknown fields in `TxRaw` and `AuthInfo`, permits *non-critical* unknown fields in `TxBody`, unmarshals it, and unpacks both extension-option lists through `TxExtensionOptionI`. The generated V2 message must be registered for `Any` unpacking and with that interface. The default `RejectExtensionOptionsDecorator` rejects every critical option: the `x/auth/tx/config` depinject provider constructs `ante.NewAnteHandler` without `ExtensionOptionChecker`. Application wiring must therefore build/replace the core Ante handler with `ante.NewAnteHandler` given a checker accepting only the exact V2 type URL, while preserving all SDK core decorators and dependencies. The checker is only an admission hook, **not** certificate validation. V2 validation additionally checks multiplicity, raw payload and unknown fields, shape, sign bytes and quorum. `sdk.Context.TxBytes()` permits a strict raw-body check because the default decoder otherwise tolerates non-critical unknowns. The V1 outer decorator currently runs before core Ante; V2 routing must skip its CURRENT-record requirement only for a structurally present V2 certificate, and must not create a V1 fallback when V2 verification fails.

The core SDK order is setup, extension-option check, basic/timeout/memo/size/fee/pubkey/signature checks, signature verification, sequence increment. V2 wiring will preserve that order, run the core handler, then run the deterministic V2 verifier on its returned cached context, using the signed `SignerInfo.sequence` and committed account number. An error from V2 verification discards the whole Ante cache, including the core's tentative sequence/fee writes. The V1 outer decorator is skipped only for transactions presenting a V2 certificate; a malformed V2 attempt never falls back to V1. CheckTx and FinalizeBlock use the *same* V2 validator. No network, local time, filesystem, or middleware call is allowed in authority. A separately coordinated application upgrade is required to activate this consensus change; this ADR does not implement it.

The SDK `SignDoc` for `SIGN_MODE_DIRECT` contains exact `body_bytes`, `auth_info_bytes`, `chain_id`, and `account_number`; `SignerInfo.sequence` is in `auth_info_bytes`. Successful included Ante execution increments sequence even if later message execution fails; failed CheckTx and failed Ante do not commit sequence. Account sequence therefore gives at most one included transaction whose Ante succeeds for a signer sequence, not consume-on-first-presentation. V2 adds no certificate-consumption state. The height window and signed sequence bound retries.

The repository has no custom authorization `ProcessProposal`. V2 does **not** require one for authoritative safety: FinalizeBlock Ante verification is mandatory. A future deterministic ProcessProposal check can be preventive hardening only and must reuse the same verifier.

## Reuse boundary

| Reuse for V2 | Do not reuse in the V2 user path |
| --- | --- |
| Chain-local `IssuerSet`, `Issuer`, `CurrentIssuerSet[(policy_id, MsgSendTypeURL)]` scope and rotation rules | `AuthorizationRecord CURRENT` lookup |
| Ed25519, unique issuer IDs, complete-signature validation, checked weighted quorum | Batch replay ID as a user-operation prerequisite |
| Trusted gateway policy ID/version/hash and off-chain Keycloak evaluation | Preliminary `BatchUpsertAuthorizations` transaction |
| Stable, non-sensitive observability principles | Persistent per-operation grant/revoke flow |

V1 must remain compilable and behaviorally unchanged for comparison. V2 certificate verification is deliberately heavier than V1's normal transaction KV check; it still performs **no external I/O** in consensus.

## Open decisions

None for this proposed initial protocol. Activation height, rollout coordination and implementation schedule are operational work, not omitted sign-byte semantics.
