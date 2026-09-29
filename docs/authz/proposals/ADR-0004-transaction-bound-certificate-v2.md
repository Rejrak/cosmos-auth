# ADR-0004: transaction-bound authorization certificate V2

Status: Implemented / local live-E2E validated on `service-manager`. `CONTRACT_VERSION` is `authz-protocol-v2.0.0`; production network activation remains a separate deployment decision.

## Context and decision

V1 first commits a signed batch to `AuthorizationRecord CURRENT`, then authorizes a later direct `MsgSend` by KV lookup. V2 is a separate route: a trusted off-chain gateway evaluates policy and returns a certificate to the client; the client places it in the same transaction as one direct `MsgSend` and signs the completed Cosmos transaction. No preliminary batch transaction and no per-operation CURRENT record are involved. V1 code and behavior remain available unchanged for coexistence and comparison.

The V2 certificate is one **critical** `TxBody.extension_options` `Any` with exact type URL `/alpha.authzattrs.v2.AuthorizationCertificateV2`. Issuers sign deterministic protobuf bytes of a newly rebuilt certificate sign document containing the transaction intent and trusted policy metadata, never the final transaction hash. The normal account signature uses `SIGN_MODE_DIRECT` over the final body (including the certificate) and auth info. Thus issuer and account signatures have different, non-circular jobs.

V2 initially accepts exactly one direct `/cosmos.bank.v1beta1.MsgSend`, one Coin, one ordinary account signer, and one `SIGN_MODE_DIRECT` signature. It does not treat `MsgExec`, `MsgMultiSend`, IBC, WASM, nested messages, or multi-message transactions as V2-authorized. The exact schema, validation and fixture are in [protocol-v2-draft.md](../protocol-v2-draft.md).

## SDK v0.53.3 integration decision

The installed SDK decoder checks unknown fields in `TxRaw` and `AuthInfo`, permits *non-critical* unknown fields in `TxBody`, unmarshals it, and unpacks both extension-option lists through `TxExtensionOptionI`. The generated V2 message is registered for `Any` unpacking and with that interface. The default `RejectExtensionOptionsDecorator` rejects every critical option: the `x/auth/tx/config` depinject provider constructs `ante.NewAnteHandler` without `ExtensionOptionChecker`. `ante.NewAnteHandler` accepts a checker but provides **no hook to insert the V2 verifier**. Alpha therefore constructs one SDK-equivalent `sdk.ChainAnteDecorators` chain with `NewExtensionOptionsDecorator` given a checker accepting only the exact V2 type URL, preserving the other SDK decorators, options and dependencies. The checker is only an admission hook, **not** certificate validation. V2 validation additionally checks multiplicity, raw payload and unknown fields, shape, sign bytes and quorum. `sdk.Context.TxBytes()` permits a strict raw-body check because the default decoder otherwise tolerates non-critical unknowns. The V1 outer decorator remains on the V1 route; V2 routing skips its CURRENT-record requirement for a transaction presenting a V2 certificate and creates no V1 fallback when V2 verification fails.

The exact SDK v0.53.3 order is `SetUpContextDecorator` (outermost gas/recovery boundary) → extension-option check → `ValidateBasic` → timeout-height check → memo check → tx-size gas → fee deduction → set pubkey → signature-count check → signature gas → `SigVerificationDecorator` → **V2 verifier** → `IncrementSequenceDecorator`. The SDK signature decorator compares the signed sequence against the pre-increment account sequence; V2 compares `certificate.intent.sequence` to the sole signed `SignerInfo.sequence`, **never** to a possibly incremented account object. Account number is stable and may be read from the account. Because V2 is downstream of `SetUpContextDecorator`, its out-of-gas/panic handling remains normal SDK Ante behavior (out-of-gas becomes an error; unrelated panics propagate). BaseApp runs the entire Ante chain against one cache: a V2 error commits none of the tentative fee/pubkey writes and occurs before any sequence increment. A successful V2 check permits the SDK increment in that same Ante cache; any subsequent Ante failure would discard it. CheckTx, ReCheckTx and FinalizeBlock all run V2 structural/issuer validation; SDK ReCheckTx's normal skip of repeat account cryptographic verification does not skip V2. FinalizeBlock is authoritative. No network, local time, filesystem, or middleware call is allowed in authority. Alpha's application Ante wiring implements this order; production rollout remains a separately coordinated upgrade.

Coexistence is not downgrade prevention: a transaction **presenting** a V2 certificate is V2-only and cannot fall back after failure; a transaction with **no** certificate follows existing V1 rules while V1 remains enabled. Alpha cannot distinguish a deliberate V1 choice from a client that discarded a previously obtained V2 certificate **before** account signing. Requiring V2 for all direct MsgSend in a scope needs a separate coordinated upgrade that retires/disables that V1 route, not new routing KV state here. V2-only E2E evidence must use a subject without an independently valid V1 CURRENT record unless that route is disabled.

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

The V2 certificate cap of **16 distinct issuer signatures** does not change V1 registry or weighted-quorum semantics. A selected set is V2-usable at height `H` only when its threshold can be met by at most 16 positive-weight issuers that are active, in the active selected set, policy/message scoped and height-valid at `H`. Otherwise no valid V2 certificate can be constructed: verification fails closed, an availability/configuration problem rather than an authorization bypass. No persistent registry field or governance message is added. A future V2 activation/rotation control surface should reject or warn on a non-V2-compatible selection; verifier safety does not depend on that warning.

## Open decisions

None for this implemented V2.0.0 protocol. Production activation height and rollout coordination are operational work, not omitted sign-byte semantics.

## Local live-E2E evidence

A local `alpha-1` run included one V2 certificate-bound `MsgSend` at height 947 with code 0 and tx hash `AA77ACF7F149DDC3CF284366AD008D30BED196F3536419C508EADA07A38E098C`. The certificate digest was `bf4b30cde59b7be5739a5a829930a6ed50e5955beedfda08eaa15ab88cf9bcbc`, with two issuer signatures from set 9. The sender sequence advanced 1 → 2; `token` balances changed Alice 5000000 → 4999000 and Bob 50000000 → 50001000. No V1 CURRENT record existed before or after, and the middleware issued/broadcast exactly one Cosmos transaction. This is local E2E evidence, not a claim of production deployment.
