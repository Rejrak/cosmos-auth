# Observability & explainability contract

Ogni decisione importante deve poter essere ricostruita senza leggere codice.

## Reason codes on-chain

Usare reason code stabili nei test/eventi/errori:

```text
AUTHZ_OK
AUTHZ_NOT_FOUND
AUTHZ_REVOKED
AUTHZ_NOT_YET_VALID
AUTHZ_EXPIRED
AUTHZ_DENOM_MISMATCH
AUTHZ_RECEIVER_MISMATCH
AUTHZ_AMOUNT_EXCEEDED
AUTHZ_POLICY_MISMATCH
AUTHZ_UNSUPPORTED_MSG_SHAPE
AUTHZ_INVALID_RECORD
AUTHZ_BATCH_BAD_SIGNATURE
AUTHZ_BATCH_UNKNOWN_ISSUER
AUTHZ_BATCH_QUORUM_NOT_MET
AUTHZ_BATCH_REPLAY
AUTHZ_BATCH_DUPLICATE_RECORD
```

`AUTHZ_POLICY_MISMATCH` è riservato ai path di update/batch in cui vengono
confrontati riferimenti di policy. Non è richiesto dal normale evaluator MsgSend
M2, perché la transazione utente non contiene metadata di policy.

## Chain events

Per tx utente:

```text
event: authz_decision
subject
msg_type
policy_id
policy_version
authorization_id
outcome
reason_code
height
```

Per batch:

```text
event: authz_batch_applied
batch_id
policy_id
policy_version
issuer_set_id
record_count
quorum_weight
height
```

Non emettere attributi enterprise sensibili o secret.

## Middleware structured logs

Event names:

```text
keycloak_sync
policy_evaluated
authorization_built
batch_built
batch_signed
batch_broadcast
batch_committed
revocation_broadcast
checktx_filter_decision
```

Campi di correlazione preferiti:

```text
batch_id
authorization_id
subject_hash (se il subject non deve comparire nei log)
tx_hash
policy_id
policy_version
```

## Human interface

`authzctl` è l'interfaccia operativa primaria finché il protocollo non è stabile.
Una TUI/web UI è fuori scope iniziale: prima deve funzionare il sistema.
