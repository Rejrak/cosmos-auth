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
AUTHZ_BATCH_BAD_DOMAIN
AUTHZ_BATCH_CHAIN_ID_MISMATCH
AUTHZ_BATCH_INVALID
AUTHZ_BATCH_POLICY_MISMATCH
AUTHZ_BATCH_BAD_SIGNATURE
AUTHZ_BATCH_UNKNOWN_ISSUER
AUTHZ_BATCH_ISSUER_INACTIVE
AUTHZ_BATCH_ISSUER_OUT_OF_SCOPE
AUTHZ_BATCH_DUPLICATE_SIGNATURE
AUTHZ_BATCH_QUORUM_NOT_MET
AUTHZ_BATCH_REPLAY
AUTHZ_BATCH_DUPLICATE_RECORD
AUTHZ_BATCH_STALE_REVOCATION
AUTHZ_BATCH_STALE_ISSUER_SET
```

`AUTHZ_POLICY_MISMATCH` è riservato ai path di update/batch in cui vengono
confrontati riferimenti di policy. Non è richiesto dal normale evaluator MsgSend
M2, perché la transazione utente non contiene metadata di policy.

I reason code batch hanno semantica stabile:

- `AUTHZ_BATCH_BAD_DOMAIN`: domain diverso da `alpha.authzattrs.batch.v1`;
- `AUTHZ_BATCH_CHAIN_ID_MISMATCH`: chain ID vuoto o diverso dal contesto on-chain;
- `AUTHZ_BATCH_INVALID`: envelope/campi/lunghezze invalidi senza reason più specifico;
- `AUTHZ_BATCH_POLICY_MISMATCH`: metadata policy/version/issuer-set/msg scope dei record
  non coerenti col sign doc;
- `AUTHZ_BATCH_BAD_SIGNATURE`: firma malformata o Ed25519 non valida;
- `AUTHZ_BATCH_UNKNOWN_ISSUER`: issuer non registrato nell'issuer set atteso;
- `AUTHZ_BATCH_ISSUER_INACTIVE`: issuer set o issuer inattivo/fuori validità height;
- `AUTHZ_BATCH_ISSUER_OUT_OF_SCOPE`: issuer set incompatibile con policy o msg type;
- `AUTHZ_BATCH_DUPLICATE_SIGNATURE`: più firme con lo stesso `issuer_id`;
- `AUTHZ_BATCH_QUORUM_NOT_MET`: peso valido unico insufficiente;
- `AUTHZ_BATCH_REPLAY`: `batch_id` non maggiore dell'ultimo applicato;
- `AUTHZ_BATCH_DUPLICATE_RECORD`: logical key record duplicata nel batch;
- `AUTHZ_BATCH_STALE_REVOCATION`: revoca non riferita esattamente al CURRENT record;
- `AUTHZ_BATCH_STALE_ISSUER_SET`: `sign_doc.issuer_set_id` non è l'issuer set
  corrente selezionato dalla governance per `(policy_id, msg_type_url)`.

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
batch_hash
policy_id
policy_version
issuer_set_id
record_count
quorum_weight
submitter
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
