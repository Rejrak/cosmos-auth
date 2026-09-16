# Architecture Contract v1

## Target

```text
external attributes / Keycloak / policy backend
        -> authorization middleware
        -> typed authorization records
        -> canonical signed batch
        -> x/authzattrs
        -> deterministic authorization evaluator
        -> allow / deny
```

## Invarianti

1. `FinalizeBlock` e l'AnteHandler autoritativo non effettuano I/O esterno.
2. `ProcessProposal` non effettua I/O esterno e usa la stessa semantica deterministica dell'enforcement finale.
3. `CheckTx` può avere un filtro esterno opzionale, ma non è l'autorità finale.
4. La tx utente normale non verifica firme issuer e non chiama oracle.
5. Firme, quorum e anti-replay sono verificati su `MsgBatchUpsertAuthorizations`/equivalente.
6. La policy applicabile è selezionata dal middleware/policy engine, non dal richiedente.
7. Issuer/checker trusted, chiavi, scope, stato e quorum sono verificabili on-chain.
8. Le autorizzazioni usano constraints pubblici tipizzati per condizioni (`amount <= max_amount` non può essere verificato con un hash opaco).
9. V1 usa height per validità (`valid_from_height`, `valid_until_height`) salvo decisione ADR esplicita.
10. Revoca persistente (`revoked=true` o equivalente auditabile), non semplice delete silenzioso.
11. Ogni modifica al protocollo aggiorna contract version e test vectors in entrambi i repo.
12. Nessun secret o DB runtime è committato.

## Primo scope funzionale

Solo `cosmos.bank.v1beta1.MsgSend` diretto:

```text
subject/from_address
msg_type_url
denom
receiver
max_amount
valid_from_height
valid_until_height
policy_id
policy_version
issuer_set_id
revoked
```

Fuori scope iniziale: `authz.MsgExec`, IBC transfer, certificate per-tx, Authorization Chain, ZK.
