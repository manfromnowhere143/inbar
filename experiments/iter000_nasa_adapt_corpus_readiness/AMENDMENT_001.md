# Amendment 001: Python TLS Trust Store

Status: AUTHORIZED FOR ONE INFRASTRUCTURE RETRY

## Trigger

Attempt 000 stopped before source acceptance. Its signed execution ledger contains exactly
`run-started` followed by `run-failed`. The terminal event records `URLError` caused by
certificate verification failure while Python was establishing the first HTTPS connection.

The attempt produced no accepted dataset, ingestion artifact, readiness report, scientific
verdict, or result. It therefore provides infrastructure evidence only and cannot support a
claim about NASA ADAPT corpus readiness.

## Frozen Scientific Scope

The iteration 000 hypothesis remains byte-identical to the root preregistration. The NASA
ADAPT dataset lock, resource identities, hashes, expected file count, visibility rules,
readiness gates, rejection conditions, and claims remain unchanged.

No observation from attempt 000 may be treated as accepted data. No threshold, selection
rule, parser rule, split rule, baseline, or claim may change under this amendment.

## Authorized Change

One additional execution, `attempt_001`, is authorized solely to replace the Python runtime's
unresolved local certificate-authority path with the Mozilla trust store distributed by
`certifi`.

Administrative code may isolate attempt 001 output, bind this amendment to the execution,
route the command and verifier to the authorized attempt, and consume one signed execution
authority before creating attempt output. Those controls do not alter the scientific protocol,
data handling, readiness adjudication, or claim semantics.

The gate-control execution seal may be regenerated after the validator changes. Its gate set,
failure classes, positive and negative control node identities, and control implementations must
remain unchanged. The regenerated seal must bind the current validator and reproduce all sixteen
controls with a zero exit status.

The HTTPS client must use a default verified TLS context loaded from `certifi.where()`. Server
certificate verification and hostname verification must remain required. TLS 1.2 is the
minimum permitted protocol version. The locked runtime must use `certifi` version `2026.6.17`,
and the CA bundle returned by `certifi.where()` must have SHA-256
`bbc7e9c01d7551bb8a159b5dedd989b8ee3ce105aff522b68eb1b01bf854cab0`.

## Prohibited Changes

TLS verification bypasses are forbidden. This includes unverified SSL contexts,
`CERT_NONE`, disabled hostname checks, `PYTHONHTTPSVERIFY=0`, insecure command-line download
flags, and request options that disable certificate verification.

The retry may not write into `attempt_000`. It may not create `attempt_002` or any later
attempt. A failure of `attempt_001` requires a new evidence-backed amendment before any
further execution.

Deleting `attempt_001` proof output does not restore execution authority. The durable authority
receipt is created with exclusive file creation, synchronized to local storage before any proof
directory is created, and treated as consumed whenever that receipt path exists. Concurrent
local replay and ordinary proof-deletion replay must fail closed.

## Machine Authority

`protocol/amendments/iter000_001.json` is the controlling machine-readable contract.
Repository mission validation must reject retry authorization unless the signed attempt 000
ledger, pinned signer, committed evidence, frozen inputs, exact retry count, and verified TLS
implementation all satisfy that contract.

`protocol/attempt_authorities/iter000_001.json` is the separately selected execution authority.
It binds the exact command, signer, amendment, lockfile, producer, validator, verifier, protocol,
and schema hashes. Its signed consumption receipt is independently checked against the selected
authority and the completed proof.

This is a local Git and Ed25519 trust boundary without an external timestamp, hardware monotonic
counter, remote append-only log, or write-once storage. It does not claim to prevent the same
local owner from deleting the receipt, rolling back the repository, or compromising the signing
key. Those threats require an external durability service and remain outside this amendment.
