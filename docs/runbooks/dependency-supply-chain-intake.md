# Dependency supply-chain intake

This procedure advances a resolved source subject through four independent
states: source observation, source admission, destination mirroring, and lab
signature admission. A success in one state never implies the next.

The current immutable source observation is
`config/dependency-source-verification.lock.json`, digest
`sha256:75539cd9e8b0fce8e556b7d3cd8a7437d2e6f26525e96639085feff431478ed8`.
It was produced on a developer workstation with Cosign `v3.1.1`; it is not a
certification-runner attestation or campaign report.

## Current observation

Three locked index subjects have keyless signatures that verify with exact
GitHub Actions identities and issuer
`https://token.actions.githubusercontent.com`:

- CloudNativePG operator `1.30.0`;
- CloudNativePG PostgreSQL `16.10-system-trixie`; and
- External Secrets `v2.8.0`.

The validator permits no wildcard certificate identity or issuer. It binds
the signature bundle digest, format, transparency-log index, integrated time,
source subject, and all successful verification checks.

No attached Cosign signature was found for the two Barman Cloud images, two
Altinity images, ClickHouse Server, NATS Server, NATS config reloader, or
Vault at their locked index subjects. Those eight observations do not approve
the images. Each requires an expiring, two-person exception with independent
licence, vulnerability, risk, and compensating-control evidence.

The machine-readable policy and empty intake for those reviews are
`config/dependency-risk-policy.lock.json` and
`config/dependency-signature-exceptions.example.json`. The end-to-end operator
procedure is in [Dependency risk review](dependency-risk-review.md).

## Reproduce the observation

The live verifier rejects stale observations, Cosign version drift, trust-root
drift, identity drift, signature bundle drift, and ambiguous registry errors.
A network or authorization failure is not accepted as proof that a signature
is absent.

```bash
python3 scripts/verify_dependency_signatures.py
```

Use `--image <id>` for a bounded retry. Successful output still ends with
`sourceAdmission=false`, `mirrorAuthorization=false`, and
`campaignEvidence=false`.

Before source admission, repeat the same verification in the published,
signed certification-runner image. Preserve the Cosign output, trusted-root
object, command policy, runner digest, and actor identity digest in restricted
raw evidence. Create a new immutable source-verification record; do not mutate
the developer observation.

## Exception requirements

An exception is valid only when all of these are present in a new immutable
record:

1. a unique exception ID and exact source subject;
2. two distinct reviewer identity digests;
3. approval and expiry timestamps, with a maximum 30-day lifetime;
4. licence and vulnerability report digests;
5. a risk-review digest and compensating-control digest; and
6. confirmation that the destination subject will receive a lab KMS
   signature and be rejected outside the declared admission policy.

The source owner, mirror operator, KMS signer, and final approver may not all
be the same identity. Expiry blocks new syncs and requires a new candidate.

An approved exception is still not source admission. The separate
signed-runner signature replay and source-admission aggregate must bind the
same source-verification, risk-policy, and exception-intake digests. The
exception contract always keeps `sourceAdmissionAuthorized` and
`mirrorAuthorization` false.

## Mirror receipts

`config/dependency-mirror-intake.example.json`, digest
`sha256:9ee380a9a86a2ea6ceb2767891845fe0693e6f4632029c5bcfae360c64e43060`,
is an intentionally empty live-intake shape. It contains all eleven subjects
but no repository binding, destination digest, object generation, actor
identity, receipt, lab signature, pull proof, or approval.

After source admission:

1. copy the exact `linux/amd64` manifest into the bootstrap Artifact Registry;
2. record the destination subject digest, immutable object generation,
   short-lived mirror actor identity digest, and signed receipt digest;
3. apply the lab KMS signature and record its bundle, signer, and policy
   digests;
4. copy the admitted subject into Harbor and record the equivalent receipt;
5. verify private pulls by digest from one GKE node and one OpenShift node; and
6. obtain two independent approvals on the complete intake digest.

Any populated field requires a new intake artifact and its underlying signed
receipt. The checked-in empty template must never be edited to look complete.

## Activation boundary

Only a complete intake may be referenced by a new admitted dependency overlay.
The current dependency and product AppProjects keep continuous deny windows,
and the dependency overlay contains zero Applications. Argo CD remains the
only deployment authority.
