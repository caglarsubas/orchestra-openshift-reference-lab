# Dependency risk review

This runbook converts the eight exact unsigned upstream image subjects into
review candidates. It cannot approve an exception, source-admit an image,
authorize mirroring, activate a dependency, or create campaign evidence.

The locked policy is
`config/dependency-risk-policy.lock.json`, digest
`sha256:c0f22c02e37447a97a6d97c6352d7fb2207c601969ba7857d7910ab661f3731e`.
The checked-in exception intake is deliberately empty, digest
`sha256:ddff89276316a21d25770cfbfc5095dcf2781281e4026236d98d6bbf784cf848`.

## Separation of duties

Use distinct short-lived identities for collection, exception request,
security review, service-owner review, mirroring, and KMS signing. The
requestor and signed-runner collector cannot approve the exception. The two
reviewers must have distinct identity digests and roles:

- `security-reviewer` verifies provenance, vulnerability evidence, the risk
  assessment, and the compensating-control plan;
- `service-owner` verifies operational need, compatibility, licence review,
  upgrade ownership, and the expiry/remediation plan.

Each approval is separately signed and binds the exact per-subject candidate
digest. One identity cannot satisfy both roles.

## Collect raw evidence

Run collection only in the published, signed certification-runner image. The
runner must pin Trivy, Syft, Cosign, their invocation policy, and the Trivy
database digest. Scan every exact `linux/amd64` platform subject from
`config/dependency-admission.lock.json` without an ignore file, ignored
unfixed findings, or a severity filter.

Equivalent runner commands are:

```bash
trivy image \
  --platform linux/amd64 \
  --scanners vuln \
  --format json \
  --output restricted/<subject-id>.trivy.json \
  '<repository>@sha256:<platform-digest>'

syft scan \
  --platform linux/amd64 \
  '<repository>@sha256:<platform-digest>' \
  --output spdx-json=restricted/<subject-id>.spdx.json
```

The signed collection statement must bind all raw file digests, exact source
and platform subjects, runner image and provenance bundle, actor identity,
tool versions, database digest, invocation policy, and start/end timestamps.
The scan manifest follows
`schemas/dependency-risk-scan-manifest-v1.schema.json`. Keep reports,
statements, and signature bundles under ignored `restricted/` storage; never
commit them.

Collection must finish within six hours and inside the seven-day source
observation window. A network, registry, scanner, or database error is an
indeterminate collection failure, not a clean report.

## Build the payload-free candidate

After independently verifying the collection attestation, build a summary:

```bash
python3 scripts/build_dependency_risk_evidence.py \
  --manifest restricted/dependency-risk-scan-manifest.json \
  --output restricted/dependency-risk-evidence.candidate.json
```

The builder refuses to overwrite output. It rejects path traversal, missing or
changed raw reports, source/platform drift, scanner-policy drift, source-window
drift, malformed Trivy results, malformed SPDX, incomplete inventory, and
unbound runner or attestation digests.

The output follows
`schemas/dependency-risk-evidence-v1.schema.json`. It contains counts, licence
expressions, report digests, machine-review digests, and a declared
compensating-control plan. It contains no image payload, secret, approval, or
admission claim. Critical, high, or unknown-severity findings set the subject
to `blocked`. A passing machine threshold only sets
`eligible-for-human-review`; licence review is always manual.

## Prepare and review exceptions

Create a new restricted intake from the strict shape in
`config/dependency-signature-exceptions.example.json`. For each reviewable
subject, bind:

1. the complete risk-evidence digest and collection attestation;
2. runner image/provenance, SBOM, vulnerability, licence-inventory, and
   machine-review digests;
3. independently signed human licence and risk-review digests;
4. the exact compensating-control plan digest;
5. a unique exception ID, request time, requestor identity, and candidate
   digest; and
6. two signed approvals with the required independent roles.

Validate the populated intake at a declared UTC time:

```bash
python3 scripts/validate_dependency_risk_intake.py \
  --risk-evidence restricted/dependency-risk-evidence.candidate.json \
  --exception-intake restricted/dependency-signature-exceptions.json \
  --at-time 2026-07-22T03:00:00Z
```

Risk evidence older than 72 hours cannot support a new exception. Exceptions
expire no later than 720 hours after approval. Expiry blocks new syncs; it does
not silently extend an existing exception. A new source digest, source
observation, scanner database, material finding, control plan, or reviewer
decision requires a new candidate digest and approvals.

## Admission boundary

Even when all eight exceptions are valid, the intake remains `blocked` with:

- `sourceAdmissionAuthorized: false`;
- `mirrorAuthorization: false`;
- `activationAuthorized: false`;
- `applied: false`; and
- `campaignEvidence: false`.

The source-admission aggregate must separately verify the signed-runner Cosign
replay for all eleven subjects and bind this exception intake. Destination
mirroring, lab KMS signing, private pulls, GitOps activation, and campaign
evidence remain later independent states.
