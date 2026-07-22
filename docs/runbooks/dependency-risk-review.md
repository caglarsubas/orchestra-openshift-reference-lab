# Dependency risk review

This runbook converts the eight exact unsigned upstream image subjects into
review candidates. It cannot approve an exception, source-admit an image,
authorize mirroring, activate a dependency, or create campaign evidence.

The locked policy is
`config/dependency-risk-policy.lock.json`, digest
`sha256:819211d44fb510a0598135f5abb406cf53da579cd5537faf3d0b867d7aafc298`.
The checked-in exception intake is deliberately empty, digest
`sha256:95f2f3cfe9852b5f17c208a54431ee453373a98c5f70623603a9f3522db5d9bf`.

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

Run collection only in the exact published certification-runner image from
`config/cross-plane-release-set.lock.json`. Before scanning, download these
assets from that same platform release into restricted storage:

- `platform-release-manifest.json`;
- `platform-release-manifest.sigstore.json`;
- `platform-release-manifest.provenance.sigstore.json`;
- `release-orchestra-certification-runner-ubi.json`; and
- `certification-runner-toolchain-lock.json`.

The collector replays the release-manifest signature and SLSA provenance,
the runner image signature and CycloneDX attestation, the exact release,
revision, image, and toolchain projection, and the runner's offline self-test.
It refuses any externally supplied scanner policy environment. It downloads
and hashes both frozen Trivy databases before scanning, then disables database
updates for all eight scans.

Use Workload Identity Federation to obtain a short-lived collector identity
and Cloud KMS signing authority. Determine the approved public-key digest in a
separate reviewer-controlled step. The exact RC8 runner package is private, so
also issue a short-lived source-registry credential with package-read access
and place its Docker config under ignored `auth/` storage. The pull credential
is consumed by Cosign, Trivy, and Syft and is never copied into evidence. Then
launch the exact runner image with the repository and restricted release
directory mounted. Its entrypoint defaults to `orchestra-certification`, so
override the entrypoint to Bash when invoking the collector:

```bash
runner="$(jq -r .certificationRunner.image config/cross-plane-release-set.lock.json)"
mkdir -p restricted

docker run --rm --platform linux/amd64 \
  --entrypoint /bin/bash \
  --user 1001230000 \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=2g \
  --env GOOGLE_APPLICATION_CREDENTIALS=/run/orchestra-auth/gcp-wif.json \
  --env DOCKER_CONFIG=/run/orchestra-auth/docker \
  --volume "$PWD/auth/gcp-wif.json:/run/orchestra-auth/gcp-wif.json:ro" \
  --volume "$PWD/auth/docker-config.json:/run/orchestra-auth/docker/config.json:ro" \
  --volume "$PWD:/workspace:ro" \
  --volume "$PWD/restricted:/workspace/restricted:rw" \
  --workdir /workspace \
  "$runner" \
  scripts/collect_dependency_risk_evidence.sh \
    --output-dir restricted/dependency-risk-collection-<run-id> \
    --evidence-id orchestra-dependency-risk-evidence-<run-id> \
    --actor-identity-digest 'sha256:<collector-identity-digest>' \
    --platform-release-dir restricted/platform-release-rc8 \
    --signing-key 'gcpkms://projects/.../cryptoKeyVersions/...' \
    --expected-signing-public-key-digest 'sha256:<approved-public-key-digest>'
```

The output directory must not already exist. The collector stages everything
in a mode-`0700` sibling directory, writes files mode `0600`, and renames the
directory into place only after every scan and the Cloud KMS detached
signature succeed. Failure removes the partial staging directory. It never
overwrites or appends to earlier evidence.

The KMS signature is an authorized collector assertion, not remote hardware
attestation of the container process. The later source-admission replay must
also retain the controlled Job specification, admission result, and runtime
resolved image ID for the exact runner digest. This is why a valid collection
still leaves `sourceAdmissionAuthorized: false`.

The signed collection statement binds every raw file digest, exact source and
platform subject, cross-plane release set, runner release/image/toolchain and
publisher provenance, collector and signing-key digests, exact scanner
versions, both Trivy database digests, invocation policy, and start/end times.
The statement and manifest follow
`schemas/dependency-risk-collection-statement-v1.schema.json` and
`schemas/dependency-risk-scan-manifest-v1.schema.json`. Keep reports,
statements, and signature bundles under ignored `restricted/` storage; never
commit them.

Collection must finish within six hours and inside the seven-day source
observation window. A network, registry, scanner, or database error is an
indeterminate collection failure, not a clean report.

## Build the payload-free candidate

Independently verify the collection before building a summary. Verification
recomputes every referenced digest, compares the complete statement projection
to the manifest, verifies the Cloud KMS signature through the captured public
key, replays publisher signatures/provenance, and re-verifies the exact runner
image and SBOM attestation:

```bash
python3 scripts/verify_dependency_risk_collection.py \
  --manifest restricted/dependency-risk-collection-<run-id>/dependency-risk-scan-manifest.json
```

Then build the payload-free summary. The builder repeats the complete
verification and cannot be invoked from its CLI without valid detached and
publisher attestations:

```bash
python3 scripts/build_dependency_risk_evidence.py \
  --manifest restricted/dependency-risk-collection-<run-id>/dependency-risk-scan-manifest.json \
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
