# Dependency risk review

This runbook converts the eight exact unsigned upstream image subjects into
review candidates. It cannot approve an exception, source-admit an image,
authorize mirroring, activate a dependency, or create campaign evidence.

The locked policy is
`config/dependency-risk-policy.lock.json`, digest
`sha256:5a48b2e16ace3e14ff01b6801c45d97a34cc0e12d56635f2a903b9e5ea726b2a`.
The checked-in exception intake is deliberately empty, digest
`sha256:f2457b0e7f9adb772494e2f14757fd15269fe34dbb5bac7e986c000a28f0ff1e`.
The preflight authority is locked separately in
`config/dependency-risk-execution.lock.json`, digest
`sha256:324b683e473bd474fdb2f48e48bb4737a1cbd681f762203ba7e0410553ee2f99`.
The full-collection and restricted raw-custody authority is locked in
`config/dependency-risk-collection-execution.lock.json`, digest
`sha256:e56bfde30b5772723a2ee82a79dbed2a1bc1f9a1d90fb18846e0ae7906792446`.
The independent raw-custody verification authority is locked in
`config/dependency-risk-custody-verification.lock.json`, digest
`sha256:dc52a9210f0eb0bbfb60b61c5d57ed0ef8ed23aa3638b11760547de90b9cc976`.

## Separation of duties

Use distinct short-lived identities for preflight, full collection, exception
request, security review, service-owner review, custody verification, and
mirroring. The source declares the preflight signer's only federation path as
the exact preflight workflow, which contains no full-collection invocation.
The full-collection signer is bound to a different exact workflow and may only
sign its collection and create objects in restricted raw custody. It cannot
read/delete raw objects, write signed evidence, mirror, request an exception,
or approve one. The custody verifier uses a third exact-workflow identity. It
can read only the dependency-risk raw prefix, create only custody reports under
a separate signed-evidence prefix, view the collection public key, and sign
with a separate verification key. It cannot overwrite/delete either prefix,
mirror, admit, activate, request an exception, or approve one. The requestor
and signed-runner collector cannot approve the exception. The two reviewers
must have distinct identity digests and roles:

Each authority also uses a distinct provider-prefixed `google.subject` derived
from the numeric repository ID and protected environment. Its service account
accepts only that exact subject, never the repository-wide principal set shared
by the workload identity pool.

- `security-reviewer` verifies provenance, vulnerability evidence, the risk
  assessment, and the compensating-control plan;
- `service-owner` verifies operational need, compatibility, licence review,
  upgrade ownership, and the expiry/remediation plan.

Each approval is separately signed and binds the exact per-subject candidate
digest. One identity cannot satisfy both roles.

## Configure the protected preflight lane

The checked-in Terraform and workflow are declarations, not live authority.
After independently reviewed bootstrap and foundation applies:

1. Verify bootstrap output `dependency_risk_workload_identity_provider` names
   the `dependency-risk-preflight` provider and output
   `dependency_risk_service_account` names only
   `orchestra-dependency-risk` in the services/evidence project.
2. Verify foundation output `dependency_risk_signing_contract` against the
   live KMS and IAM APIs. The key must use `ASYMMETRIC_SIGN`, algorithm
   `EC_SIGN_P256_SHA256`, and software protection; the collector must have only
   key-level `roles/cloudkms.signerVerifier` and no project, bucket, or mirror
   grant.
3. Create GitHub environment
   `reference-lab-dependency-risk-preflight`. Restrict it to exact `main`,
   require at least one configured non-owner reviewer, prevent self-review,
   and disable administrator bypass. Set
   `DEPENDENCY_RISK_PREFLIGHT_REVIEW_GATE_CONFIGURED=true` only after a second
   operator verifies those controls.
4. Set environment variables `GCP_DEPENDENCY_RISK_WIF_PROVIDER`,
   `GCP_DEPENDENCY_RISK_COLLECTOR_SERVICE_ACCOUNT`, and
   `GCP_SERVICES_PROJECT_ID` from independently verified live outputs.
5. Follow `docs/runbooks/operator-control-plane-readiness.md` to install the
   exact dedicated GitHub App on only `agent-hook-v2`, with release contents
   read and package read. Store its App ID, installation ID, and private key as
   `DEPENDENCY_RISK_GITHUB_APP_ID`,
   `DEPENDENCY_RISK_GITHUB_APP_INSTALLATION_ID`, and
   `DEPENDENCY_RISK_GITHUB_APP_PRIVATE_KEY` environment secrets. Do not use a
   personal access token or a service-account key.
6. Select one enabled KMS key version. A reviewer outside the triggering
   workflow obtains its public key, writes the PEM in the exact form returned
   by Cloud KMS, computes `sha256sum`, and records that digest with the key
   version and source-observation window. A workflow input is not evidence of
   review; the protected-environment approval binds the reviewed values to the
   current run.

Dispatch only from exact `main` and never rerun a failed attempt:

```bash
revision="$(git rev-parse origin/main)"
gh workflow run dependency-risk-preflight.yml \
  --ref main \
  -f expected_main_sha="$revision" \
  -f kms_key_version='<reviewed-version>' \
  -f expected_signing_public_key_digest='sha256:<reviewed-pem-digest>' \
  -f reason='Verify dependency risk collection launch prerequisites'
```

The workflow re-reads the current environment approval, rejects rerun attempts,
mints an unrestricted App installation token to verify the exact one-repository
and read-only scope, revokes that token, obtains short-lived WIF and
repository-narrowed App tokens, downloads the exact five platform release
assets, mounts credentials read-only into the pinned runner, and invokes
`collect_dependency_risk_evidence.sh` exactly once with `--preflight-only`. It
uploads nothing and removes credentials, release assets, and transient logs. A
successful log contains `collectionStarted=false`; it is an operational
readiness observation, not stored campaign evidence.

Do not dispatch after the locked source-verification window expires. Renew and
review that source observation first, which changes its digest and all bound
contracts.

## Configure the protected full-collection lane

Configure this lane only after independently verifying the bootstrap and
foundation resources used by preflight:

1. Verify bootstrap outputs
   `dependency_risk_collection_workload_identity_provider` and
   `dependency_risk_collection_service_account`. They must name only the
   `dependency-risk-collection` provider and `orchestra-risk-collector`
   identity.
2. Verify foundation output `dependency_risk_collection_contract` and the
   live IAM APIs. The identity may have key-level
   `roles/cloudkms.signerVerifier` and bucket-level
   `roles/storage.objectCreator` only. Reject any project role, object read or
   delete grant, signed-evidence grant, or mirror grant.
3. Create GitHub environment
   `reference-lab-dependency-risk-collection`, restricted to exact `main`.
   Require a configured non-owner reviewer, prevent self-review, and disable
   administrator bypass. Set
   `DEPENDENCY_RISK_COLLECTION_REVIEW_GATE_CONFIGURED=true` only after a
   second operator verifies these controls.
4. Set `GCP_DEPENDENCY_RISK_COLLECTION_WIF_PROVIDER`,
   `GCP_DEPENDENCY_RISK_COLLECTION_SERVICE_ACCOUNT`,
   `GCP_SERVICES_PROJECT_ID`, and `GCP_RAW_EVIDENCE_BUCKET` from independently
   observed live resources. Reuse all three narrowly installed GitHub App
   secrets from preflight; do not broaden its repository or permission scope.
5. Bind the exact enabled KMS key version and reviewer-derived PEM digest to
   the current environment approval. Never rerun a failed workflow attempt;
   dispatch a new run and obtain a new approval.

After a successful standalone preflight, dispatch the full lane from exact
`main`:

```bash
revision="$(git rev-parse origin/main)"
gh workflow run dependency-risk-collection.yml \
  --ref main \
  -f collection_scope='production-dependencies' \
  -f expected_main_sha="$revision" \
  -f kms_key_version='<reviewed-version>' \
  -f expected_signing_public_key_digest='sha256:<reviewed-pem-digest>' \
  -f reason='Collect bounded dependency vulnerability and SPDX evidence'
```

The workflow repeats preflight and the full collection in the same approved
attempt. It verifies the complete collection before uploading four
generation-zero objects under a unique evidence prefix. The deterministic raw
archive, KMS public key, and payload-free custody statement are uploaded first;
the detached custody signature is the final completion marker. An absent
signature means the prefix is incomplete. The collector cannot list the
bucket, read back objects, or capture immutable object generations, so success
still leaves `custodyVerified=false`.

## Configure the protected custody-verification lane

Configure this lane only after the full-collection authority has been verified
and a new, completed four-object raw prefix exists:

1. Verify bootstrap outputs
   `dependency_risk_custody_verification_workload_identity_provider` and
   `dependency_risk_custody_verification_service_account`. They must name only
   the `dependency-risk-custody` provider and `orchestra-custody-verifier`
   identity for the exact custody-verification workflow.
2. Verify foundation output
   `dependency_risk_custody_verification_contract` and live IAM independently.
   The identity may have `roles/storage.objectViewer` only on the
   `dependency-risk/` raw managed folder,
   `roles/storage.objectCreator` only on the `dependency-risk-custody/` signed
   managed folder, `roles/cloudkms.publicKeyViewer` only on the collection key,
   and `roles/cloudkms.signerVerifier` only on the separate verification key.
   Reject project roles, raw write/delete, signed read/delete, mirror, source
   admission, or activation authority.
3. Create GitHub environment
   `reference-lab-dependency-risk-custody-verification`, restricted to exact
   `main`. Require a configured non-owner reviewer, prevent self-review, and
   disable administrator bypass. Set
   `DEPENDENCY_RISK_CUSTODY_REVIEW_GATE_CONFIGURED=true` only after a second
   operator verifies those controls.
4. Set `GCP_DEPENDENCY_RISK_CUSTODY_WIF_PROVIDER`,
   `GCP_DEPENDENCY_RISK_CUSTODY_SERVICE_ACCOUNT`, `GCP_SERVICES_PROJECT_ID`,
   `GCP_RAW_EVIDENCE_BUCKET`, and `GCP_SIGNED_EVIDENCE_BUCKET` from
   independently observed live resources. Reuse all three narrowly installed
   GitHub App secrets; this workflow requests package-read only after verifying
   the App's full installation scope.
5. Independently select enabled collection and verification key versions,
   fetch their exact Cloud KMS public-key PEMs, and bind both PEM digests to the
   current protected-environment approval. Never reuse an approval or rerun a
   failed workflow attempt.

Dispatch from exact `main` after the collector has published its signature
completion marker:

```bash
revision="$(git rev-parse origin/main)"
gh workflow run dependency-risk-custody-verification.yml \
  --ref main \
  -f verification_scope='production-dependencies' \
  -f expected_main_sha="$revision" \
  -f evidence_id='<completed-evidence-id>' \
  -f collection_kms_key_version='<reviewed-collection-version>' \
  -f expected_collection_public_key_digest='sha256:<collection-pem-digest>' \
  -f verification_kms_key_version='<reviewed-verification-version>' \
  -f expected_verification_public_key_digest='sha256:<verification-pem-digest>' \
  -f reason='Independently verify immutable dependency-risk raw custody'
```

The workflow requires exactly four raw objects, records each generation and
metageneration, and pins both preconditions on every download. It requires the
detached signature to be the newest object, compares the stored collection
public key with the exact Cloud KMS key, safely extracts the bounded archive,
and replays the complete collection verifier. It then create-only uploads the
strict report and verification public key under `dependency-risk-custody/`,
with the report signature last as the completion marker. An absent report
signature means verification is incomplete. A successful report can set
`custodyVerified=true` only for that exact raw prefix; every source-admission,
mirror, activation, campaign, and reference-profile claim remains false.

The publishing workflow replays its new signature before upload. A later
read-only evidence reviewer must independently download the completed report,
verification public key, and signature bundle by immutable generation, obtain
the expected key digest outside those objects, and replay the same contract:

```bash
python3 scripts/validate_dependency_risk_custody_report.py \
  --report restricted/dependency-risk-custody-verification.json \
  --verification-public-key restricted/dependency-risk-custody-verification-public-key.pem \
  --signature-bundle restricted/dependency-risk-custody-verification-signature.sigstore.json \
  --expected-verification-public-key-digest 'sha256:<reviewed-pem-digest>'
```

`signatureVerified=true` verifies the detached report signature and its key
binding; it does not by itself authorize source admission or establish custody
for the report objects. Their generations belong in the later evidence index.

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

The protected full-collection workflow is the supported execution path. The
container command below is retained only to document the runner boundary and
for controlled local rehearsal; it is not authorized for live publication.
The workflow obtains a short-lived collector identity and Cloud KMS signing
authority, and a separate reviewer supplies the approved public-key digest.
The key version must be enabled and use `EC_SIGN_P256_SHA256`. The private
runner receives a short-lived package-read credential consumed by Cosign,
Trivy, and Syft and never copied into evidence.

First run the launch preflight. It replays the runner and release attestations,
checks the exact Trivy, Syft, Cosign, and gcloud versions, validates the source
window and approved public key, and performs an ephemeral Cloud KMS sign plus
local OpenSSL verification. It exits before scanner database downloads and
removes its staging directory, challenge, and signature. It creates no report,
authorization, or campaign evidence.

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
    --platform-release-dir restricted/platform-release-rc10 \
    --signing-key 'gcpkms://projects/.../cryptoKeyVersions/...' \
    --expected-signing-public-key-digest 'sha256:<approved-public-key-digest>' \
    --preflight-only
```

A successful preflight prints `collectionStarted=false` and every authorization
claim as `false`; it is a readiness signal, not a stored certification artifact.
The preflight workflow cannot start collection and must never be edited merely
to remove `--preflight-only`. Only the separately protected
`dependency-risk-collection.yml` contract may invoke the same container
without that flag. The runner entrypoint defaults to
`orchestra-certification`, so both controlled invocations retain an explicit
Bash entrypoint override.

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

Before building a payload-free candidate, a separate read-only custody actor
must list the exact four raw objects, record their immutable GCS generations,
recompute their digests, verify the detached signature and KMS public-key
binding, and attest that the signature object was the completion marker for
that prefix. The collector's success log is not that attestation. The protected
custody workflow now implements this contract in source, but its Terraform,
environment, and live report remain unapplied and unverified. Therefore no raw
prefix can currently advance to source admission.

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
