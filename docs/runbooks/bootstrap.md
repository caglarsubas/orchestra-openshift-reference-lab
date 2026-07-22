# Bootstrap runbook

## Preconditions

1. A fresh live prerequisite observation has been independently reviewed.
2. `restricted/prerequisites.json` passes `--require-ready
   --readiness-stage bootstrap`. Project and WIF gates are not required yet
   because this module creates them.
3. Two operators review project IDs, billing account, monthly budget, quota,
   DNS delegation, image pins, approved egress CIDRs, and the exact installer
   digest.
4. A dedicated GCP organization or folder parent is visible to the bootstrap
   identity. No-organization project creation is outside the locked profile.
5. The initial identity is short-lived and recorded by digest. No key file is
   created or downloaded.
6. The working directory is encrypted and excluded from backup/sync tools that
   are not approved for restricted material.

## Bootstrap apply

1. Create `restricted/bootstrap.auto.tfvars.json` with non-secret project and
   topology inputs. Keep the billing account input in the protected execution
   environment rather than shell history.
2. Run repository validation and both Terraform validations.
3. Produce a saved bootstrap plan under ignored `artifacts/`, record its
   digest, and obtain two-person approval.
4. Apply that exact plan once. Verify two distinct projects, API enablement,
   versioned CMEK state bucket, budget thresholds, WIF provider condition, and
   absence of service-account keys. The bootstrap also creates the separate
   `dependency-risk-preflight` provider and `orchestra-dependency-risk`
   identity, plus the `dependency-risk-collection` provider and
   `orchestra-risk-collector` identity, plus the `dependency-risk-custody`
   provider and `orchestra-custody-verifier` identity. Confirm each provider
   condition names only exact `main`, `workflow_dispatch`, its own protected
   environment, and its own exact workflow; confirm all three identities have
   no project role. Verify all four providers, including the foundation
   planner, map a distinct provider-prefixed numeric repository/environment
   `google.subject`, and each service account grants impersonation only to that
   exact `principal://.../subject/...`. Reject a repository-wide
   `principalSet` binding.
5. Configure the foundation GCS backend using the bootstrap outputs. Never
   migrate state to a local backend.
6. Re-authenticate through WIF and prove the bootstrap credential is no longer
   used for ordinary foundation operations.
7. Re-run the read-only observation, obtain independent project/WIF review, and
   require `--readiness-stage foundation` before the foundation apply.

## Foundation apply

1. Pin immutable bastion/probe OS images and probe container image.
2. Review every egress CIDR and its business purpose. `0.0.0.0/0` is rejected.
3. Configure the independently protected GitHub environment, then follow
   `docs/runbooks/foundation-plan.md`. The plan identity must remain read-only,
   use `certification_mode=false` and `lock_signed_evidence_bucket=false`, and
   must not produce an apply artifact.
4. Apply the reviewed plan, then prove no VM has an external IP, both flow-log
   sinks receive traffic, the two probes are in distinct zones, GKE has
   exactly three standard nodes, the immutable `orchestra-bootstrap` Artifact
   Registry repository exists, VPC peering is active in both directions, the
   public DNS zone has only its managed SOA/NS records, and the services-to-
   target DNS peering zone has no writable records.
5. Verify the separate `dependency-risk-collection-signing` key uses
   `ASYMMETRIC_SIGN` and `EC_SIGN_P256_SHA256`. Confirm the preflight identity
   has only `roles/cloudkms.signerVerifier` on that key and no bucket or mirror
   grant. Confirm the full-collection identity has the same key-level role and
   only `roles/storage.objectCreator` on the restricted raw-evidence bucket,
   with no read, delete, signed-evidence, mirror, or project grant. Record an
   exact enabled key version and have an independent reviewer derive the
   public-key PEM digest. Verify the separate
   `dependency-risk-custody-verification-signing` key has the same algorithm,
   and the custody verifier has only `roles/cloudkms.publicKeyViewer` on the
   collection key plus `roles/cloudkms.signerVerifier` on the verification
   key. Confirm managed-folder-scoped `roles/storage.objectViewer` on
   `dependency-risk/` and create-only `roles/storage.objectCreator` on
   `dependency-risk-custody/`, with no project, delete, mirror, source
   admission, or activation grant. Independently bind exact versions and PEM
   digests for both keys before following all three protected procedures in
   `docs/runbooks/dependency-risk-review.md`.
6. Exercise backup/export access before considering the retention lock.
7. In a separately approved change, set certification mode and the exact lock
   acknowledgement. Confirm the 400-day lock is irreversible before apply.
8. Follow `docs/runbooks/dns-delegation.md` to establish and independently
   verify the exact public DNS delegation. Require `--readiness-stage
   openshift-install` before rendering or executing the OpenShift installer.

## Dependency source intake

1. Re-download every chart version in `config/dependency-bom.lock.json` from
   its declared HTTPS repository and verify the package digest independently.
2. Record upstream signature verification. When an upstream does not publish
   a usable signature, stop for a named security exception; a package hash by
   itself is not publisher identity.
3. Render each chart offline, enumerate every image, resolve each image to a
   digest, scan it, and verify its upstream signature or approved exception.
4. Mirror charts and images into the immutable Artifact Registry seed with the
   dedicated short-lived mirror identity. Apply the lab KMS signature and
   record source-to-destination bindings without rewriting the source BOM.
5. Bootstrap services-plane Argo CD only from that admitted inventory. The
   tracked AppProject remains deny-all and contains no Applications at this
   stage.
6. Promote the same admitted subjects into Harbor after Harbor is healthy.
   Keep the bootstrap seed until Harbor loss and rollback are proven.

## Failure handling

- Never rerun an apply blindly. Capture state serial, plan digest, actor, and
  provider error first.
- Never grant the read-only planner object-write, project mutation, or apply
  permissions to work around a failed preview.
- If a partial apply affects routing, IAM, KMS, or retention, stop and obtain
  security review before repair.
- A bootstrap or foundation apply is infrastructure evidence only. It cannot
  populate any of the 18 product certification slots.
