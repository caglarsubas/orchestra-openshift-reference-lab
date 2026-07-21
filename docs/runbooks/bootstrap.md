# Bootstrap runbook

## Preconditions

1. `restricted/prerequisites.json` passes `--require-ready`.
2. Two operators review project IDs, billing account, monthly budget, quota,
   DNS delegation, image pins, approved egress CIDRs, and the exact installer
   digest.
3. The initial identity is short-lived and recorded by digest. No key file is
   created or downloaded.
4. The working directory is encrypted and excluded from backup/sync tools that
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
   absence of service-account keys.
5. Configure the foundation GCS backend using the bootstrap outputs. Never
   migrate state to a local backend.
6. Re-authenticate through WIF and prove the bootstrap credential is no longer
   used for ordinary foundation operations.

## Foundation apply

1. Pin immutable bastion/probe OS images and probe container image.
2. Review every egress CIDR and its business purpose. `0.0.0.0/0` is rejected.
3. Run a non-certification plan with
   `certification_mode=false` and
   `lock_signed_evidence_bucket=false`.
4. Apply the reviewed plan, then prove no VM has an external IP, both flow-log
   sinks receive traffic, the two probes are in distinct zones, GKE has
   exactly three standard nodes, the immutable `orchestra-bootstrap` Artifact
   Registry repository exists, and peering is active in both directions.
5. Exercise backup/export access before considering the retention lock.
6. In a separately approved change, set certification mode and the exact lock
   acknowledgement. Confirm the 400-day lock is irreversible before apply.

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
- If a partial apply affects routing, IAM, KMS, or retention, stop and obtain
  security review before repair.
- A bootstrap or foundation apply is infrastructure evidence only. It cannot
  populate any of the 18 product certification slots.
