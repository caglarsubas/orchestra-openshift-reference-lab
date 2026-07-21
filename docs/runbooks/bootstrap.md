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
   exactly three standard nodes, and peering is active in both directions.
5. Exercise backup/export access before considering the retention lock.
6. In a separately approved change, set certification mode and the exact lock
   acknowledgement. Confirm the 400-day lock is irreversible before apply.

## Failure handling

- Never rerun an apply blindly. Capture state serial, plan digest, actor, and
  provider error first.
- If a partial apply affects routing, IAM, KMS, or retention, stop and obtain
  security review before repair.
- A bootstrap or foundation apply is infrastructure evidence only. It cannot
  populate any of the 18 product certification slots.
