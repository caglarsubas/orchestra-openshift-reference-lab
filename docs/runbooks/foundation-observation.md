# Independent foundation observation runbook

This procedure verifies one completed foundation apply through a separate,
read-only identity. It checks the deployed observer boundary, immutable plan
and receipt custody, current Terraform state, and live provider state. It can
publish a signed post-apply observation, but it cannot mutate infrastructure,
authorize dependency activation, populate a campaign slot, or verify the
reference profile.

## Authority boundary

Bootstrap declares a sixth exact-workflow WIF provider and the dedicated
`orchestra-foundation-observer` service account. The observer receives:

- read-only project roles required by the Google Terraform provider;
- a custom storage metadata/IAM role with no object-content permission;
- prefix-scoped read access to foundation state, plans, and apply receipts;
- create-only access to `foundation-observations/`;
- public-key access to the plan and receipt keys; and
- sign/verify access only to `foundation-observation-signing`.

It receives no state lock, source-object write, report read/delete,
infrastructure mutation, Artifact Registry write, or campaign authority.

The project/folder/organization operator must separately grant
`roles/iam.securityReviewer` to the observer on every ancestor returned for
the two dedicated projects. This read-only grant is intentionally external
because bootstrap may place projects under either a folder or an organization.
The workflow rejects a missing ancestor grant, any additional direct ancestor
role, any extra service-account impersonation grant, and any ancestor binding
to the observer's WIF pool. This is an exact direct-binding check. Effective
access through Google Workspace groups is an external readiness review until
a separately authorized Cloud Asset Policy Analyzer lane can expand groups.

## External prerequisites

1. Bootstrap and foundation have been applied from the same exact `main`
   revision that contains this observation lane.
2. The apply workflow published a completed three-object receipt prefix and
   printed its SHA-256 receipt digest.
3. An operator independently recorded exact enabled versions and public-key
   PEM digests for `foundation-plan-signing`,
   `foundation-apply-receipt-signing`, and
   `foundation-observation-signing`.
4. `reference-lab-foundation-observation` is a private-repository GitHub
   Enterprise environment with one non-owner reviewer, self-review disabled,
   exact `main` deployment policy, and administrator bypass disabled.
5. The observer has the exact direct project, ancestor, storage, KMS,
   service-account, and WIF grants in
   `config/foundation-observation.lock.json`. No user-managed service-account
   key exists.
6. The workflow attempt is `1`. Reruns are rejected.

Configure these non-secret environment variables:

| Variable | Contract |
|---|---|
| `GCP_FOUNDATION_OBSERVATION_WIF_PROVIDER` | Bootstrap output `foundation_observation_workload_identity_provider` |
| `GCP_FOUNDATION_OBSERVATION_SERVICE_ACCOUNT` | Bootstrap output `foundation_observation_service_account` |
| `GCP_TERRAFORM_STATE_BUCKET` | Bootstrap output `state_bucket` |
| `FOUNDATION_OBSERVATION_REVIEW_GATE_CONFIGURED` | Operational interlock set only after environment review |

The environment also receives the exact non-secret foundation variables used
by the plan and apply jobs. The source revision and variables must match the
applied saved plan.

## Dispatch

```bash
gh workflow run foundation-observation.yml \
  --ref main \
  -f expected_main_sha='<exact-main-sha>' \
  -f plan_id='orchestra-foundation-plan-<plan-run>.1' \
  -f apply_id='orchestra-foundation-apply-<apply-run>.1' \
  -f expected_receipt_digest='sha256:<receipt-digest>' \
  -f plan_kms_key_version='<reviewed-version>' \
  -f expected_plan_public_key_digest='sha256:<public-key-digest>' \
  -f receipt_kms_key_version='<reviewed-version>' \
  -f expected_receipt_public_key_digest='sha256:<public-key-digest>' \
  -f observation_kms_key_version='<reviewed-version>' \
  -f expected_observation_public_key_digest='sha256:<public-key-digest>' \
  -f reason='Observe the exact applied foundation without mutation'
```

The environment reviewer compares every input with the plan review and apply
receipt before approving the current run.

## Verification sequence

The workflow:

1. Verifies its current GitHub environment approval and obtains only the
   exact observer WIF identity.
2. Queries the live WIF provider, service-account policy and keys, project and
   ancestor policies, custom role definition, managed-folder policies, and KMS
   policies. All direct observer grants must match exactly.
3. Lists exactly three receipt objects and five plan objects, validates
   pre-download size and completion-marker order, and pins every downloaded
   generation and metageneration.
4. Re-derives all three KMS public keys, compares their PEM digests, and
   verifies the plan-statement and apply-receipt signatures.
5. Pins `foundation/default.tfstate`, pulls the same backend state, and requires
   its serial, lineage digest, and state digest to equal the apply receipt.
6. Runs only:

   ```bash
   terraform plan \
     -refresh-only \
     -lock=false \
     -detailed-exitcode \
     -input=false
   ```

7. Requires exit code `0`, no managed-resource action other than `no-op`, only
   `read` or `no-op` for data resources, and an exact resource identity-set
   match with the signed source plan summary.
8. Re-reads state metadata and requires the generation and metageneration to
   be unchanged throughout the observation.
9. Builds and signs a strict report, verifies it locally, then creates exactly
   three non-overwritable objects:

   ```text
   foundation-observations/v1/<profile>/<revision>/<plan>/<apply>/<observation>/
     foundation-observation.json
     foundation-observation-public-key.pem
     foundation-observation-signature.sigstore.json
   ```

   The detached signature is the final completion marker. No state, plan,
   receipt, provider payload, refresh plan, or Terraform log is uploaded to
   GitHub.

## Interpretation

A valid signed report may state `foundationPostApplyObserved: true` and
`independentlyObserved: true` for this narrow foundation check. It must keep:

- `campaignEvidence: false`
- `referenceProfileVerified: false`
- `customerCertified: false`
- `redHatCertified: false`
- `contractualSla: false`

The provider refresh proves that the source-declared foundation resources
match current provider state. It does not prove OpenShift health, dependency
availability, workload behavior, backup recovery, RPO/RTO, fault tolerance,
load behavior, or soak availability. Those remain separate live evidence
slots.

## Failure handling

- Never rerun an observation attempt. Dispatch a new run with a new ID and
  approval.
- Exit code `2` is drift, not success. Stop downstream work and repair through
  a new reviewed plan and apply.
- Reject a changed state generation, lineage, receipt, plan identity set,
  public key, signature, source revision, observer role, custom-role
  permission, ancestor grant, or completion-marker order.
- Never broaden the observer to make a failed refresh pass. Add only a
  reviewed read permission when the exact provider operation proves it is
  missing, then regenerate every bound authority digest.
- A successful report is a foundation readiness input only. It must not be
  copied into any of the 18 certification slots.
