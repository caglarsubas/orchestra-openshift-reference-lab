# Review-bound foundation apply runbook

This procedure consumes one immutable foundation plan package and applies that
exact saved plan. It can create lab infrastructure and publish a
self-attested execution receipt. It cannot independently verify the resulting
infrastructure, satisfy a certification slot, start a campaign, or verify the
reference profile.

## Authority split

Bootstrap declares four separate boundaries:

| Principal | Granted authority | Explicitly absent |
|---|---|---|
| `orchestra-lab-foundation-plan` | Read live APIs and foundation state without locking | State writes and infrastructure mutation |
| `orchestra-plan-packager` | Sign a plan statement and create objects under `foundation-plans/` | Object read/delete, state read, project roles, and infrastructure mutation |
| Approved `group:` reviewers | Read objects under `foundation-plans/` | State read, object mutation, signing, and infrastructure mutation |
| `orchestra-lab-foundation` | Foundation project roles, state locking, package read, and receipt signing/publication | Campaign authority; the workflow also forbids mirror operations |

The executor's services-project roles include Artifact Registry and broad
storage authority because the bootstrap foundation role predates this lane.
The authority contract records that fact. Workflow validation forbids mirror
commands, but it is not an IAM-level denial. Reducing the executor to a
purpose-specific role is a later hardening item.

## External prerequisites

The following must exist outside Git:

1. The bootstrap module has been applied and independently observed.
2. `reference-lab-foundation-plan` and
   `reference-lab-foundation-apply` are private-repository GitHub Enterprise
   environments. Each requires one configured non-owner reviewer, prevents
   self-review, permits only exact `main`, and has administrator bypass
   disabled through separately reviewed UI state.
3. `foundation_plan_reviewer_members` contains only approved `group:` IAM
   members. The apply approver is a member of that group and reviews the
   private plan before approving the apply environment.
4. The current `foundation` prerequisite projection passes independent review.
5. Exact enabled KMS versions and independently derived public-key PEM digests
   are recorded for `foundation-plan-signing` and
   `foundation-apply-receipt-signing`.
6. The plan and apply workflow attempts are both `1`. Reruns are rejected.

Set these apply-environment variables only after independent verification:

| Variable | Contract |
|---|---|
| `GCP_FOUNDATION_APPLY_WIF_PROVIDER` | Bootstrap output `foundation_apply_workload_identity_provider` |
| `GCP_FOUNDATION_SERVICE_ACCOUNT` | Bootstrap output `foundation_service_account` |
| `GCP_TERRAFORM_STATE_BUCKET` | Bootstrap output `state_bucket` |
| `FOUNDATION_APPLY_REVIEW_GATE_CONFIGURED` | Operational interlock for the protected environment |
| `FOUNDATION_PLAN_REVIEW_ACCESS_CONFIGURED` | Operational interlock for the read-only reviewer group |

The apply environment also receives the same non-secret foundation variables
used by the plan workflow. The saved plan is authoritative; the repeated
variables let Terraform load and validate the same module without introducing
a second configuration source.

## Create the immutable plan package

Follow [`foundation-plan.md`](foundation-plan.md). A successful attempt creates
five non-overwritable objects:

```text
foundation-plans/v1/<profile>/<main-sha>/<plan-id>/
  foundation.tfplan
  foundation-plan-summary.json
  foundation-plan-package-public-key.pem
  foundation-plan-package-statement.json
  foundation-plan-package-signature.sigstore.json
```

The signature is uploaded last. Its presence is the completion marker, not
apply authorization. The value-bearing binary plan is never a GitHub
artifact. The packager uses the Cloud Storage JSON media-insert API with a
generation-zero precondition; it does not list or read the destination and
therefore needs only `storage.objects.create` in the managed folder.

## Review the private saved plan

Use a short-lived identity from the configured reviewer group in a clean
checkout at the plan's exact source revision. Copy the statement and
public-key digests from the successful plan workflow, then run:

```bash
scripts/review_foundation_plan_package.sh \
  --state-bucket '<bootstrap-state-bucket>' \
  --source-revision '<exact-main-sha>' \
  --plan-id 'orchestra-foundation-plan-<run>.1' \
  --expected-plan-statement-digest 'sha256:<statement-digest>' \
  --expected-plan-public-key-digest 'sha256:<public-key-digest>' \
  --output-dir 'restricted/foundation-plan-review-<run>'
```

The helper checks the exact five-object inventory and object-size bounds before
download, pins every generation and metageneration, verifies marker ordering,
verifies the detached signature, replays the payload-free summary from the
saved plan, and writes the full plan to
`restricted/foundation-plan-review-<run>/foundation-plan-review.txt`.

Review every create and update, provider, project, IAM binding, network,
firewall, bucket, retention, KMS, GKE, DNS, image, and cost-bearing resource.
Reject all deletes and replacements. Treat the review directory as sensitive:
it can contain values from Terraform state and configuration. Delete it after
the apply receipt and independent observation are retained. The review helper
does not sign an attestation or authorize an apply; the protected-environment
approval is the recorded authorization event.

## Dispatch the exact apply

Use the same source revision as the plan:

```bash
gh workflow run foundation-apply.yml \
  --ref main \
  -f expected_main_sha='<exact-main-sha>' \
  -f plan_id='orchestra-foundation-plan-<plan-run>.1' \
  -f expected_plan_statement_digest='sha256:<statement-digest>' \
  -f plan_kms_key_version='<reviewed-version>' \
  -f expected_plan_public_key_digest='sha256:<public-key-digest>' \
  -f receipt_kms_key_version='<reviewed-version>' \
  -f expected_receipt_public_key_digest='sha256:<public-key-digest>' \
  -f reason='Apply the exact reviewed reference-lab foundation plan'
```

The apply reviewer compares all inputs with the restricted review result before
approving the current run. The workflow then:

1. Revalidates source contracts and the current approval event.
2. Obtains the separate exact-subject apply identity.
3. Lists exactly five plan objects and validates size and completion-marker
   ordering before download.
4. Downloads every object with generation and metageneration preconditions.
5. Re-verifies the detached signature, exact expected digests, 24-hour plan
   age, non-destructive action set, and replayed summary.
6. Records the pre-apply state serial and lineage when state exists.
7. Runs only:

   ```bash
   terraform apply -input=false -lock=true -lock-timeout=300s <exact-saved-plan>
   ```

8. Requires a higher state serial and unchanged lineage.
9. Signs and creates a three-object receipt prefix under
   `foundation-apply-reports/`, with the detached signature uploaded last.

No plan, state, apply log, receipt, or credential is uploaded as a GitHub
artifact.

## Interpret the receipt

The receipt may truthfully state:

- `exactReviewedPlanApplied: true`
- `infrastructureApplied: true`
- `receiptSelfAttested: true`

It must state:

- `independentlyObserved: false`
- `campaignEvidence: false`
- `referenceProfileVerified: false`

The executor signs its own result and has broad storage authority, so the
receipt is execution custody, not independent proof. A different read-only
observer must run the live prerequisite checks and the procedure in
[`foundation-observation.md`](foundation-observation.md) before any downstream
operation treats the infrastructure as available.

## Failure handling

- Never rerun a plan or apply attempt. Generate a new plan package and obtain a
  new approval.
- A partial apply is not success. Preserve the run ID, plan digest, state
  serial, and generic failure code; do not publish a successful receipt.
- Never edit, recreate, or overwrite a plan or receipt prefix. Generation-zero
  preconditions must fail closed.
- Never substitute a newer main revision, KMS version, public key, package
  statement, or Terraform state lineage.
- Do not use the apply identity for dependency mirroring, retention locking, or
  campaign work.
- Any repair uses a new reviewed saved plan. Do not issue an unsaved
  `terraform apply`.
