# Immutable foundation plan runbook

This workflow previews the foundation against live GCP state. It cannot apply
Terraform, write Terraform state, authorize an apply, satisfy a campaign slot,
or verify the reference profile. It may publish a signed saved-plan package
for the separately reviewed apply lane.

The bootstrap module separates four boundaries:

- `orchestra-lab-foundation-plan` has read-oriented project permissions and
  read-only access to the foundation state bucket.
- `orchestra-plan-packager` can sign a package statement and create, but not
  read or delete, objects under `foundation-plans/`. It has no state or project
  role.
- Approved `group:` reviewers can read only the private plan-package managed
  folder for full value-bearing review.
- `orchestra-lab-foundation` retains the permissions eventually required for
  apply and is federated only through the separate apply workflow and
  environment.

## External GitHub environment gate

Before the first run, a repository administrator must configure the
`reference-lab-foundation-plan` environment outside Git:

1. Keep the repository private and use a GitHub plan that supports required
   reviewers for private repositories. GitHub's
   [environment availability matrix](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)
   currently reserves that control for Enterprise; making the lab repository
   public is not an acceptable workaround.
2. Add at least one non-owner collaborator with read access, restrict the exact
   deployment branch to `main`, require that collaborator as reviewer, and
   prevent self-review. Disable administrator bypass in the environment UI.
3. Add the exact non-secret repository variables listed below.
4. Add `LAB_FOUNDATION_PREREQUISITES_JSON` as an environment secret. It contains
   only the independently reviewed gate projection, never provider credentials.
5. Set `FOUNDATION_PLAN_REVIEW_GATE_CONFIGURED=true` only after another operator
   verifies the protection rules. The variable is an operational interlock,
   not evidence that GitHub protection is configured.

The repository currently has no such environment and only its owner is a
collaborator. Until the account and reviewer prerequisites exist, the plan job
is deliberately blocked before OIDC authentication.

The workflow uses its ephemeral `GITHUB_TOKEN` with Actions-read permission to
run `scripts/github_environment_contract.py`. The verifier reads the repository,
environment, deployment-branch, and current workflow-run approval APIs and
emits only identity digests and counts. It rejects owner review, self-review,
review by the triggering actor, unconfigured approvers, rejected or ambiguous
review history, duplicate reviewers, missing required-reviewer protection, and
any branch pattern other than exact `main`. It accepts only workflow attempt
one because GitHub's review-history response does not bind events to rerun
attempts. GitHub documents the
[approval-history endpoint](https://docs.github.com/en/rest/actions/workflow-runs#get-the-review-history-for-a-workflow-run)
as requiring Actions-read permission.

The read API does not expose the environment's administrator-bypass toggle.
Disabling bypass is therefore a separately reviewed UI precondition. The
current-run approval check still fails when no matching approval event exists;
it must not be described as an API attestation of that toggle.

## Required variables

| Variable | Contract |
|---|---|
| `GCP_WORKLOAD_IDENTITY_PROVIDER` | Bootstrap output `workload_identity_provider` |
| `GCP_FOUNDATION_PLAN_SERVICE_ACCOUNT` | Bootstrap output `foundation_plan_service_account` |
| `GCP_FOUNDATION_PLAN_PACKAGER_SERVICE_ACCOUNT` | Bootstrap output `foundation_plan_packager_service_account` |
| `GCP_TERRAFORM_STATE_BUCKET` | Bootstrap output `state_bucket` |
| `GCP_TARGET_PROJECT_ID` | Exact dedicated OpenShift project |
| `GCP_SERVICES_PROJECT_ID` | Exact services/evidence project |
| `GCP_SIGNED_EVIDENCE_BUCKET` | Globally unique signed-evidence bucket |
| `GCP_RAW_EVIDENCE_BUCKET` | Globally unique restricted raw-artifact bucket |
| `GCP_BASTION_SOURCE_IMAGE` | Immutable GCE image self-link |
| `GCP_PROBE_SOURCE_IMAGE` | Immutable GCE image self-link |
| `ORCHESTRA_PROBE_CONTAINER_IMAGE` | Immutable image reference with `@sha256` |
| `GCP_APPROVED_EGRESS_CIDRS_JSON` | Reviewed JSON array without `0.0.0.0/0` |
| `GCP_IAP_OPERATOR_MEMBERS_JSON` | Reviewed JSON array; defaults to empty |
| `GCP_GKE_RELEASE_CHANNEL` | `STABLE` or `EXTENDED`; defaults to `STABLE` |

## Identity checks

The WIF provider accepts a token only when all locked claims match:

- Private repository ID `1307302690` and owner ID `37515097`.
- Repository `caglarsubas/orchestra-openshift-reference-lab`.
- `refs/heads/main` and `workflow_dispatch`.
- Workflow ref `.github/workflows/foundation-plan.yml@refs/heads/main`.
- Environment `reference-lab-foundation-plan`.
- `google.subject` exactly
  `github:1307302690:reference-lab-foundation-plan`, with only that single
  principal allowed to impersonate the read-only planner.
- At least one non-owner `User` reviewer, `prevent_self_review=true`, and one
  exact custom branch policy named `main`.

Run the live prerequisite collector and obtain independent review of the WIF
gate after bootstrap changes. A workflow file or Terraform plan is not proof
that the deployed provider has these restrictions.

## Generate a preview

1. Confirm the reviewed main revision and current `foundation` prerequisite
   projection.
2. Dispatch the workflow with an exact revision and bounded reason:

   ```bash
   revision="$(git rev-parse origin/main)"
   gh workflow run foundation-plan.yml \
     --ref main \
     -f expected_main_sha="$revision" \
     -f reason='Preview the independently reviewed foundation inputs' \
     -f plan_kms_key_version='<reviewed-version>' \
     -f expected_plan_public_key_digest='sha256:<public-key-digest>'
   ```

3. The protected-environment reviewer compares the revision, reason, gate
   projection, and requested variables before approving the job.
4. The workflow re-reads and validates the GitHub protection rules and binds a
   single approved event for this run to a configured non-owner reviewer who
   did not trigger the run. It then validates the repository and independently
   reviewed `foundation` gate before requesting a GCP token.
5. Terraform refreshes live state with `-lock=false`. The planner cannot lock
   or write state. A second identity then signs the package statement and
   creates exactly five non-overwritable objects under the unique
   `foundation-plans/` prefix. The detached signature is uploaded last.
6. Download and validate the seven-day
   `foundation-plan-summary-<run>-<attempt>` artifact. It contains resource
   address digests, action classes, immutable bindings, and negative authority
   claims. Terraform's value-bearing plan output is withheld from Actions logs;
   its log, plan JSON, and binary are removed from the runner and never
   uploaded to GitHub.
7. The summary is not sufficient for full review. Follow
   [`foundation-apply.md`](foundation-apply.md) to generation-pin, verify, and
   render the private saved plan under ignored `restricted/` storage before
   approving an apply.

## Review and failure handling

- Reject an unexpected create, update, delete, or replacement before any
  apply work begins.
- Treat a state-read, API-read, environment, WIF, or prerequisite failure as a
  blocker. Do not broaden planner roles during the run.
- Do not set the environment interlock when GitHub cannot return the required
  reviewer and exact branch-policy state.
- Do not continue when the current-run approval is absent, rejected, duplicated,
  from the triggering actor, or from an identity outside the configured set.
- Never rerun a failed or cancelled foundation-plan workflow. Start a new
  `workflow_dispatch` so it receives a new run ID and independent review.
- Never rerun against a different main revision using the previous reason or
  summary.
- A successful package does not authorize infrastructure changes. Only the
  separate apply workflow may consume it, after private full-plan review and a
  new current-run approval. Its signed receipt is self-attested and remains
  non-campaign evidence.
