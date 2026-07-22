# Read-only foundation plan runbook

This workflow previews the foundation against live GCP state. It cannot apply
Terraform, write Terraform state, authorize an apply, satisfy a campaign slot,
or verify the reference profile.

The bootstrap module separates two identities:

- `orchestra-lab-foundation-plan` has read-oriented project permissions and
  read-only access to the foundation state bucket.
- `orchestra-lab-foundation` retains the permissions eventually required for
  apply, but has no GitHub WIF binding in this phase.

## External GitHub environment gate

Before the first run, a repository administrator must configure the
`reference-lab-foundation-plan` environment outside Git:

1. Restrict deployment branches to `main`.
2. Require an independent reviewer and prevent self-review.
3. Add the exact non-secret repository variables listed below.
4. Add `LAB_FOUNDATION_PREREQUISITES_JSON` as an environment secret. It contains
   only the independently reviewed gate projection, never provider credentials.
5. Set `FOUNDATION_PLAN_REVIEW_GATE_CONFIGURED=true` only after another operator
   verifies the protection rules. The variable is an operational interlock,
   not evidence that GitHub protection is configured.

The repository currently has no such environment. Until it exists, the plan
job is deliberately blocked before OIDC authentication.

## Required variables

| Variable | Contract |
|---|---|
| `GCP_WORKLOAD_IDENTITY_PROVIDER` | Bootstrap output `workload_identity_provider` |
| `GCP_FOUNDATION_PLAN_SERVICE_ACCOUNT` | Bootstrap output `foundation_plan_service_account` |
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
     -f reason='Preview the independently reviewed foundation inputs'
   ```

3. The protected-environment reviewer compares the revision, reason, gate
   projection, and requested variables before approving the job.
4. The workflow validates the repository and the independently reviewed
   `foundation` gate before requesting a GCP token.
5. Terraform refreshes live state with `-lock=false`. This avoids granting the
   planner state-write authority; therefore the result is a preview and cannot
   be promoted into an apply artifact.
6. Download and validate only the seven-day
   `foundation-plan-summary-<run>-<attempt>` artifact. It contains resource
   address digests, action classes, immutable bindings, and negative authority
   claims. Terraform's value-bearing plan output is withheld from Actions logs;
   its log, plan JSON, and binary are removed and never uploaded.

## Review and failure handling

- Reject an unexpected create, update, delete, or replacement before any
  apply work begins.
- Treat a state-read, API-read, environment, WIF, or prerequisite failure as a
  blocker. Do not broaden planner roles during the run.
- Never rerun against a different main revision using the previous reason or
  summary.
- A successful preview does not authorize infrastructure changes. A future
  apply lane must use a separately federated executor, acquire the state lock,
  bind an exact saved plan and digest, require independent approval, and emit a
  distinct non-campaign execution report.
