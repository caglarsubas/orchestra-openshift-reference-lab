# Operator control-plane readiness

## Purpose and boundary

This procedure observes the external GitHub controls required before bootstrap
and dependency-risk execution:

- all six protected workflow environments;
- their exact `main` branch policy, independent reviewer configuration, and
  self-review prevention;
- the dedicated GitHub App identity, complete installation set, read-only
  permissions, event subscriptions, and complete repository set.

The locked policy is
`config/operator-control-plane-readiness.lock.json`; its canonical digest is
`sha256:c344bba86571ab5cf347c8c70e0745c6c22afd7cc9fd930f91f7cf5b15db0ec4`.
The strict payload-free report schema is
`schemas/operator-control-plane-readiness-v1.schema.json`.

A passing observation is not provisioning admission. It remains valid for at
most 60 minutes, requires independent review, and always records
`provisioningReady=false`, `campaignEvidence=false`, and
`referenceProfileVerified=false`.

## Configure the six protected environments

The six environment shells are not sufficient. Each exact contract requires
one non-owner `User` reviewer, self-review prevention, only the `main`
deployment branch, and only its workflow-declared environment Secret names.
The bootstrap reads names only; it never reads, creates, rotates, or deletes
Secret values. The supported contract names are:

- `foundation-plan`
- `foundation-apply`
- `foundation-observation`
- `dependency-risk-preflight`
- `dependency-risk-collection`
- `dependency-risk-custody-verification`

First add the intended reviewer as a repository collaborator with at least read
access. Use a short-lived repository-administration token from a mode-`0600`
file under ignored `restricted/` storage. Create a separate, payload-free plan
for each contract:

```bash
contract='foundation-plan'

make plan-reference-lab-environment \
  CONTRACT="$contract" \
  TOKEN_FILE=restricted/github-environment-admin-token \
  REVIEWER_LOGIN='<non-owner-reviewer>' \
  OUTPUT="restricted/${contract}-environment-plan.json"
```

The planner rejects the repository owner, a missing collaborator, unknown or
malformed environment Secret names, repository identity drift, unsupported
contracts, and non-private or non-`main` repository state before mutation. It
hashes the reviewer identity and binds the operator-readiness policy, exact
authority-owned environment contract, and a digest of the allowed Secret-name
inventory. The output is create-only and mode `0600`.

Review the status, current and desired state digests, controls, and operations.
Apply only the exact reviewed digest, using the same contract and reviewer:

```bash
make apply-reference-lab-environment \
  CONTRACT="$contract" \
  TOKEN_FILE=restricted/github-environment-admin-token \
  REVIEWER_LOGIN='<non-owner-reviewer>' \
  PLAN="restricted/${contract}-environment-plan.json" \
  EXPECTED_PLAN_DIGEST='sha256:<reviewed-plan-digest>'

make verify-reference-lab-environment \
  CONTRACT="$contract" \
  TOKEN_FILE=restricted/github-environment-admin-token
```

Apply recomputes the full plan immediately before mutation. A changed reviewer
permission, environment, branch policy, Secret-name inventory, contract, or
plan digest stops the operation. It configures only the required-reviewer rule,
self-review prevention, and exact `main` branch policy; Secret values remain a
separate operator responsibility. It cannot manage Secret values, OIDC, cloud
IAM, registry access, deployments, or repository settings. Repeat the reviewed
sequence independently for all six contracts.

GitHub makes required reviewers for private repositories plan-dependent. If an
environment update reports
`github_environment_required_reviewers_unavailable`, stop. Do not weaken the
environment, make the repository public, substitute the owner, or dispatch an
unreviewed workflow.

## Configure the GitHub App

Create the GitHub App with these exact properties:

1. Owner: the `caglarsubas` account.
2. Slug: `orchestra-reference-lab-release-reader`.
3. Repository access: selected repositories, with only
   `caglarsubas/agent-hook-v2` selected.
4. Repository permissions: `Contents: read-only` and `Packages: read-only`.
   The mandatory metadata permission may also appear as read-only.
5. Event subscriptions: none.
6. Webhook: inactive; this App only reads the pinned platform release and
   certification-runner package.

Store the App ID, installation ID, and private key in the protected GitHub
environments as:

- `DEPENDENCY_RISK_GITHUB_APP_ID`;
- `DEPENDENCY_RISK_GITHUB_APP_INSTALLATION_ID`;
- `DEPENDENCY_RISK_GITHUB_APP_PRIVATE_KEY`.

The three dependency-risk workflows first enumerate every installation of the
App and require exactly the locked installation. They then mint a
full-installation token before any release download, enumerate that
installation's actual repository set, and revoke the token. A separately
repository-narrowed token is used for release and package reads. A second App
installation, a second repository, a write permission, an event subscription,
a suspension, or failed token revocation stops the workflow.

## Collect an aggregate observation

Use a short-lived GitHub token that can read the lab repository's environment
configuration. Keep both token and App private key in mode-`0600` files under
ignored `restricted/` storage. The App verifier creates its own unrestricted
installation token by App JWT, so a repository-narrowed token cannot conceal a
broader installation.

```bash
umask 077

python3 scripts/operator_control_plane_readiness.py collect \
  --observation-id "operator-readiness.$(date -u +%Y%m%d%H%M%S)" \
  --repository-revision "$(git rev-parse HEAD)" \
  --environment-token-file restricted/github-environment-read-token \
  --app-private-key-file restricted/github-app-private-key.pem \
  --app-id '<github-app-id>' \
  --installation-id '<github-app-installation-id>' \
  --output restricted/operator-control-plane-readiness.json
```

The report retains only identity, permission, repository-set, reviewer, and
branch-policy digests. It never contains login names, numeric App or
installation IDs, tokens, private keys, API payloads, or comments. The
installation-set count is retained so independent review can confirm that the
App has no second account boundary. The collector sets its own UTC observation
time; callers cannot extend the validity window. Output is mode `0600` and
create-only.

Verify the report during its one-hour window:

```bash
make verify-operator-control-plane-readiness \
  REPORT=restricted/operator-control-plane-readiness.json \
  ASSESSED_AT="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
```

An independent reviewer checks the live GitHub settings, the administrator
bypass setting that GitHub's read API does not expose, the report digest, and
the source revision. Only then may the relevant facts be projected into
`restricted/prerequisites.json`.

## Failure handling

- Do not run an environment apply until the non-owner reviewer is an active
  repository collaborator and the plan digest has been independently reviewed.
- Treat a partially completed six-environment rollout as not ready. Re-plan
  each remaining or changed environment and require all six to verify before
  collecting the aggregate observation.
- Do not narrow the App installation token passed to this verifier. The
  verifier itself creates the token without repository filters and revokes it.
- Do not add a second repository or write permission to make a workflow pass.
- Rotate the App private key after suspected exposure and rerun the observation.
- Treat revocation failure as an incident; the verifier emits no passing
  observation.
- A changed environment, reviewer set, App installation, repository set, or
  permission set invalidates the prior report.
- Never place the private key, environment token, raw API response, or generated
  report in Git or GitHub artifacts.
