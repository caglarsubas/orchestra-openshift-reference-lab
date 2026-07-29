# Provisioning gates and observations

Provisioning is fail-closed. A human-readable assertion, a successful command,
or a file path is not verified evidence. The workflow deliberately separates:

1. A payload-free read-only machine observation.
2. Independent review of the underlying restricted material.
3. A verified gate projection in `restricted/prerequisites.json`.

The collector cannot perform steps 2 or 3. Its contract always records zero
verified gates, `provisioningReady: false`, and `campaignEvidence: false`.

| Gate | Required proof |
|---|---|
| Red Hat entitlement | Active subscription/entitlement verification digest |
| Pull secret | Presence and access check digest; never the secret itself |
| Installer | Exact `4.20.27` linux/amd64 binary digest and official checksum result |
| GCP billing/quotas | Approved quotas for six OCP nodes, GKE, PD, LB, DNS, KMS, and probes |
| Target project | Distinct active project, billing, labels, and required APIs |
| Services/evidence project | Distinct active project, billing, labels, and required APIs |
| DNS | Exact public delegation for services-project zone `orchestra-ocp-lab-public` at `ocp-lab.planeon.ai.` |
| WIF and operator GitHub controls | Machine-verified independent GitHub environment protection plus exact private repository/owner IDs, separate plan/apply workflow restrictions, exact planner/packager/executor bindings, no user-managed key, all six protected environments, and the exact read-only platform-release GitHub App installation; the post-apply observer verifies its additional WIF/IAM boundary separately |
| Runner | Published signed UBI9 linux/amd64 image and toolchain digest |
| Release set | Canonical cross-plane release set including runner subject |

## Stage order

The gates are stage-aware because Terraform bootstrap creates the two projects
and WIF resources that later stages verify:

| Stage | Required gates |
|---|---|
| `bootstrap` | Entitlement, pull secret, installer, runner, and release set |
| `foundation` | Bootstrap gates plus billing/quotas, target project, services/evidence project, and WIF |
| `openshift-install` | Foundation gates plus exact public DNS delegation |
| `all` | All ten gates; required before the frozen campaign |

Do not require project or WIF evidence before the bootstrap operation that
creates those resources. Conversely, never treat a successful Terraform apply
as independent verification of its own outputs.

## Observation collector

The locked policy is
`config/prerequisite-observation-policy.lock.json`; its canonical digest is
`sha256:e5a454a6bbdff84b184ea56ee5b67cb35898f6736e0c9045a2dc4cfb8dcb7561`.
It requires a maximum 30-minute read-only collection window and expires an
observation after 24 hours.

A local diagnostic is useful for enumerating blockers, but is permanently
classified as `fixture/simulated`:

```bash
python3 scripts/collect_prerequisite_observation.py \
  --observation-id orchestra-prerequisite-observation-local.1 \
  --actor-identity-digest 'sha256:<operator-identity-digest>' \
  --execution-mode simulated \
  --output artifacts/prerequisite-observation.json

python3 scripts/validate_prerequisite_observation.py \
  --observation artifacts/prerequisite-observation.json
```

A live run must execute inside the exact certification-runner image and expose
both immutable runner bindings to the process. Before collecting, the CLI
requires Linux AMD64, the exact in-image toolchain-lock digest, all read-only
probe commands, and a passing `orchestra-certification self-test`:

```bash
export ORCHESTRA_CERTIFICATION_RUNNER_IMAGE='ghcr.io/caglarsubas/agent-hook-v2/orchestra-certification-runner-ubi@sha256:0009128ccbb53b9e376f74e7a6110ab6d2316be392be825d938705b88488f061'
export ORCHESTRA_CERTIFICATION_RUNNER_TOOLCHAIN_DIGEST='sha256:7dc16baeb7c7a5dcfb0fb360f748b190d0e042f1bd9cf5843e1b75e3546a9593'

python3 scripts/collect_prerequisite_observation.py \
  --observation-id orchestra-prerequisite-observation-live.1 \
  --actor-identity-digest 'sha256:<short-lived-collector-identity-digest>' \
  --execution-mode live \
  --red-hat-entitlement-statement restricted/red-hat-entitlement.json \
  --pull-secret restricted/pull-secret.json \
  --installer-binary restricted/openshift-install \
  --installer-digest 'sha256:<officially-verified-binary-digest>' \
  --github-token-file restricted/github-actions-read-token \
  --target-project-id '<dedicated-target-project>' \
  --services-project-id '<dedicated-services-project>' \
  --dns-managed-zone 'orchestra-ocp-lab-public' \
  --output restricted/prerequisite-observation.json
```

The collector reads the pull secret only to validate required registry entries;
it emits only a digest. The GitHub token must be a mode-`0600`, short-lived
GitHub App or fine-grained token with Actions-read permission; it is never
embedded in evidence. GCP, GitHub, and DNS requests are read-only, and their raw
output is reduced to policy facts before hashing. Runner verification uses the
exact Sigstore publisher identity. Command failures produce typed blocker codes
and never raw provider errors in the report.

The public zone is an explicit ownership/delegation gate, not the private
cluster record authority. OpenShift `publish: Internal` creates and owns the
private cluster namespace in the target VPC. The foundation's services-plane
peering zone only resolves that namespace; it does not create or modify
OpenShift records. See `docs/runbooks/dns-delegation.md` for the apply and
independent verification sequence.

The foundation WIF gate has two required observations. The GitHub observation
requires the exact private repository IDs, environment, non-owner reviewer,
self-review prevention, and exact `main` deployment policy. The GCP observation
requires both exact workflow/ref/event conditions, provider-prefixed numeric
repository/environment subject mappings, single-subject planner and packager
bindings for the plan workflow, the single-subject executor binding for the
separate apply workflow, and absence of user-managed keys on all three service
accounts. Managed-folder reviewer/package IAM and KMS key-level roles are
separate foundation-apply checks; WIF success alone does not prove them.

The later `foundation-observation` provider is intentionally outside this
pre-bootstrap WIF gate. Its protected workflow performs a stronger post-apply
check of its exact provider, impersonation binding, user-managed keys, project
and ancestor roles, metadata-only custom role, managed-folder grants, and KMS
grants before it observes provider state. See
`docs/runbooks/foundation-observation.md`.

The standalone collector proves the environment configuration only because it
is not executing inside an approved workflow run. The foundation-plan workflow
adds a current-run check against GitHub's approval-history API and requires one
approved event from a configured non-owner reviewer distinct from the workflow
initiator. Neither path claims to attest the administrator-bypass UI setting,
which remains an independently reviewed Enterprise-environment precondition.

The aggregate operator-control-plane collector in
`docs/runbooks/operator-control-plane-readiness.md` separately checks all six
environment contracts and the complete GitHub App installation repository set.
It mints and revokes an unrestricted installation token so a narrowed token
cannot hide a broader installation. Its payload-free report expires after one
hour and still requires independent review before any prerequisite gate changes
to `verified`.

The Red Hat input is a payload-free external statement with exact product,
OpenShift `4.20.27`, `linux/amd64`, active/expiry timestamps, and issuer/account
identity digests. It is still subject to independent review; the collector does
not treat the statement's presence as entitlement authority.

Build that statement from restricted source material without writing account
identity or issuer content into the output:

```bash
python3 scripts/build_red_hat_entitlement_statement.py \
  --account-identity-file restricted/red-hat-account-identity.txt \
  --issuer-evidence restricted/red-hat-trial-confirmation.png \
  --observed-at '<exact UTC observation time>' \
  --expires-at '<exact UTC expiry from Red Hat>' \
  --output restricted/red-hat-entitlement.json
```

The account identity input must be a non-symlinked mode-`0600` regular file.
The exact expiry must come from Red Hat's UI or confirmation email; do not infer
it from a relative “days left” display.

## Independent gate projection

Copy `config/prerequisites.example.json` to ignored
`restricted/prerequisites.json`. Change a gate to `verified` only after an
independent reviewer has checked the restricted source material and the live
observation. Populate the evidence digest, UTC verification time, and
short-lived reviewer identity digest. At least two independent reviewer
identities are required across every admitted stage.

Validate only the stage about to execute:

```bash
python3 scripts/validate_repository.py \
  --prerequisites restricted/prerequisites.json \
  --require-ready \
  --readiness-stage bootstrap
```

Repeat with `foundation`, `openshift-install`, and finally `all` as the lab
advances. This validates admission to the named operation; it does not perform
the operation and does not satisfy a certification evidence slot.
