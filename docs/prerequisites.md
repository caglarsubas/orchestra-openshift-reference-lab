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
| DNS | Exact public delegation for `ocp-lab.prometa.ai` |
| WIF | GitHub/environment subject restriction, expected binding, and no user-managed key |
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
`sha256:70270422a283f5dfe623025d82e00e7deb5bd2e8980a5ac78f609e5a887f2e97`.
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
export ORCHESTRA_CERTIFICATION_RUNNER_IMAGE='ghcr.io/caglarsubas/agent-hook-v2/orchestra-certification-runner-ubi@sha256:dfe1d808addf2808ea71f63b1297d08db58f8418c3afa3c09eed74b7e701aaa8'
export ORCHESTRA_CERTIFICATION_RUNNER_TOOLCHAIN_DIGEST='sha256:b6e3a4e11f5e0a5421c5007c132fba3bdd3b72ad620ed07f813b8c7677b0b34e'

python3 scripts/collect_prerequisite_observation.py \
  --observation-id orchestra-prerequisite-observation-live.1 \
  --actor-identity-digest 'sha256:<short-lived-collector-identity-digest>' \
  --execution-mode live \
  --red-hat-entitlement-statement restricted/red-hat-entitlement.json \
  --pull-secret restricted/pull-secret.json \
  --installer-binary restricted/openshift-install \
  --installer-digest 'sha256:<officially-verified-binary-digest>' \
  --target-project-id '<dedicated-target-project>' \
  --services-project-id '<dedicated-services-project>' \
  --dns-managed-zone '<managed-zone-resource-name>' \
  --output restricted/prerequisite-observation.json
```

The collector reads the pull secret only to validate required registry entries;
it emits only a digest. GCP and DNS commands are read-only, and their raw output
is reduced to policy facts before hashing. Runner verification uses the exact
Sigstore publisher identity. Command failures produce typed blocker codes,
the exact workflow SHA/ref/repository/trigger, and never raw provider errors in
the report.

The Red Hat input is a payload-free external statement with exact product,
OpenShift `4.20.27`, `linux/amd64`, active/expiry timestamps, and issuer/account
identity digests. It is still subject to independent review; the collector does
not treat the statement's presence as entitlement authority.

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
