# Orchestra OpenShift Reference Lab

Private infrastructure and GitOps source for the exact
`orchestra-ocp-4.20-amd64-v1` vendor reference lab.

The lab is designed to produce this bounded result after a real campaign:

```json
{
  "referenceProfileVerified": true,
  "customerCertified": false,
  "redHatCertified": false,
  "contractualSla": false
}
```

It does not put Orchestra in a tenant's synchronous production request path,
does not grant Orchestra deployment authority over customer workloads, and
does not enable platform production tool execution.

## Current state

This repository contains the source-controlled infrastructure foundation,
immutable cross-plane release intake, immutable dependency source catalog,
immutable platform-owned certification contract intake,
source-resolved dependency admission contract, bounded source-signature
observation, locked unsigned-source risk policy, empty signature-exception and
mirror-intake contracts, a digest-bound source-only dependency GitOps
candidate, an atomic signed-runner scan collector and detached
attestation verifier, a stage-aware prerequisite observation policy and
payload-free read-only collector, gate-controlled product and dependency
GitOps floors, an environment-bound read-only Terraform planning lane, a
payload-free GitHub environment/current-run approval verifier, a source-only
durable release-validation receiver, and a source-only synthetic tenant kit. It
does not contain a kubeconfig, provider
identity, OpenShift pull secret, live prerequisite observation, independent
prerequisite review, live risk scan, approved source exception, live campaign,
campaign evidence report, or completed soak. No declaration has been applied
to a target, so the reference profile is not verified.

Hard gates are recorded in
[`config/prerequisites.example.json`](config/prerequisites.example.json). A
live copy belongs under ignored `restricted/` storage and must contain digests,
not credentials. Provisioning is blocked until every gate is independently
verified. Machine observation is separately governed by
[`config/prerequisite-observation-policy.lock.json`](config/prerequisite-observation-policy.lock.json):
diagnostic output is always `fixture/simulated`, while live output must bind the
published certification runner. Neither output can verify a gate or authorize
provisioning.

## Locked topology

- GCP `europe-west1`, zones `b`, `c`, and `d`.
- Separate target and services/evidence projects with private VPC peering.
- Services-project public delegation zone plus one-way private DNS peering to
  the installer-owned OpenShift namespace.
- Private self-managed OpenShift `4.20.27`, OVN-Kubernetes, three
  `n2-standard-4` control-plane nodes, and three `n2-standard-8` workers.
- Private regional GKE dependency plane with three non-preemptible
  `n2-standard-8` nodes.
- Private API/routes, IAP administration, internal image mirror, default-deny
  workloads, and allowlisted egress.
- CMEK evidence custody, 400-day locked signed-report retention, and 90-day
  restricted raw-artifact retention.
- GitOps/Argo CD owns rollout. Orchestra emits recommendations only.

The full machine-readable topology contract is
[`config/lab.lock.json`](config/lab.lock.json). It deliberately contains no
product versions. The independently digested
[`config/cross-plane-release-set.lock.json`](config/cross-plane-release-set.lock.json)
binds the platform, runtime, model plane, charts, and certification runner.
Every campaign binds both digests so an artifact update cannot masquerade as a
topology change or combine evidence from different release sets.

The current canonical release-set digest is
`sha256:4f571fade2a1566a53d797c82561f30292734fcfcc75b23667dc08007ee8b6fe`.
It records published artifacts only; it is not deployment, drill, soak, or
verification evidence.

The independently locked dependency BOM digest is
`sha256:fabec47064381d067ca759ba99c47470cc66628ecaacd2e0521f50bb29aad5dc`.
It locks eleven upstream chart packages and accounts for every declared
dependency, while keeping activation blocked until image-level mirror intake,
Secret references, and unresolved provider decisions are closed.

The dependency admission digest is
`sha256:fc1f22817a5959e18d3f4493f199bda61b30cea441929ee321b531402e846def`.
It locks eleven exact source image indexes and linux/amd64 manifests, the
Barman Cloud release manifest, and service contracts for PostgreSQL,
ClickHouse/Keeper, JetStream, Vault, and External Secrets. Every source
signature, destination mirror, lab signature, live identity, backup target,
dry run, and approval remains blocked. Source resolution is not mirror
admission.

The bounded source-verification digest is
`sha256:cbfaa95d09e7a9ca1812028ba13f21c40846c3c91b32424d1e834eab6ab69f89`.
It records exact keyless verification for three subjects and explicit
signature absence for eight subjects during a seven-day developer-workstation
observation. The latter require reviewed exceptions, and all eleven require a
signed certification-runner replay before source admission. Its empty mirror
intake digest is
`sha256:fe357261b272cd8fb4d6917e55453b613967fe5557616550c49591d035a5fc21`.
No destination, receipt, lab signature, pull proof, or approval is populated.

The unsigned-source risk-policy digest is
`sha256:b7ea9ab33854715e24eae2cb90fdc8ca8c8058df55f9b038f5856cb4a5c513c4`.
It requires the release-set-bound signed runner, exact Trivy and Syft versions,
frozen vulnerability databases, Cloud KMS detached collection evidence, and
SPDX inventory. Its preflight-only lane verifies the exact release, runner,
toolchain, scanner versions, source window, and an ephemeral Cloud KMS signing
round trip before downloading scanner databases; it publishes no collection
artifact and grants no authorization. The policy blocks critical, high, and
unknown-severity findings, requires human licence and risk review, and enforces
two independent approval roles with a maximum 30-day exception lifetime. The
empty signature-exception intake digest is
`sha256:2231cf7c2f2dce5c1b35f402cdd193ce4268e1726f7ab3b27f3fd23b7bb9b70f`.
It contains all eight unsigned subjects but zero evidence bundles and zero
approvals. Even a fully approved exception set cannot authorize source
admission or mirroring without the separate signed-runner source replay and
admission aggregate.

The dependency-risk preflight authority digest is
`sha256:746304a45ba15385d629ee3ef5c7618e36980524ca4f73e024007e958925b679`.
It declares a separate exact-main GitHub WIF provider, a collector service
account with no project, evidence-bucket, or artifact-mirror role, and a
dedicated `EC_SIGN_P256_SHA256` Cloud KMS key whose only collector grant is
key-level `roles/cloudkms.signerVerifier`. The protected workflow obtains a
short-lived GitHub App token for the exact platform release and package,
rechecks the current environment approval, and invokes only the collector's
no-evidence `--preflight-only` path. No Terraform has been applied and no live
identity, KMS round trip, preflight, collection, admission, mirror, activation,
campaign, or verification state is claimed.

The source-only dependency GitOps candidate digest is
`sha256:6f7a051f0dcf3c46ecbde68efb5e21369d42035ec72cca2f334c652c37600790`.
It projects five exact chart/image contracts into offline values for
CloudNativePG, the ClickHouse operator, JetStream, Vault, and External Secrets,
plus six blocked service-resource plans. CI derives the chart and image
bindings from the existing BOM and admission contracts, checks the values
semantically, and proves the candidate is absent from the active
Kustomization. It contains no Argo Application or destination mirror reference
and cannot be applied. Ten services, including cert-manager and
Valkey/Sentinel, remain unresolved.

Lab-owned service admission is locked separately in
[`config/lab-services.lock.json`](config/lab-services.lock.json). The durable
release-validation receiver and synthetic tenant kit remain `source-only`:
neither has a release, image, or GitOps reference until publication and live
prerequisites are complete.

## Layout

| Path | Ownership |
|---|---|
| `config/` | Independently locked topology, release set, certification contract intake, dependency BOM/admission/GitOps candidate, source observation, risk policy, empty exception/mirror intakes, prerequisite gates, and prerequisite observation policy |
| `contracts/platform/` | Exact platform-owned policy, schema bundle, and fixture bytes vendored from the pinned release revision; not campaign evidence |
| `infra/terraform/bootstrap/` | Projects, APIs, state custody, KMS, WIF bootstrap |
| `infra/terraform/foundation/` | Private networks, GKE, VPC/DNS peering, public delegation zone, evidence buckets, bastion, probes |
| `infra/openshift/` | Secret-free OpenShift installer template |
| `gitops/` | Active cluster declarations plus a non-activatable dependency values candidate; no generated Secret values |
| `policies/` | Repository and deployment policy inputs |
| `schemas/` | Strict additive JSON contracts for prerequisite observations, signed collection statements, scan manifests, risk evidence, and signature exceptions |
| `scripts/` | Local/CI validation and rendering tools |
| `services/` | Lab-owned synthetic and GitOps integration services; none are platform runtime authority |
| `docs/runbooks/` | Human-controlled operational procedures |

The current proof-state matrix is maintained in
[`docs/implementation-status.md`](docs/implementation-status.md); the security
boundaries and residual risks are in
[`docs/threat-model.md`](docs/threat-model.md).

## Safe local checks

```bash
make validate
make test
make verify-platform-contract-source PLATFORM_REPOSITORY=/absolute/path/to/agent-hook-v2
make verify-dependency-sources
make terraform-fmt
```

`make validate` checks the topology, immutable cross-plane release set,
platform-owned certification contract intake, dependency BOM, fail-closed
dependency admission, bounded signature observation, unsigned-source risk
policy, empty exception intake, empty mirror intake, and source-only dependency
GitOps candidate, plus the staged
prerequisite observation policy. It rejects
mutable product tags, missing planes, an unbound runner, changed chart or image
subjects, wildcard signing identities, silently
omitted dependencies, populated approvals, self-review, stale evidence,
overlong exceptions, populated mirror claims, or any attempt to mark the
dependency plane active.
The dependency candidate validator also rejects destination references,
mutable image tags, values drift, path escapes, missing blocked services,
unsafe chart features, generated manifests in the candidate tree, or a
reference from the active Kustomization.
It also renders the product overlay and proves that the Argo Applications use
the matching source revisions, chart digests, mirrored repositories, image
digests, profile, and control-plane boundary. Only ExternalSecret and
cert-manager references may create credential or certificate objects.
The dependency overlay is checked separately and must contain zero
Applications and Secrets while its deny window is in force.

The contract-intake check is self-contained and safe for CI. The separate
`verify-platform-contract-source` target requires an authorized platform
checkout and replays bytes from the exact pinned Git revision; it does not use
working-tree contents. Neither check creates or approves a campaign.

`make verify-dependency-sources` is networked and time-bounded. It re-resolves
the locked image/manifests and reproduces the signature observation, but it
does not approve exceptions or authorize mirroring.

Terraform validation downloads pinned providers but uses no credentials and
does not contact a target project:

```bash
make terraform-validate
```

Render an installer configuration only into the ignored `install-dir/` path:

```bash
python3 scripts/render_install_config.py \
  --values restricted/install-values.json \
  --output install-dir/install-config.yaml
```

The renderer refuses to overwrite files, validates exact topology values, and
does not accept a pull secret in its values file. Pull secret and SSH public
key injection remain an operator step immediately before installer execution.

## Delivery boundary

Repository CI proves syntax, topology invariants, strict gate shapes,
secret-exclusion rules, Terraform formatting/validation, and deterministic
installer rendering. The vendored certification inputs prove a pinned contract
intake only. They are not OpenShift deployment or campaign evidence. Live
evidence must be produced by the signed certification runner under the v2
contracts in `prometa-platform` and retained in the configured evidence
bucket.
