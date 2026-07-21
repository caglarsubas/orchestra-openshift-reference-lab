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
source-resolved dependency admission contract, gate-controlled product and
dependency GitOps floors, a source-only durable release-validation receiver,
and a source-only synthetic tenant kit. It does not contain a kubeconfig,
provider identity, OpenShift pull secret, live campaign, evidence report, or
completed soak. No declaration has been applied to a target, so the reference
profile is not verified.

Hard gates are recorded in
[`config/prerequisites.example.json`](config/prerequisites.example.json). A
live copy belongs under ignored `restricted/` storage and must contain digests,
not credentials. Provisioning is blocked until every gate is independently
verified.

## Locked topology

- GCP `europe-west1`, zones `b`, `c`, and `d`.
- Separate target and services/evidence projects with private VPC peering.
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
`sha256:ec705bcc9a1e0cee42b152369c95f30012f7f2516c5a3e02076c9d7711cc74b6`.
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

Lab-owned service admission is locked separately in
[`config/lab-services.lock.json`](config/lab-services.lock.json). The durable
release-validation receiver and synthetic tenant kit remain `source-only`:
neither has a release, image, or GitOps reference until publication and live
prerequisites are complete.

## Layout

| Path | Ownership |
|---|---|
| `config/` | Independently locked topology, release set, dependency BOM/admission, and prerequisite gates |
| `infra/terraform/bootstrap/` | Projects, APIs, state custody, KMS, WIF bootstrap |
| `infra/terraform/foundation/` | Private networks, GKE, peering, evidence buckets, bastion, probes |
| `infra/openshift/` | Secret-free OpenShift installer template |
| `gitops/` | Cluster declarations; no generated Secret values |
| `policies/` | Repository and deployment policy inputs |
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
make terraform-fmt
```

`make validate` checks the topology, immutable cross-plane release set,
dependency BOM, and fail-closed dependency admission. It rejects mutable
product tags, missing planes, an unbound runner, changed chart or image
subjects, silently omitted dependencies, populated mirror claims, or any
attempt to mark the dependency plane active.
It also renders the product overlay and proves that the Argo Applications use
the matching source revisions, chart digests, mirrored repositories, image
digests, profile, and control-plane boundary. Only ExternalSecret and
cert-manager references may create credential or certificate objects.
The dependency overlay is checked separately and must contain zero
Applications and Secrets while its deny window is in force.

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
installer rendering. It is not OpenShift deployment evidence. Live evidence
must be produced by the signed certification runner under the v2 contracts in
`prometa-platform` and retained in the configured evidence bucket.
