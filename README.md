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

This repository contains the source-controlled foundation only. It does not
contain a kubeconfig, provider identity, OpenShift pull secret, live campaign,
evidence report, or completed soak. The reference profile is therefore not
verified yet.

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

The full machine-readable contract is
[`config/lab.lock.json`](config/lab.lock.json).

## Layout

| Path | Ownership |
|---|---|
| `config/` | Locked topology and prerequisite gates |
| `infra/terraform/bootstrap/` | Projects, APIs, state custody, KMS, WIF bootstrap |
| `infra/terraform/foundation/` | Private networks, GKE, peering, evidence buckets, bastion, probes |
| `infra/openshift/` | Secret-free OpenShift installer template |
| `gitops/` | Cluster declarations; no generated Secret values |
| `policies/` | Repository and deployment policy inputs |
| `scripts/` | Local/CI validation and rendering tools |
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
