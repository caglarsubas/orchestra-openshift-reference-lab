# Dependency GitOps source candidate

This directory contains offline Helm values and service-resource plans for the
subset of the dependency plane whose source charts and images are fully
inventoried. It is deliberately not a Kustomize overlay and contains no Argo
CD `Application`, `ApplicationSet`, Kubernetes `Secret`, or deployable YAML.

The controlling lock is
[`config/dependency-gitops-candidate.lock.json`](../../../../config/dependency-gitops-candidate.lock.json),
canonical digest
`sha256:432f3a9c430229b54cc75b9c123b0b9596124bd0b7e104a7522c5475a92484a5`.
It binds the topology, release set, dependency BOM, source admission,
signature observation, risk policy, and empty mirror intake.

## Covered source projections

| Candidate | Chart | Target | Scope |
|---|---|---|---|
| CloudNativePG operator | `cloudnative-pg` `0.29.0` | services GKE | Operator only; two PostgreSQL cluster resources remain planned and blocked |
| ClickHouse operator | `altinity-clickhouse-operator` `0.27.1` | services GKE | Operator and metrics exporter only; ClickHouse/Keeper resources remain planned and blocked |
| JetStream | `nats` `2.14.2` | services GKE | Three-server service values with TLS, account Secret references, regional storage, and PDB |
| Vault | `vault` `0.34.0` | services GKE | Three-member Raft values with TLS references and an unresolved GCP KMS binding |
| External Secrets | `external-secrets` `2.8.0` | OpenShift | Two controller and webhook replicas; cert-manager supplies the webhook certificate |

Every projected image uses the admitted `linux/amd64` source digest under the
unresolved `ORCHESTRA_SERVICES_PROJECT_REQUIRED` bootstrap-registry
placeholder. That placeholder is not a mirror receipt or a pullable image.
The External Secrets built-in certificate controller is disabled, and its
chart creates neither certificate material nor a certificate resource. The
separate cert-manager installation and live PKI binding remain unresolved.

The six entries in `service-overlays.json` describe expected resource kinds
and preserve the exact admission blockers. They are plans, not CRs or rendered
manifests. Ten other dependency services remain unresolved in the controlling
lock, including services GitOps, cert-manager, Valkey/Sentinel, Harbor,
Keycloak, Thanos, probes, model backends, and the synthetic MCP service.

## Offline render review

Download each exact chart package from the repository in the dependency BOM,
verify its package SHA-256 before extraction, and render only into ignored
`restricted/` storage. For example:

```bash
mkdir -p restricted/dependency-gitops-candidate
helm template cloudnative-pg /path/to/cloudnative-pg-0.29.0.tgz \
  --namespace orchestra-postgres \
  --include-crds \
  -f gitops/dependencies/candidates/reference-lab/cloudnative-pg.values.json \
  > restricted/dependency-gitops-candidate/cloudnative-pg.yaml
```

Repeat with the other four exact packages and their values files. Inventory
every rendered workload, hook, init container, sidecar, image, cluster-scoped
resource, and Secret reference. The Altinity CRD hook must remain disabled so
its mutable helper image cannot enter the render. A render is review input
only: do not run `kubectl apply`, `helm install`, or an imperative Argo sync.

## Activation boundary

The active dependency Kustomization must never reference this directory. A
future admitted overlay is a new artifact that requires destination mirror
digests, lab signatures, live Secret/PKI/storage/backup identities,
server-side dry runs against the exact clusters, and two independent
approvals. Until then, the continuous Argo deny window and zero-Application
inventory remain authoritative.
