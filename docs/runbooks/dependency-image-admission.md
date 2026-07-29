# Dependency image and service admission

This procedure turns the source-resolved dependency candidate into a separate,
reviewed deployment candidate. It does not authorize provisioning and cannot
produce campaign evidence without the live prerequisite gate.

The bounded signature observation, exception requirements, and empty mirror
receipt contract are maintained in
[`dependency-supply-chain-intake.md`](dependency-supply-chain-intake.md).

The immutable input is
`config/dependency-admission.lock.json`, digest
`sha256:73282faf172793398120509087930691e362f2290d4b60cc7f13ef4f99bf4219`.
It deliberately contains no destination references, mirror digests, lab
signatures, live identities, or approval claims.

## Roles

- The source reviewer verifies upstream packages, images, licences, and
  provenance.
- The mirror operator has short-lived write access only to the bootstrap
  Artifact Registry and Harbor intake projects.
- The KMS signer may sign admitted destination subjects but cannot mirror or
  deploy them.
- The GitOps reviewer can approve the admitted overlay but cannot sign
  evidence or execute a fault.

At least two independent humans review activation. No one identity may perform
source review, mirror write, KMS signing, and final approval.

## Source verification

1. Download each chart package and the Barman Cloud manifest from the exact
   source in the dependency BOM/admission lock.
2. Recompute every package, manifest, index, and linux/amd64 manifest digest.
   Reject a matching tag with a different digest.

The source image and release-manifest check is automated and remains separate
from signature admission:

```bash
python3 scripts/verify_dependency_sources.py
```

Use `--image <id> --skip-artifacts` for a bounded retry. A successful command
prints `signatureAdmission=false`; it cannot satisfy the next verification
step by itself.

3. For Sigstore-capable projects, verify the issuer and repository/workflow
   identity, not only cryptographic validity. Preserve the verification bundle
   in restricted raw evidence.
4. For a source without an acceptable upstream signature, require a named,
   expiring, two-person exception that records licence review, source digest,
   vulnerability findings, and compensating controls. A missing signature is
   never silently interpreted as verified.
5. Render each chart with the proposed values and inventory every init,
   sidecar, hook, test, and workload image. The Altinity CRD hook stays disabled
   so its upstream mutable `bitnami/kubectl:latest` default cannot enter the
   deployment. CRDs are admitted from the locked chart package instead.

The Barman Cloud upstream manifest needs a reviewed hardening patch before
admission: pin both controller and sidecar by destination digest, replace its
image-name-only Secret with a non-Secret configuration mechanism, add resource
limits and disruption behavior, and keep cert-manager-generated TLS material
out of Git.

## Offline values-candidate review

The source-only candidate is bound by
`config/dependency-gitops-candidate.lock.json`, digest
`sha256:62c01f5574ee0b065f6b8a67d09c32a7cf9c076497f347746e0b4830f3a8cf22`.
It covers only the five chart packages whose operator/service images are fully
inventoried:

| Package | Expected package SHA-256 |
|---|---|
| `cloudnative-pg-0.29.0.tgz` | `668e065ff53508d58238788fd35b355a925060843629a951df0e6a9362e6d32f` |
| `altinity-clickhouse-operator-0.27.1.tgz` | `716fd37d87bce19e15b42b207db5b0363f61d4f7b546413935d9a2ed9144401e` |
| `nats-2.14.2.tgz` | `86e0fbfe000b6d7fe70a3032ad3a667252f2d3dd2022e95f7330704d947d0f84` |
| `vault-0.34.0.tgz` | `a716f4fa8bb80e450ce7c0f9de7b475183c47437a162eee744cd40bf991244e9` |
| `external-secrets-2.8.0.tgz` | `251e4615013c6d2f9ade5cedf1cd8615613f286bfc381e44fb005f197e611ecd` |

Verify package bytes before extraction or rendering. Store chart packages and
rendered manifests under ignored `restricted/` custody, never in Git:

```bash
shasum -a 256 /path/to/cloudnative-pg-0.29.0.tgz
mkdir -p restricted/dependency-gitops-candidate
helm template cloudnative-pg /path/to/cloudnative-pg-0.29.0.tgz \
  --namespace orchestra-postgres \
  --include-crds \
  -f gitops/dependencies/candidates/reference-lab/cloudnative-pg.values.json \
  > restricted/dependency-gitops-candidate/cloudnative-pg.yaml
```

Repeat for ClickHouse, JetStream, Vault, and External Secrets with their exact
package and values paths. For every output:

1. enumerate all rendered images and require the admitted `linux/amd64`
   platform digests;
2. reject upstream registries, mutable tags, undeclared hooks, tests, init
   containers, and sidecars;
3. inspect cluster-scoped RBAC, CRDs, webhook configuration, PDBs, topology,
   storage, TLS, Workload Identity, and Secret references;
4. confirm the Altinity CRD hook and NATS toolbox are disabled;
5. confirm Vault relies on the chart-injected per-pod Raft node identity; and
6. confirm External Secrets uses external cert-manager issuance and renders no
   built-in certificate `Secret` or `Certificate`.

The registry project placeholder is intentionally unresolved. An offline
render does not establish a destination mirror, signature, private-pull proof,
server-side dry run, deployment, or campaign evidence. Do not apply it and do
not add the candidate directory to the active Kustomization.

## Mirror and sign

1. Copy only the declared linux/amd64 manifest into the immutable bootstrap
   Artifact Registry repository. Do not copy by tag alone.
2. Resolve the destination subject and prove that its manifest digest matches
   the admitted source platform digest. Record registry object generation and
   the short-lived mirror actor identity digest.
3. Apply the lab Cloud KMS signature to that exact destination subject. Store
   the detached signature bundle digest, signer identity digest, and policy
   digest.
4. Repeat the same process into Harbor. Verify pull by digest from a private
   GKE node and a private OpenShift node before declaring the mirror usable.
5. Submit a new immutable admission-lock revision. Never overwrite this source
   candidate or backfill its false claims without the underlying receipts.

## Service contract review

Review the six declared contracts independently:

- PostgreSQL uses two separate three-instance CloudNativePG clusters,
  PostgreSQL 16.10, regional PD, synchronous standby, TLS, Barman Cloud PITR,
  and GKE Workload Identity. No JSON service-account key is permitted.
- ClickHouse uses one shard with three replicas plus three Keeper instances.
  The 25.8.28.1 LTS candidate remains blocked until platform compatibility and
  a concrete backup/restore contract pass.
- JetStream uses three servers, R3 streams, per-pod regional PD, mTLS for
  clients and routes, account authorization, encrypted storage, and the
  snapshot API for backup export.
- Vault uses three Raft members, TLS, regional PD, GCP KMS auto-unseal through
  Workload Identity, audit storage, and Raft snapshots. The injector stays
  disabled in the services plane.
- External Secrets runs in OpenShift, not GKE. It authenticates to private
  Vault with a bounded Kubernetes identity and projects only allowlisted paths
  into declared namespaces.

Any material version, image, topology, storage, backup, TLS, identity, or
network change creates a new admission digest and invalidates dependent dry
runs.

## Activation gate

Activation requires all of the following in one reviewed candidate:

1. Verified live prerequisites.
2. Source verification or accepted, time-bounded exceptions.
3. Artifact Registry and Harbor destination digests.
4. Lab KMS signature bundles and successful admission-policy tests.
5. Existing live Secret, certificate, Workload Identity, storage, and backup
   references without reading their values into evidence.
6. Product compatibility results for PostgreSQL, ClickHouse, JetStream, and
   Vault.
7. Successful server-side dry runs against the exact GKE and OpenShift API
   versions.
8. Two independent approvals.

Only then may a reviewed Git change add dependency Applications and remove the
continuous deny windows. Argo CD remains the sole deployment authority.
