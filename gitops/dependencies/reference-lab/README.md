# Dependency-plane admission floor

This overlay is intentionally non-activatable. It creates the eleven
services-plane namespaces, applies default-deny ingress and egress to each,
and creates an Argo CD `AppProject` with a continuous deny window. It contains
zero `Application`, `ApplicationSet`, or `Secret` objects.

External Secrets runs in OpenShift and reaches the private Vault service over
the peered network. Its namespace and security floor therefore live in the
OpenShift cluster overlay, not in this GKE services-plane project.

The immutable source catalog is
[`config/dependency-bom.lock.json`](../../../config/dependency-bom.lock.json).
Its current digest is
`sha256:fabec47064381d067ca759ba99c47470cc66628ecaacd2e0521f50bb29aad5dc`.
That lock records downloaded upstream chart package digests; it does not claim
that upstream signatures, chart images, or destination mirrors have been
verified.

The source-resolved dependency admission candidate is
[`config/dependency-admission.lock.json`](../../../config/dependency-admission.lock.json),
digest
`sha256:73282faf172793398120509087930691e362f2290d4b60cc7f13ef4f99bf4219`.
It binds eleven exact source image indexes and linux/amd64 manifests plus six
service contracts. All upstream verification, mirror, lab-signature, live
binding, dry-run, and approval fields remain blocked.

The project also binds the bounded source-verification observation digest
`sha256:75539cd9e8b0fce8e556b7d3cd8a7437d2e6f26525e96639085feff431478ed8`.
Three exact subjects verified cryptographically, while eight require reviewed
exceptions. The observation is not signed-runner evidence and does not remove
the deny window. The mirror-intake template remains completely empty.

The separate
[source-only dependency candidate](../candidates/reference-lab/README.md)
projects the five fully inventoried chart/image sets into offline
values and records six blocked service-resource plans. Its controlling digest
is
`sha256:62c01f5574ee0b065f6b8a67d09c32a7cf9c076497f347746e0b4830f3a8cf22`.
It is not part of this Kustomization, contains no Application, and has no
destination reference. Its existence does not remove this project's deny
window.

## Why there are no Applications yet

A chart version does not bind all images rendered by that chart. Creating an
Argo Application before recording the full image inventory could turn a
reviewed chart package into mutable upstream pulls. The admitted overlay is a
later artifact and must bind, for every component:

1. upstream signature verification or a named, time-bounded exception;
2. source package digest and every rendered image digest;
3. Artifact Registry and Harbor destination digests;
4. lab KMS signatures and admission-policy dry-run results;
5. all Secret, certificate, Workload Identity, storage, backup, and network
   references;
6. a deterministic Helm render and server-side dry run; and
7. two independent approvals.

Only a reviewed Git change may remove the deny window and add Applications.
No imperative Argo sync or manual workload deployment is permitted.

## Bootstrap sequence

Harbor cannot supply its own installer. Terraform therefore creates an
immutable `orchestra-bootstrap` Artifact Registry repository and a dedicated
short-lived mirror identity. The source charts and complete image inventories
are admitted there first. Services-plane Argo CD is then bootstrapped from the
admitted seed, reconciles the security/data dependencies, and finally promotes
the same subjects into Harbor. Artifact Registry remains available until a
Harbor loss-and-rollback drill succeeds.

The first-party Valkey chart `0.10.0` is source-locked but cannot satisfy this
profile's three-Sentinel contract. Keycloak Operator source and the standalone
Thanos deployment contract are also unresolved. They remain explicit blockers
instead of being replaced with undeclared third-party components.
