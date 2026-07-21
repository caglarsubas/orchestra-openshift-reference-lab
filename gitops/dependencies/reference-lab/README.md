# Dependency-plane admission floor

This overlay is intentionally non-activatable. It creates the twelve
services-plane namespaces, applies default-deny ingress and egress to each,
and creates an Argo CD `AppProject` with a continuous deny window. It contains
zero `Application`, `ApplicationSet`, or `Secret` objects.

The immutable source catalog is
[`config/dependency-bom.lock.json`](../../../config/dependency-bom.lock.json).
Its current digest is
`sha256:fabec47064381d067ca759ba99c47470cc66628ecaacd2e0521f50bb29aad5dc`.
That lock records downloaded upstream chart package digests; it does not claim
that upstream signatures, chart images, or destination mirrors have been
verified.

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
