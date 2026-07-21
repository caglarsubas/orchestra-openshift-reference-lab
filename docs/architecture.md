# Reference-lab architecture

## Trust zones

```mermaid
flowchart LR
  subgraph GCP_TARGET["GCP target project"]
    IAP["IAP bastion"]
    OCP["Private OCP 4.20.27"]
    PLATFORM["Orchestra control plane"]
    GATEWAY["Synthetic tenant gateway"]
    RUNTIME["Tenant runtime host"]
    MODEL["Model plane"]
    IAP --> OCP
    OCP --> PLATFORM
    OCP --> GATEWAY
    OCP --> RUNTIME
    OCP --> MODEL
    GATEWAY -->|"JWT-authenticated tenant request"| RUNTIME
  end

  subgraph GCP_SERVICES["GCP services and evidence project"]
    GKE["Private regional GKE"]
    DATA["PostgreSQL, ClickHouse, JetStream, Valkey"]
    SECURITY["Vault, Harbor, Keycloak"]
    SEED["Immutable Artifact Registry bootstrap seed"]
    SARGO["Services-plane Argo CD"]
    SYNTHETIC["Synthetic MCP and model backends"]
    EVIDENCE["Probes, Thanos, immutable GCS"]
    GKE --> DATA
    GKE --> SECURITY
    SEED --> SARGO
    SARGO --> GKE
    GKE --> SYNTHETIC
    GKE --> EVIDENCE
  end

  OCP <-->|"Private VPC peering and explicit firewall"| GKE
  SECURITY -->|"OIDC JWKS and synthetic identities"| GATEWAY
  RUNTIME -->|"Model and read-only MCP only"| SYNTHETIC
  PLATFORM -->|"Receipts and telemetry; no deployment credential"| EVIDENCE
  ARGO["OpenShift GitOps / Argo CD"] -->|"Sole workload rollout authority"| OCP
```

## Boundary invariants

1. The tenant gateway and runtime path remain tenant-plane components.
   Orchestra is not a synchronous production proxy.
2. OpenShift GitOps owns promotion, hold, rollback, and workload credentials.
   Orchestra emits signed recommendations and observes the result.
3. Platform agent-query and production tool-execution paths remain disabled.
   The runtime may call only the pinned model plane and read-only synthetic MCP
   allowlist during this campaign.
4. The target project and dependency/evidence project are separate. Peering is
   private, non-transitive, and protected by explicit ingress and egress rules.
5. Evidence writers cannot mutate infrastructure. Fault controllers cannot
   approve or sign certification results. Reviewers cannot execute drills.
6. Generated Secret values are never stored in Git. External Secrets resolves
   Vault references at runtime.
7. OpenShift GitOps owns tenant-plane product rollout. A separate
   services-plane Argo CD instance owns GKE dependencies, starts from the
   immutable Artifact Registry seed, and cannot mutate OpenShift products.
8. The dependency AppProject remains continuously denied until a reviewed
   image-level admission overlay is committed. A source chart lock is not an
   executable deployment approval.
9. The synthetic tenant gateway may contact Keycloak and the runtime host only.
   Its runtime credential is tenant-owned, and it has no platform API key or
   deployment credential. Tenant-beta identities are adversarial inputs, not a
   second certified tenant.
10. Synthetic MCP deployments expose one read-only, idempotent tool. Slow,
    unavailable, wrong-tenant, and untrusted-certificate lanes are separate
    immutable deployments; none may enable write or destructive behavior.

## Source-of-truth split

- This repository: infrastructure, GitOps, synthetic surfaces, campaigns,
  fault orchestration, and runbooks.
- `prometa-platform`: certification contracts, aggregation, platform probes,
  policy/evidence behavior, and certification-runner source.
- `orchestra-python-sdk`: runtime-host lifecycle and MCP probes.
- `llm_inference_engine`: routing, inference, TLS, fairness, fallback,
  embedding, and lifecycle probes.

Changing a product-owned behavior here is prohibited. A product fix creates a
new immutable artifact in its owning repository, updates the cross-plane
release set, and reruns affected evidence.

The topology, release set, and dependency BOM are separate canonical inputs.
Campaigns bind their digests independently;
none can be inferred from another. Mirroring an accepted release into Harbor
records destination digests and lab signatures as deployment evidence without
rewriting the source release set.
