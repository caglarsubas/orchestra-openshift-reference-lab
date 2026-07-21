# Reference-lab architecture

## Trust zones

```mermaid
flowchart LR
  subgraph GCP_TARGET["GCP target project"]
    IAP["IAP bastion"]
    OCP["Private OCP 4.20.27"]
    PLATFORM["Orchestra control plane"]
    RUNTIME["Tenant runtime host"]
    MODEL["Model-plane client"]
    IAP --> OCP
    OCP --> PLATFORM
    OCP --> RUNTIME
    OCP --> MODEL
  end

  subgraph GCP_SERVICES["GCP services and evidence project"]
    GKE["Private regional GKE"]
    DATA["PostgreSQL, ClickHouse, JetStream, Valkey"]
    SECURITY["Vault, Harbor, Keycloak"]
    SYNTHETIC["Synthetic MCP and model backends"]
    EVIDENCE["Probes, Thanos, immutable GCS"]
    GKE --> DATA
    GKE --> SECURITY
    GKE --> SYNTHETIC
    GKE --> EVIDENCE
  end

  OCP <-->|"Private VPC peering and explicit firewall"| GKE
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
