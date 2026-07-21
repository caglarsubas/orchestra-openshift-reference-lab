# Implementation status

States are recorded independently. `declared` or `CI-validated` never implies
`applied`, `deployed`, `rehearsed`, `soaked`, or `verified`.

| Capability | Declared | CI-validated | Applied | Live-tested | Campaign evidence |
|---|---:|---:|---:|---:|---:|
| Exact topology and claim lock | Yes | Yes | No | No | No |
| Strict prerequisite admission | Yes | Yes | No | No | No |
| Project/API/state/KMS/WIF bootstrap | Yes | Yes | No | No | No |
| Monthly budget thresholds | Yes | Yes | No | No | No |
| Dual VPC, subnets, NAT, peering, flow logs | Yes | Yes | No | No | No |
| Explicit egress allowlist plus deny floor | Yes | Yes | No | No | No |
| Private regional GKE, three fixed nodes | Yes | Yes | No | No | No |
| CMEK 400-day/90-day evidence buckets | Yes | Yes | No | No | No |
| IAP bastion and two zonally independent probe hosts | Yes | Yes | No | No | No |
| Distinct operator identity shells | Yes | Yes | No | No | No |
| OpenShift installer input | Yes | Yes | No | No | No |
| Namespace/restricted/default-deny/quota/storage floor | Yes | Yes | No | No | No |
| OpenShift `4.20.27` cluster | No | N/A | No | No | No |
| Dependency operators/services | No | N/A | No | No | No |
| Vault/ESO/Harbor/Keycloak | No | N/A | No | No | No |
| Product GitOps applications | No | N/A | No | No | No |
| Synthetic tenant/MCP/model surfaces | No | N/A | No | No | No |
| Slots 1-17 rehearsal and frozen runs | No | N/A | No | No | No |
| 72-hour burn-in | No | N/A | No | No | No |
| 30-day soak | No | N/A | No | No | No |
| Reference verification BOM | No | N/A | No | No | No |

The next implementation increment is Wave 1 dependency-plane GitOps and
operator pinning, but it remains behind Red Hat, GCP, DNS, runner, and release
set gates.
