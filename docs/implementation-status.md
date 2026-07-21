# Implementation status

States are recorded independently. `declared` or `CI-validated` never implies
`applied`, `deployed`, `rehearsed`, `soaked`, or `verified`.

| Capability | Declared | CI-validated | Applied | Live-tested | Campaign evidence |
|---|---:|---:|---:|---:|---:|
| Exact topology and claim lock | Yes | Yes | No | No | No |
| Immutable three-plane release set and runner | Yes | Yes | No | No | No |
| Strict prerequisite admission | Yes | Yes | No | No | No |
| Project/API/state/KMS/WIF bootstrap | Yes | Yes | No | No | No |
| Monthly budget thresholds | Yes | Yes | No | No | No |
| Dual VPC, subnets, NAT, peering, flow logs | Yes | Yes | No | No | No |
| Explicit egress allowlist plus deny floor | Yes | Yes | No | No | No |
| Private regional GKE, three fixed nodes | Yes | Yes | No | No | No |
| Immutable pre-Harbor Artifact Registry seed | Yes | Yes | No | No | No |
| CMEK 400-day/90-day evidence buckets | Yes | Yes | No | No | No |
| IAP bastion and two zonally independent probe hosts | Yes | Yes | No | No | No |
| Distinct operator identity shells | Yes | Yes | No | No | No |
| OpenShift installer input | Yes | Yes | No | No | No |
| Namespace/restricted/default-deny/quota/storage floor | Yes | Yes | No | No | No |
| OpenShift `4.20.27` cluster | No | N/A | No | No | No |
| Immutable dependency source/BOM lock | Yes | Yes | No | No | No |
| Dependency GitOps namespace/default-deny/project floor | Yes | Yes | No | No | No |
| Dependency operator Applications and admitted image locks | No | N/A | No | No | No |
| Dependency service CRs/values | No | N/A | No | No | No |
| Vault/ESO/Harbor/Keycloak | No | N/A | No | No | No |
| Product GitOps applications | Yes | Yes | No | No | No |
| Runtime/model Secret-backed server TLS declarations | Yes | Yes | No | No | No |
| Platform router-to-pod TLS | Yes | Yes | No | No | No |
| Durable release-validation receiver and GitHub App executor | Yes | Yes | No | No | No |
| Synthetic tenant gateway and read-only MCP fault surfaces | Yes | Yes | No | No | No |
| Pinned CPU model and embedding backends | No | N/A | No | No | No |
| Slots 1-17 rehearsal and frozen runs | No | N/A | No | No | No |
| 72-hour burn-in | No | N/A | No | No | No |
| 30-day soak | No | N/A | No | No | No |
| Reference verification BOM | No | N/A | No | No | No |

The dependency source catalog and fail-closed GitOps floor are now declared.
The next dependency increment is image-level mirror admission plus reviewed
service contracts for PostgreSQL, ClickHouse/Keeper, JetStream, Vault, and
External Secrets. Valkey/Sentinel, Keycloak Operator, and standalone Thanos
remain named design decisions. Platform backend TLS is now declared with an
OpenShift service-serving certificate and re-encrypt Route. The durable
release-validation receiver now has a strict signed-event parser,
transactional PostgreSQL inbox/outbox, monotonic admission, GitHub App
dispatcher, indeterminate-delivery reconciliation, pinned UBI build, and
disposable PostgreSQL tests. The synthetic tenant kit now has strict Keycloak
JWT/JWKS verification, an HTTPS-only runtime proxy, official read-only MCP
Streamable HTTP behavior, and normal/slow/unavailable/wrong-tenant fault
lanes. Both services have hash-locked UBI AMD64 builds, but neither has a
published or mirrored image or GitOps reference. Live activation remains
behind Red Hat, GCP, DNS, PKI, Keycloak, and short-lived identity gates; no
dependency or product declaration has been applied.
