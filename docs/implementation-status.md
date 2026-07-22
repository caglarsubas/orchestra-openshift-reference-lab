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
| Source-resolved dependency image admission lock | Yes | Yes | No | No | No |
| Bounded source-signature observation | Yes | Yes | No | Partial | No |
| Unsigned-source risk policy and strict contracts | Yes | Yes | No | No | No |
| Signed-runner vulnerability/SBOM evidence bundle contract | Yes | Yes | No | No | No |
| Live signed-runner vulnerability/SBOM evidence | No | N/A | No | No | No |
| Empty upstream-signature exception intake | Yes | Yes | No | No | No |
| Reviewed upstream-signature exceptions | No | N/A | No | No | No |
| Empty mirror-receipt intake contract | Yes | Yes | No | No | No |
| Dependency topology/security/backup contracts | Yes | Yes | No | No | No |
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

The dependency source catalog, fail-closed GitOps floor, eleven exact AMD64
source image identities, and six detailed service contracts are declared. A
seven-day, non-campaign workstation observation cryptographically verified
three exact keyless subjects and found no attached signature for eight. It did
not approve an exception or authorize mirroring; signed-runner replay remains
required. A locked risk policy, strict JSON contracts, atomic eight-subject
collector, detached Cloud KMS verification path, payload-free Trivy/SPDX
evidence builder, and empty eight-subject exception intake are now declared and
CI-validated. The collector also replays the published runner signature, SBOM
attestation, release-manifest signature, and SLSA provenance before scanning.
No live scan or human review is checked in, so no exception is approved. The
mirror intake is intentionally empty. No destination mirror, lab
signature, live identity, backup target, server-side dry run, or approval is
claimed. ClickHouse backup selection and compatibility proofs remain explicit
blockers. External Secrets is correctly assigned to OpenShift while Vault
remains in the GKE services plane. The next dependency increment is execution
of the live signed-runner collection with an approved short-lived identity and
Cloud KMS key, followed by independent licence/risk reviews, source-replay
aggregation, live Artifact Registry/Harbor receipts, and executable
operator/service overlays.
Valkey/Sentinel, Keycloak Operator, and standalone Thanos remain named design
decisions. Platform backend TLS is now declared with an
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
