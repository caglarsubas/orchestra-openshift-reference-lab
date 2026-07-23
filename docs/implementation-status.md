# Implementation status

States are recorded independently. `declared` or `CI-validated` never implies
`applied`, `deployed`, `rehearsed`, `soaked`, or `verified`.

| Capability | Declared | CI-validated | Applied | Live-tested | Campaign evidence |
|---|---:|---:|---:|---:|---:|
| Exact topology and claim lock | Yes | Yes | No | No | No |
| Immutable three-plane release set and runner | Yes | Yes | No | No | No |
| Platform-owned certification contract intake | Yes | Yes | No | No | No |
| Strict prerequisite admission | Yes | Yes | No | No | No |
| Stage-aware payload-free prerequisite observation | Yes | Yes | No | No | No |
| Project/API/state/KMS/WIF bootstrap | Yes | Yes | No | No | No |
| Environment/current-review-bound read-only foundation plan | Yes | Yes | No | No | No |
| Immutable signed saved-plan package and private review path | Yes | Yes | No | No | No |
| Separately federated exact saved-plan foundation apply | Yes | Yes | No | No | No |
| Signed self-attested foundation apply receipt | Yes | Yes | No | No | No |
| Independent post-apply foundation observation | Yes | Yes | No | No | No |
| Monthly budget thresholds | Yes | Yes | No | No | No |
| Dual VPC, subnets, NAT, peering, flow logs | Yes | Yes | No | No | No |
| Public delegation zone and private DNS peering | Yes | Yes | No | No | No |
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
| Signed-runner collection launch preflight | Yes | Yes | No | No | No |
| Dedicated dependency-risk KMS/WIF preflight authority | Yes | Yes | No | No | No |
| Protected exact-main dependency-risk preflight workflow | Yes | Yes | No | No | No |
| Dedicated dependency-risk collection/custody authority | Yes | Yes | No | No | No |
| Protected full collection and create-only raw-custody workflow | Yes | Yes | No | No | No |
| Dedicated independent raw-custody verification authority | Yes | Yes | No | No | No |
| Generation-pinned raw verification and signed-report workflow | Yes | Yes | No | No | No |
| Live signed-runner vulnerability/SBOM evidence | No | N/A | No | No | No |
| Live independently verified raw custody | No | N/A | No | No | No |
| Empty upstream-signature exception intake | Yes | Yes | No | No | No |
| Reviewed upstream-signature exceptions | No | N/A | No | No | No |
| Empty mirror-receipt intake contract | Yes | Yes | No | No | No |
| Dependency topology/security/backup contracts | Yes | Yes | No | No | No |
| Dependency GitOps namespace/default-deny/project floor | Yes | Yes | No | No | No |
| Source-only dependency chart values and service plans | Yes | Yes | No | No | No |
| Dependency operator Applications and admitted image locks | No | N/A | No | No | No |
| Admitted dependency service CRs/values | No | N/A | No | No | No |
| Admitted/deployed Vault/ESO/Harbor/Keycloak | No | N/A | No | No | No |
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

The platform-owned certification intake now pins the exact policy, strict
schema bundle, and fixture bytes from platform release
`platform-v0.1.0-rc.10` at revision
`a6eb8a98051197722cd338c76a3e4d29d5a51c87`. CI validates their raw and
canonical digests, the live policy's 18 evidence slots, schema strictness,
release/topology/dependency bindings, bounded BOM claims, and the fixture's
`fixture/simulated` isolation. An operator command additionally replays the
pinned Git objects from an authorized platform checkout. This is source-only
contract intake: no live campaign has started, no evidence slot is populated,
and no verification or certification claim changes.

The pinned runner toolchain now binds the
`orchestra.openshift.certification-probes.v1` contract and its 15 exact
commands, including preflight, target intake, deployment observation, pod and
worker drills, outage observation, and secret-rotation capture/verification.
CI checks the released toolchain bytes and command inventory. Live OCI
signature replay, mirroring, admission, and runner execution remain required
before those commands can produce reference-lab evidence.

The dependency source catalog, fail-closed GitOps floor, eleven exact AMD64
source image identities, and six detailed service contracts are declared. A
seven-day, non-campaign workstation observation cryptographically verified
three exact keyless subjects and found no attached signature for eight. It did
not approve an exception or authorize mirroring; signed-runner replay remains
required. A locked risk policy, strict JSON contracts, atomic eight-subject
collector, fail-closed no-evidence launch preflight, detached Cloud KMS
verification path, payload-free Trivy/SPDX evidence builder, and empty
eight-subject exception intake are now declared and CI-validated. The preflight
replays the published runner signature, SBOM attestation, release-manifest
signature, and SLSA provenance, verifies exact tool versions, and proves an
ephemeral Cloud KMS signing round trip before any scanner database download.
It has not been run against live infrastructure.

The dedicated preflight authority is now also source-declared and
CI-validated. Bootstrap Terraform declares an exact-workflow WIF provider and
a service account with no project, storage, or mirror grant. Foundation
Terraform declares a separate asymmetric signing key and grants that identity
only key-level signing and verification. The protected workflow accepts an
exact reviewed key version and public-key digest, obtains short-lived GCP and
GitHub App credentials, and runs only `--preflight-only`; it uploads no
artifact. Neither Terraform state has been applied, the protected environment
and GitHub App remain external configuration, and no live preflight result is
checked in or inferred.

The separate full-collection authority is also source-declared and
CI-validated. Its exact-workflow WIF identity receives no project role, raw
read/delete grant, signed-evidence grant, or mirror grant. It can sign with the
dedicated key and create non-overwritable objects in the restricted raw bucket.
The protected workflow repeats preflight, performs the complete collection,
verifies it before publication, and uploads the detached custody signature
last. Tests execute the publisher with simulated KMS and storage commands,
including a failed completion-marker upload. This proves local contract,
ordering, and fail-closed behavior only. The collector deliberately does not
record GCS object generations, so an independent custody observer remains
required before the raw prefix can support any later evidence intake.

That independent custody lane is now source-declared and CI-validated. A third
exact-workflow WIF identity has no project role and receives only managed-folder
read/list access to `dependency-risk/`, managed-folder create-only access to
`dependency-risk-custody/`, public-key access to the collection key, and
sign/verify access to a separate report key. Its protected workflow records and
pins all four raw object generations and metagenerations, verifies completion
marker ordering and the collection key, safely extracts the bounded archive,
replays the full collection verifier, verifies the new report signature against
an independently expected key digest, and uploads that signature last. Tests
exercise extra-object, marker-order, size-drift, key-substitution,
archive-traversal, report-tamper, invalid-report-signature, and
failed-final-upload cases. This remains local source evidence: no Terraform
resource or protected environment has been created, and no live raw prefix or
signed custody report has been verified.
All six GitHub providers use distinct provider-prefixed subjects, and IAM
impersonation binds each service account to one exact subject instead of a
repository-wide principal set. The planner and create-only packager share only
the exact plan subject; the executor uses the separate apply subject. This
removes cross-assumption between foundation execution and the three
dependency-risk authorities in the shared pool; the live bindings still
require independent verification after apply.

No live scan or human review is checked in, so no exception is approved. The
mirror intake is intentionally empty. No destination mirror, lab
signature, live identity, backup target, server-side dry run, or approval is
claimed. ClickHouse backup selection and compatibility proofs remain explicit
blockers. External Secrets is correctly assigned to OpenShift while Vault
remains in the GKE services plane. A separate source-only candidate now binds
five exact chart/image projections and six blocked service plans. It disables
the Altinity mutable CRD hook, uses the chart-provided Vault Raft node identity,
and requires external cert-manager issuance for the External Secrets webhook.
CI proves it contains no deployable manifest or destination reference and is
not reachable from the active Kustomization. This is not an admitted overlay.

The next live increment is bootstrap/foundation application and independent
verification of all six WIF providers, seven service accounts, foundation and
dependency-risk KMS versions/public-key digests, managed-folder and bucket IAM,
all six protected environments, reviewer-group plan access, and the GitHub
App installation. The
protected launch preflight executes first; a successful result still does not
start collection. A separately approved full-collection run may then publish
only a completed raw prefix. A third approval runs the independent custody lane
to capture exact object generations and verify the detached signature. Only
that signed custody report can feed later licence/risk reviews and source-replay
aggregation; it still cannot authorize Artifact Registry/Harbor mirroring or an
executable operator/service overlay.
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

Prerequisite admission is now separated from machine observation. The locked
policy defines bootstrap, foundation, and OpenShift-install stages, removing
the prior cycle that required project and WIF evidence before Terraform created
those resources. The read-only collector validates restricted pull-secret and
installer inputs, exact GCP project/API/billing/quota state, DNS delegation,
WIF restrictions, runner Sigstore identity, and the canonical release set while
storing no secret or raw provider output. Diagnostic runs are
`fixture/simulated`; live runs bind the published runner. Neither can verify a
gate, authorize provisioning, or produce campaign evidence. No live
prerequisite observation or independent review exists yet.

The DNS foundation now declares the exact services-project public zone and a
one-way services-to-target peering zone for the private cluster namespace. It
does not create private OpenShift records, perform registrar delegation, or
claim that either resolution path works live. Those states require the
foundation apply, external NS update, installer-created private zone, and the
independent checks in the DNS runbook.

The foundation execution lane is source-declared and CI-validated. A read-only
planner produces a saved plan without locking state; a create-only identity
signs and publishes an immutable five-object package; group-only reviewers can
generation-pin, verify, and render the full value-bearing plan under ignored
restricted storage; and a separate exact-workflow executor can apply only that
non-destructive plan with state locking. It emits a distinct signed receipt
whose contract explicitly remains self-attested and
`independentlyObserved: false`. The required GitHub Enterprise environments,
non-owner collaborator, reviewer group, bootstrap resources, KMS versions, and
live prerequisite evidence do not exist in this source checkout. No live plan,
apply, receipt, or independent post-apply observation exists.

The independent foundation-observation lane is now also source-declared and
CI-validated. A sixth exact-workflow WIF provider binds a dedicated observer
identity with read-only provider roles, a metadata-only storage custom role,
generation-pinned state/plan/receipt reads, create-only observation writes,
public-key access to prior signing keys, and a separate report key. Before
trusting itself, the lane verifies the deployed provider, exact
service-account impersonation, absence of user-managed keys, project and
direct ancestor role boundaries, custom-role permissions, managed-folder
grants, and KMS grants. Group-transitive access remains an independent live
review prerequisite. The lane then verifies both prior signatures, binds the
current state to the receipt, runs a lock-free refresh-only Terraform plan,
rejects drift or a resource-identity mismatch, and uploads its signature last.
A valid live report can assert only the narrow foundation
`independentlyObserved` state; campaign and certification claims remain false.
No Terraform resource,
protected environment, plan, apply receipt, provider refresh, or report has
been created by this source-only increment.
