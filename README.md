# Orchestra OpenShift Reference Lab

Private infrastructure and GitOps source for the exact
`orchestra-ocp-4.20-amd64-v1` vendor reference lab.

The lab is designed to produce this bounded result after a real campaign:

```json
{
  "referenceProfileVerified": true,
  "customerCertified": false,
  "redHatCertified": false,
  "contractualSla": false
}
```

It does not put Orchestra in a tenant's synchronous production request path,
does not grant Orchestra deployment authority over customer workloads, and
does not enable platform production tool execution.

## Current state

This repository contains the source-controlled infrastructure foundation,
immutable cross-plane release intake, immutable dependency source catalog,
immutable platform-owned certification contract intake,
source-resolved dependency admission contract, bounded source-signature
observation, locked unsigned-source risk policy, empty signature-exception and
mirror-intake contracts, a digest-bound source-only dependency GitOps
candidate, an atomic signed-runner scan collector and detached
attestation verifier, an exact public OpenShift SNO toolchain archive lock and
payload-free local intake verifier, a stage-aware prerequisite observation policy and
payload-free read-only collector, gate-controlled product and dependency
GitOps floors, an environment-bound read-only Terraform planning lane, a
create-only signed saved-plan package lane, a private generation-pinned plan
review helper, a separately federated saved-plan-only apply lane with signed
self-attested receipts, a separately federated read-only provider-refresh
observation lane with create-only signed reports, a payload-free GitHub
environment/current-run approval verifier, a strict aggregate verifier for all
six protected environments and the complete read-only platform-release GitHub
App installation, an exact-main immutable GHCR publication lane for the two
lab-owned services with pinned embedded SBOM/provenance and keyless signatures,
a separately executed read-only publication replay, and digest-bound
published-but-unadmitted receiver and synthetic tenant-kit inventories. It does
not contain a kubeconfig, provider
identity, OpenShift pull secret, live prerequisite observation, independent
prerequisite review, live risk scan, approved source exception, live campaign,
campaign evidence report, or completed soak. No production-reference
declaration has been applied to a target, so the reference profile is not
verified.

Hard gates are recorded in
[`config/prerequisites.example.json`](config/prerequisites.example.json). A
live copy belongs under ignored `restricted/` storage and must contain digests,
not credentials. Provisioning is blocked until every gate is independently
verified. Machine observation is separately governed by
[`config/prerequisite-observation-policy.lock.json`](config/prerequisite-observation-policy.lock.json):
diagnostic output is always `fixture/simulated`, while live output must bind the
published certification runner. Neither output can verify a gate or authorize
provisioning.

## Cost-bounded SNO engineering trial

The separate `orchestra-ocp-sno-trial-amd64-v1` profile provides a live,
non-certifying path for the current Red Hat trial and a `$75` monthly budget
alert ceiling. The Google billing account is denominated in TRY, so the
provider budget is locked to 3,500 TRY (about $74.08 at the 2026-07-24 TCMB
selling rate). It does not alter or weaken `orchestra-ocp-4.20-amd64-v1`.
The account-specific conversion is isolated in
[`config/sno-trial-billing-execution.lock.json`](config/sno-trial-billing-execution.lock.json)
so rotating it does not rewrite the stable trial profile or product-artifact
lineage.

- One OpenShift `4.20.27` `n2-standard-8` control-plane node in
  `europe-west1-b`, 150 GB `pd-balanced`, and zero workers.
- No GKE dependency plane; only named single-replica engineering dependencies
  may be co-located on SNO.
- A maximum 12-hour operator lease is required before installer rendering,
  with an 8-hour first-session recommendation and no more than 48 active
  node-hours per month.
- Budget alerts fire at 10, 25, 50, 75, 90, and 100 percent. GCP budgets are
  alerts, not hard spending caps, and the source lease does not automatically
  destroy provider resources.
- All certification, HA, RPO/RTO, production-support, and SLA claims remain
  false. The profile has no allowed certification evidence slots.

The locked trial contract is
[`config/sno-trial.lock.json`](config/sno-trial.lock.json), with canonical
digest
`sha256:9a7dbdac36417b10ce15b74de4558502fc09cf1740153c5817b89df4c0ba738a`.
The complete source-to-destroy procedure is in
[`docs/runbooks/sno-trial.md`](docs/runbooks/sno-trial.md).

The disposable `prometa-orch-sno-499235` foundation was applied on 2026-07-26
and independently read back: billing is enabled, all 11 locked APIs are
active, the project-filtered 3,500 TRY budget has all six thresholds, and the
legacy `ocp-lab.prometa.ai.` managed zone exists. The active
`ocp-lab.planeon.ai.` Cloud DNS zone was then created from exact main with a
guarded plan of one add, zero changes, and zero destroys. The legacy zone moved
in Terraform state without a provider mutation. Independent readback observed
both exact zones, and a post-apply plan reported no drift.

On 2026-07-27, the parent delegation, Linux AMD64 operator path, exact
`4.20.27` tools, project-bound lease, and short-lived render admission were
observed before a clean install. The resulting `SingleReplica` cluster had one
ready schedulable `n2-standard-8` control-plane/worker node, zero worker
Machines, `Manual` cloud credentials with workload identity, two CSI storage
classes, a host-scoped API firewall, a reachable console, and 34 of 34 healthy
cluster operators. No product workload or application Secret was deployed.
The cluster and separately created CCO/WIF resources were later destroyed, and
the operator VM was deleted.

Exact-main payload-free observation
`sno-cluster-main-20260727160232.1` has report digest
`sha256:440b40b3e9b173ebe3c8ddba6020406b4a9651b3931a11c1ffd3ffcc88ae21c6`.
It records `TRIAL_CLUSTER_OBSERVED`, grants no mutation authority, and keeps
all campaign, certification, production, HA, RPO/RTO, Red Hat, and SLA claims
false. Product admission, live pull/mirror proof, external inputs, deployment,
and a production/reference-profile exercise remain.

Cost and teardown state use a separate read-only contract. A dated GCP catalog
rate card estimates only the dominant N2/E2 compute and zonal balanced-disk
charges; load balancing, external IP, DNS, egress, tax, credits, and discounts
remain explicit exclusions, so the result is never represented as billed
spend. The same payload-free inventory contract requires zero managed target
and operator resources before it can report clean teardown.

Exact-main active report `sno-exposure-main-20260727163536.1` has digest
`sha256:b11972ee78ee58f6aa326b58ff64895bca60265b63d221734b4a1d2e41b86f88`
and status `ACTIVE_EXPOSURE_OBSERVED`. Its incomplete dominant-charge estimate
at `2026-07-27T16:35:36Z` was `$0.888127` / `41.963752 TRY`; this is not a
billing export, hard cap, or teardown result.

Post-teardown report `sno-exposure-post-teardown-20260727172000.1` has digest
`sha256:98b62fa0b69ef12a362e4915b9ababff3c5b5193652bf9143d9d3508c32fdf70`
and status `TEARDOWN_RESIDUALS_CLEAN`. It observed zero target
instances/disks, zero resources in all ten managed trial classes, and zero
operator VM/disks. This closes the bounded SNO trial cleanup only; the retained
GCP project foundation, budget, APIs, and delegated DNS zone are outside the
managed residual set and the report does not claim that the project is empty.

Product API acceptance and live-capacity projection use another payload-free
contract. It binds the healthy cluster report, artifact set, workload
candidate, and three rendered-manifest digests; runs strict server-side
dry-runs; and proves no rendered object persisted. A successful observation
does not resolve image pulls, destination mirroring, Secrets, CAs,
dependencies, scheduling, readiness, deployment, admission, or certification.

Exact-main report `sno-product-dry-run-main-20260727170500.1` has digest
`sha256:9394ce8fed98e92c46ff01479d86c0f40ee330409d12b8a8e350866d303b2ae1`
and status `SERVER_DRY_RUN_OBSERVED_WITH_GAPS`. All 18 rendered objects passed
strict server-side validation and all were absent afterward. Projecting the
locked candidate over current OpenShift requests left `628m` CPU and
`2214 MiB` memory, so the capacity margin remains explicitly tight. At
collection time, the platform migration image was not artifact-bound, and
external references, live pulls, and destination mirroring were unverified.
The current source contract now binds that released migration image, but this
historical report is immutable and cannot prove the updated artifact set.

The pre-install payload-free report
`sno-readiness-operator-20260726174421.1` binds the current profile digest,
records approved quota status as operator-declared, and remains
`DOWNSTREAM_VERIFICATION_REQUIRED`. Its report digest is
`sha256:13ba6f6fb93e524b0dcb28d653ff9ab52de1228fd0a2d94db8bdd66511cd56dc`.
Re-run the assessment before relying on that point-in-time observation:

```bash
READINESS_ID=sno-readiness-operator-$(date -u +%Y%m%d%H%M%S).1

make observe-sno-trial-readiness \
  PROJECT_ID=prometa-orch-sno-499235 \
  QUOTA_REQUEST_STATUS=approved \
  ASSESSMENT_ID="$READINESS_ID" \
  OUTPUT="restricted/$READINESS_ID.json"

make verify-sno-trial-readiness \
  REPORT="restricted/$READINESS_ID.json"
```

The diagnostic runs only read-only `gcloud` describe/list commands. It stores
neither raw provider output nor billing-account identity and always reports
`cloudMutationAuthorized: false`, `campaignEvidence: false`, and no
certification slots. The quota-review status is explicitly operator-declared;
it is not represented as a `gcloud` or Google attestation.

DNS delegation has its own read-only, payload-free observation contract. It
compares the exact active Cloud DNS zone with the externally authoritative NS
answer, then persists only counts and canonical set digests:

```bash
DNS_ID=sno-dns-operator-$(date -u +%Y%m%d%H%M%S).1

make observe-sno-trial-dns-delegation \
  PROJECT_ID=prometa-orch-sno-499235 \
  ASSESSMENT_ID="$DNS_ID" \
  OUTPUT="restricted/$DNS_ID.json"

make verify-sno-trial-dns-delegation \
  REPORT="restricted/$DNS_ID.json"
```

An empty answer produces `WAITING_DELEGATION`; a partial or different set
produces `BLOCKED`; only an exact set produces `DELEGATION_OBSERVED`. Even that
last status grants no installation or DNS mutation authority. Source CIDR,
administration path, and operator lease verification remain separate gates.

The operator path is also assessed separately on the Linux AMD64 host that
would run the installer. Put one public host CIDR in a mode-`0600` ignored
file, extract the verified installer and client under `restricted/`, and run:

```bash
OPERATOR_ID=sno-operator-operator-$(date -u +%Y%m%d%H%M%S).1

make observe-sno-trial-operator-path \
  PROJECT_ID=prometa-orch-sno-499235 \
  SOURCE_CIDR_FILE=restricted/operator/source-cidr.txt \
  INSTALLER=restricted/redhat/4.20.27/openshift-install \
  CLIENT=restricted/redhat/4.20.27/oc \
  ASSESSMENT_ID="$OPERATOR_ID" \
  OUTPUT="restricted/$OPERATOR_ID.json"

make verify-sno-trial-operator-path \
  REPORT="restricted/$OPERATOR_ID.json"
```

The live collector verifies Linux AMD64, exactly one active `gcloud` identity,
the exact configured project, host-scoped public IPv4 `/32` or IPv6 `/128`,
and exact installer/client version `4.20.27`. It stores identity and source
CIDR digests, never the values. `OPERATOR_PATH_OBSERVED` still grants no
firewall, cloud mutation, or install authority; a short-lived lease and a
separate aggregate install admission remain downstream.

Network hygiene is assessed separately because GCP can create a default
auto-mode VPC when Compute becomes active even when the project contract
disables automatic network creation. The assessment records only counts and
canonical inventory digests, blocks on any pre-install network or firewall
rule, and grants neither cleanup nor install authority:

```bash
NETWORK_ID=sno-network-operator-$(date -u +%Y%m%d%H%M%S).1

make observe-sno-trial-network-hygiene \
  PROJECT_ID=prometa-orch-sno-499235 \
  ASSESSMENT_ID="$NETWORK_ID" \
  OUTPUT="restricted/$NETWORK_ID.json"

make verify-sno-trial-network-hygiene \
  REPORT="restricted/$NETWORK_ID.json"
```

The initial live observation found the unused GCP-created `default` auto-mode
VPC, 42 subnetworks, four default firewall rules, and three enabled
internet-ingress rules. After a zero-dependent-resource inventory, the bounded
operator cleanup removed only those default resources. Fresh report
`sno-network-operator-20260726174421.1` binds the current Planeon profile, is
`CLEAN`, has report digest
`sha256:fb074a14e51f012c750954f766bcd1d09bf05d8f10a40352fee4f8235f870380`,
and observes zero networks, subnetworks, firewall rules, and internet-ingress
rules. This closes the network-hygiene drift only; it does not authorize
installation or produce campaign evidence.

The exact versioned OpenShift `4.20.27` linux/amd64 installer and client
archives are independently available from Red Hat's public mirror. Their URLs,
byte sizes, OpenPGP-signed published checksums, signing-key fingerprint, and
permitted tar members are locked in
[`config/sno-trial-openshift-toolchain.lock.json`](config/sno-trial-openshift-toolchain.lock.json).
The local intake verifies those facts without extracting binaries or reading a
pull secret:

```bash
TOOLCHAIN_ID=sno-toolchain-operator-$(date -u +%Y%m%d%H%M%S).1

make inspect-sno-trial-toolchain \
  ARCHIVE_DIR=restricted/redhat/4.20.27 \
  INTAKE_ID="$TOOLCHAIN_ID" \
  OUTPUT="restricted/$TOOLCHAIN_ID.json"

make verify-sno-trial-toolchain \
  REPORT="restricted/$TOOLCHAIN_ID.json"
```

This intake alone is signed archive-integrity evidence only. The successful
trial separately exercised extracted ELF architecture and version on the
Linux AMD64 operator host, active trial access, and an operator-held pull
secret. No credential value enters a report or the repository. Every report
denies cloud mutation and all campaign or certification use.

The source-only workload candidate in
[`config/sno-trial-workload-candidate.lock.json`](config/sno-trial-workload-candidate.lock.json)
uses the released three-plane images and currently resolved dependency sources
to test whether the intended trial shape can fit on the node. It reserves
3 vCPU and 12 GiB for OpenShift and system services, caps workload requests at
5 vCPU and 20 GiB, and records 3.4 vCPU/14.375 GiB steady requests plus a
serial 250m/256 MiB transient allowance. The resulting peak leaves 1.35 vCPU
and 5.375 GiB request headroom; aggregate limits are 7.25 vCPU/25 GiB and
persistent volumes total 48 GiB. Validate the canonical candidate with:

```bash
make validate-sno-trial-workload-candidate
```

This is a capacity decision record, not deployment input. It emits no
manifests, Argo CD applications, Secret values, lease, or cloud authority.
Its Valkey and CPU model-backend entries intentionally remain unresolved
because the candidate predates the artifact selection below, and
the new trial-specific single-replica manifest candidate is not yet bound back
into this capacity record. The
source-only dependency runtime requirements are locked separately in
[`config/sno-trial-dependency-runtime-contracts.lock.json`](config/sno-trial-dependency-runtime-contracts.lock.json).
Its five contracts bind the current candidate, dependency admission, and
operator-input contract while requiring restricted-v2, arbitrary UID,
read-only roots, TLS/authentication, default-deny networking, persistent
single replicas, no runtime model download, and fail-closed degradation.
They emit no Kubernetes objects and remain blocked on artifact, Secret/TLS,
storage-class, mirror, dry-run, and live-connectivity evidence. The candidate
will retain its runtime-contract blocker until a new candidate revision binds
this contract set and forces a fresh product-artifact replay. Its canonical
digest is
`sha256:f94c20abad9070ca1e1ca0f5e232bc4e1e6805783bd3088ef337608f6df8a0c9`;
all production, HA, campaign, certification, and SLA claims remain false.

The remaining source artifacts are now selected in
[`config/sno-trial-dependency-artifacts.lock.json`](config/sno-trial-dependency-artifacts.lock.json):
Valkey 9.1.0, the linux/amd64 llama.cpp `b10143` server manifest, and Qwen2.5
0.5B Instruct Q4_K_M at its immutable Hugging Face revision, byte count, and
SHA-256 digest. The model must be operator-prestaged on a read-only PVC;
runtime download is prohibited. Validate the strict derivation from the
dependency BOM and runtime contracts with:

```bash
make validate-sno-trial-dependency-artifacts
```

Artifact selection now feeds the inactive Kubernetes candidate in
[`gitops/dependencies/candidates/sno-trial`](gitops/dependencies/candidates/sno-trial).
It renders one restricted single-replica StatefulSet each for Valkey and the
CPU model backend, their headless Services, dedicated tokenless service
accounts, restricted namespaces, and exact default-deny/allowlist policies.
The model is mounted from an operator-prestaged read-only PVC and the
containers use the exact artifact-set images and startup arguments. Validate
the source and render contract with:

```bash
make validate-sno-trial-dependency-manifests
```

This closes manifest authoring only. The candidate uses a conspicuous
unresolved storage-class identifier and references operator-owned
authentication/TLS Secrets and model PVC without creating them. It is absent
from the active dependency Kustomization and emits no Argo CD Application.
Upstream review, destination admission and signing, input materialization,
live allocatable capacity, workload-candidate rebinding, server-side dry-run,
and connectivity remain blocked. Neither the artifact set nor this manifest
candidate changes the current product replay lineage or authorizes apply.

Red Hat documents GCP x86_64 as a supported SNO cloud target and requires one
control-plane replica, zero compute replicas, OVN-Kubernetes, at least 8 vCPU,
and at least 120 GB storage. The trial profile deliberately uses 8 vCPU and
150 GB. This establishes a supported installation shape, not production
certification.

## Locked topology

- GCP `europe-west1`, zones `b`, `c`, and `d`.
- Separate target and services/evidence projects with private VPC peering.
- Services-project public delegation zone plus one-way private DNS peering to
  the installer-owned OpenShift namespace.
- Private self-managed OpenShift `4.20.27`, OVN-Kubernetes, three
  `n2-standard-4` control-plane nodes, and three `n2-standard-8` workers.
- Private regional GKE dependency plane with three non-preemptible
  `n2-standard-8` nodes.
- Private API/routes, IAP administration, internal image mirror, default-deny
  workloads, and allowlisted egress.
- CMEK evidence custody, 400-day locked signed-report retention, and 90-day
  restricted raw-artifact retention.
- GitOps/Argo CD owns rollout. Orchestra emits recommendations only.

The full machine-readable topology contract is
[`config/lab.lock.json`](config/lab.lock.json). It deliberately contains no
product versions. The independently digested
[`config/cross-plane-release-set.lock.json`](config/cross-plane-release-set.lock.json)
binds the platform, runtime, model plane, charts, and certification runner.
Every campaign binds both digests so an artifact update cannot masquerade as a
topology change or combine evidence from different release sets.

The current canonical release-set digest is
`sha256:4f571fade2a1566a53d797c82561f30292734fcfcc75b23667dc08007ee8b6fe`.
It records published artifacts only; it is not deployment, drill, soak, or
verification evidence.

The isolated SNO lane does not rewrite that production lineage. Its v2 product
artifact set is independently digested in
[`config/sno-trial-product-artifacts.lock.json`](config/sno-trial-product-artifacts.lock.json).
It binds four workload images across the platform
`platform-v0.1.0-rc.11`, runtime `v0.18.7`, and model-plane `v0.1.11`
releases. The platform entry binds both `prometa-ubi` and the
`prometa-tools-ubi` migration image from the same signed release manifest.
Charts, exact source revisions, exact publication attempts, and source-only
SNO values are also bound for read-only registry replay. Every artifact binds
its first successful publication attempt. Runtime `v0.18.7` also binds the
supported Cosign v3 publisher used by the independent replay. The artifact-set
digest is
`sha256:865f1a9b6112da2594856c40405e2bbe630b0e524896937d1b12b7d5196d2948`.
The replay uses two separate environment credentials: a classic token limited
to package-read access across the locked GHCR namespaces and a fine-grained
token limited to Actions-read plus required metadata on the private platform
source repository. Exact-main run `30211883723` completed on 2026-07-26
against verifier revision
`985cb37de283193a24776dfe840ab240d34a929a`, with payload-free report digest
`sha256:7fe8801345099fa1ad1073cdfdae7204f6aa3f577474a462200c1a5f7b7eb359`.
That report remains valid evidence for the previous artifact-set digest only.
Exact-main run `30293130839` replayed the current four-image set from revision
`2350e41cb0db00b96f70cc4d5f9c9c1b09cd17ee`; artifact `8663575783`
contains payload-free report digest
`sha256:e67081bf9ee0d0402d97d23be4b646d059d5fa3e0c30b9ad8e53209157a15615`.
Admission policy `orchestra-sno-trial-product-admission-2026-07-28.3`
binds only that replay and is current. The value-free operator-input contract
now locks 14 Secret references, three CA ConfigMaps, their required key names,
and the three rendered-manifest bindings; no live input observation exists.
Destination mirror and live-cluster pulls, populated operator inputs, a fresh
server-side dry run, and provider readiness remain absent; activation and
every certifying claim remain false.

The independently locked dependency BOM digest is
`sha256:fabec47064381d067ca759ba99c47470cc66628ecaacd2e0521f50bb29aad5dc`.
It locks eleven upstream chart packages and accounts for every declared
dependency, while keeping activation blocked until image-level mirror intake,
Secret references, and unresolved provider decisions are closed.

The dependency admission digest is
`sha256:fc1f22817a5959e18d3f4493f199bda61b30cea441929ee321b531402e846def`.
It locks eleven exact source image indexes and linux/amd64 manifests, the
Barman Cloud release manifest, and service contracts for PostgreSQL,
ClickHouse/Keeper, JetStream, Vault, and External Secrets. Every source
signature, destination mirror, lab signature, live identity, backup target,
dry run, and approval remains blocked. Source resolution is not mirror
admission.

The bounded source-verification digest is
`sha256:cbfaa95d09e7a9ca1812028ba13f21c40846c3c91b32424d1e834eab6ab69f89`.
It records exact keyless verification for three subjects and explicit
signature absence for eight subjects during a seven-day developer-workstation
observation. The latter require reviewed exceptions, and all eleven require a
signed certification-runner replay before source admission. Its empty mirror
intake digest is
`sha256:fe357261b272cd8fb4d6917e55453b613967fe5557616550c49591d035a5fc21`.
No destination, receipt, lab signature, pull proof, or approval is populated.

The unsigned-source risk-policy digest is
`sha256:b7ea9ab33854715e24eae2cb90fdc8ca8c8058df55f9b038f5856cb4a5c513c4`.
It requires the release-set-bound signed runner, exact Trivy and Syft versions,
frozen vulnerability databases, Cloud KMS detached collection evidence, and
SPDX inventory. Its preflight-only lane verifies the exact release, runner,
toolchain, scanner versions, source window, and an ephemeral Cloud KMS signing
round trip before downloading scanner databases; it publishes no collection
artifact and grants no authorization. The policy blocks critical, high, and
unknown-severity findings, requires human licence and risk review, and enforces
two independent approval roles with a maximum 30-day exception lifetime. The
empty signature-exception intake digest is
`sha256:2231cf7c2f2dce5c1b35f402cdd193ce4268e1726f7ab3b27f3fd23b7bb9b70f`.
It contains all eight unsigned subjects but zero evidence bundles and zero
approvals. Even a fully approved exception set cannot authorize source
admission or mirroring without the separate signed-runner source replay and
admission aggregate.

The dependency-risk preflight authority digest is
`sha256:746304a45ba15385d629ee3ef5c7618e36980524ca4f73e024007e958925b679`.
It declares a separate exact-main GitHub WIF provider, a collector service
account with no project, evidence-bucket, or artifact-mirror role, and a
dedicated `EC_SIGN_P256_SHA256` Cloud KMS key whose only collector grant is
key-level `roles/cloudkms.signerVerifier`. The protected workflow obtains a
short-lived GitHub App token for the exact platform release and package,
rechecks the current environment approval, and invokes only the collector's
no-evidence `--preflight-only` path. No Terraform has been applied and no live
identity, KMS round trip, preflight, collection, admission, mirror, activation,
campaign, or verification state is claimed.

The dependency-risk collection authority digest is
`sha256:120cb99523e13116473548ee6e34e1b0fd7f2fdce9ea98b2d22861697ab1c4b0`.
It declares a second exact-main WIF provider and protected environment for the
full collection, plus a distinct `orchestra-risk-collector` identity. That
identity receives only key-level `roles/cloudkms.signerVerifier` and
create-only `roles/storage.objectCreator` on the restricted raw-evidence
bucket. The workflow repeats the no-evidence preflight, runs and verifies the
full collection in the same approved attempt, then uploads a deterministic raw
archive, KMS public key, payload-free custody statement, and detached custody
signature with generation-zero preconditions. The signature is uploaded last
as the completion marker. The collector cannot read or delete raw objects,
write signed evidence, mirror artifacts, or record object generations. The
Terraform and workflow remain source declarations: no live collection, raw
publication, independent custody verification, source admission, activation,
campaign evidence, or reference-profile verification is claimed.

The independent dependency-risk custody-verification authority digest is
`sha256:294e544928d032046a4b8a9cec85b067f9ce5b36982597f56029d6f349151eaf`.
It declares a third exact-main WIF provider and protected environment, a
distinct `orchestra-custody-verifier` identity, and prefix-scoped managed-folder
roles. The verifier can list and read only `dependency-risk/`, create but not
read or delete reports under `dependency-risk-custody/`, view the collection
public key, and sign with a separate custody-verification key. The protected
workflow pins all four raw objects by generation and metageneration, requires
the detached signature to be the newest completion marker, safely extracts the
bounded archive, replays the complete collection verifier, and uploads a strict
signed custody report with its detached signature last. A bound offline CLI
replays that report signature against an independently expected public-key
digest before publication and for later consumers. The verifier has no
source-admission, mirror, activation, or campaign authority. Terraform,
environment protection, and workflow execution remain source declarations: no
live identity, raw-custody verification, report publication, or downstream
authorization is claimed.

The review-bound foundation-apply authority digest is
`sha256:6d658bc8cba37642dbca5bf7370c00dced6b1f312e71ad2c4f531101f2ab4d7d`.
It separates the read-only planner, create-only `orchestra-plan-packager`,
group-only private plan reviewers, and the exact-workflow apply executor. Plan
packages and receipts use distinct asymmetric KMS keys, immutable
generation-zero prefixes, and detached signatures uploaded last. Apply accepts
only a generation-pinned, signature-verified, non-destructive saved plan from
the exact current main revision, acquires the Terraform state lock, and checks
state serial/lineage. The executor retains broad foundation and Artifact
Registry authority, which the contract records honestly; the workflow forbids
mirror commands but this is not an IAM denial. Terraform and workflows are
source declarations only: no package, apply, receipt, independent observation,
campaign evidence, or profile verification is claimed.

The independent foundation-observation authority digest is
`sha256:6506655bee4b63e6636bb47211aceebf03ef0603aae5f398cd0c5fd7d3b9a524`.
It declares the exact-main `foundation-observation` provider and a dedicated
`orchestra-foundation-observer` identity. The observer has read-only provider
roles, a metadata-only storage custom role, managed-folder reads for state,
plans, and receipts, create-only report access, public-key access to prior
keys, and a separate observation-signing key. Its workflow verifies the live
direct observer boundary including ancestor IAM, pins and verifies the plan
and receipt, requires current state to match the receipt, and runs only a
lock-free refresh-only Terraform plan. Drift, resource-identity mismatch,
state-generation change, direct role expansion, or signature substitution
fails closed. Group-transitive IAM remains an independently reviewed live
prerequisite. This is source declaration and fixture proof only: no observer
identity, protected environment, provider refresh, signed report, campaign
evidence, or profile verification exists yet.

The operator control-plane readiness policy digest is
`sha256:c344bba86571ab5cf347c8c70e0745c6c22afd7cc9fd930f91f7cf5b15db0ec4`.
Its collector checks all six protected environment contracts and uses the
GitHub App private key to require exactly one App installation, mint an
unrestricted installation token, enumerate the real repository set, and revoke
the token. The report contains only
digests, expires after one hour, and cannot authorize provisioning or campaign
evidence. No protected environment, App installation, credential, or live
report is created by this source declaration.

The lab service publication policy digest is
`sha256:61e1af0f3c2874df6ec8077e3ac03f2a036197e0998d224a7cafea8c5130b8e1`.
It binds both service source/package identities, exact GHCR repositories, the
single AMD64 OCI index shape, an immutable BuildKit SBOM generator, maximum
provenance, and the exact main-branch Sigstore workflow identity. A successful
run can assert only that the two source artifacts were published and their
digests, embedded attestations, and keyless signatures were replayed. It cannot
assert a certification risk scan, Harbor mirror, RHTAS admission, GitOps
reference, deployment, campaign evidence, or profile verification. The
exact workflow succeeded as run `30002879030` for release
`lab-services-v0.1.0-rc.1` at revision
`a54ca86f2c7e4746b85110bb29052f836401ec9c`; its locally validated
observation digest is
`sha256:36fe99667ea6fe4ea8d019b28e10dc899804c4ebb7d8485149fbec83ba40d4bf`.

The lab service publication replay policy digest is
`sha256:0607daa157b5a0a49284305d8216d6ecf98019eb25a5d48032c26bc09e050317`.
Its separate exact-main workflow can read the prior Actions artifact, source,
and private GHCR packages. It has no package-write, OIDC, image-signing, GitOps,
or deployment authority. A valid statement replays the prior run/artifact,
source trees, OCI indexes, embedded attestations, and keyless signatures while
keeping human-review, admission, deployment, campaign, and certification
claims false. Run `30006907539` completed that replay from exact-main revision
`79186ace0d8bfdc2ad378bff3be96c3653f24aa4`. Its locally validated statement
digest is
`sha256:9480ed84fc9ea802f7fb6aeaf73912788b2764598685d269145cd642fcb13ab9`.

Each GitHub WIF provider maps a provider-prefixed numeric
repository/environment subject, and each service-account impersonation grant
names that single subject. Repository-wide principal sets are rejected, so the
foundation planner/packager, apply executor, foundation observer, preflight
signer, collector, and custody verifier cannot cross-assume one another merely
because they share a workload identity pool.

The source-only dependency GitOps candidate digest is
`sha256:6f7a051f0dcf3c46ecbde68efb5e21369d42035ec72cca2f334c652c37600790`.
It projects five exact chart/image contracts into offline values for
CloudNativePG, the ClickHouse operator, JetStream, Vault, and External Secrets,
plus six blocked service-resource plans. CI derives the chart and image
bindings from the existing BOM and admission contracts, checks the values
semantically, and proves the candidate is absent from the active
Kustomization. It contains no Argo Application or destination mirror reference
and cannot be applied. Ten services, including cert-manager and
Valkey/Sentinel, remain unresolved.

Lab-owned service admission is locked separately in
[`config/lab-services.lock.json`](config/lab-services.lock.json). The durable
release-validation receiver and synthetic tenant kit are now `published`: the
lock binds the exact `rc.1` release, source revision, source-tree digests, GHCR
index and manifest digests, embedded SBOM/provenance descriptors, signature
subjects, publication observation, and separate replay statement. They remain
unmirrored, unadmitted, absent from GitOps, undeployed, and outside campaign
evidence. The canonical inventory digest is
`sha256:bcb33ebb8ff8d539780ed4fdfb728196744832491e5aa61ad714613d968a290e`.

## Layout

| Path | Ownership |
|---|---|
| `config/` | Independently locked topology, release set, certification contract intake, dependency BOM/admission/GitOps candidate, source observation, risk policy, empty exception/mirror intakes, prerequisite gates, prerequisite observation policy, operator control-plane readiness policy, lab service publication/replay policies, and published service inventory |
| `contracts/platform/` | Exact platform-owned policy, schema bundle, and fixture bytes vendored from the pinned release revision; not campaign evidence |
| `infra/terraform/bootstrap/` | Projects, APIs, state custody, KMS, WIF bootstrap |
| `infra/terraform/foundation/` | Private networks, GKE, VPC/DNS peering, public delegation zone, evidence buckets, bastion, probes |
| `infra/terraform/sno-trial/` | Isolated non-certifying trial project, APIs, `$75` budget, and public delegation zone |
| `infra/openshift/` | Secret-free OpenShift installer template |
| `gitops/` | Active cluster declarations plus a non-activatable dependency values candidate; no generated Secret values |
| `policies/` | Repository and deployment policy inputs |
| `schemas/` | Strict additive JSON contracts for SNO readiness, network-hygiene, operator-input and dependency-manifest diagnostics, prerequisite observations, operator control-plane readiness, lab service publication, foundation plan/apply/observation custody, signed collection statements, scan manifests, risk evidence, and signature exceptions |
| `scripts/` | Local/CI validation and rendering tools |
| `services/` | Lab-owned synthetic and GitOps integration services; none are platform runtime authority |
| `docs/runbooks/` | Human-controlled operational procedures |

The current proof-state matrix is maintained in
[`docs/implementation-status.md`](docs/implementation-status.md); the security
boundaries and residual risks are in
[`docs/threat-model.md`](docs/threat-model.md).

## Safe local checks

```bash
make validate
make test
make verify-platform-contract-source PLATFORM_REPOSITORY=/absolute/path/to/agent-hook-v2
make verify-dependency-sources
make terraform-fmt
```

`make validate` checks the topology, immutable cross-plane release set,
platform-owned certification contract intake, dependency BOM, fail-closed
dependency admission, bounded signature observation, unsigned-source risk
policy, empty exception intake, empty mirror intake, and source-only dependency
GitOps candidate, plus the staged
prerequisite observation policy and review-bound foundation-apply authority.
It rejects
mutable product tags, missing planes, an unbound runner, changed chart or image
subjects, wildcard signing identities, silently
omitted dependencies, populated approvals, self-review, stale evidence,
overlong exceptions, populated mirror claims, or any attempt to mark the
dependency plane active.
The dependency candidate validator also rejects destination references,
mutable image tags, values drift, path escapes, missing blocked services,
unsafe chart features, generated manifests in the candidate tree, or a
reference from the active Kustomization.
It also renders the product overlay and proves that the Argo Applications use
the matching source revisions, chart digests, mirrored repositories, image
digests, profile, and control-plane boundary. Only ExternalSecret and
cert-manager references may create credential or certificate objects.
The dependency overlay is checked separately and must contain zero
Applications and Secrets while its deny window is in force.

The contract-intake check is self-contained and safe for CI. The separate
`verify-platform-contract-source` target requires an authorized platform
checkout and replays bytes from the exact pinned Git revision; it does not use
working-tree contents. Neither check creates or approves a campaign.

`make verify-dependency-sources` is networked and time-bounded. It re-resolves
the locked image/manifests and reproduces the signature observation, but it
does not approve exceptions or authorize mirroring.

Terraform validation downloads pinned providers but uses no credentials and
does not contact a target project:

```bash
make terraform-validate
```

Render an installer configuration only into the ignored `install-dir/` path:

```bash
python3 scripts/render_install_config.py \
  --values restricted/install-values.json \
  --output install-dir/install-config.yaml
```

The renderer refuses to overwrite files, validates exact topology values, and
does not accept a pull secret in its values file. Pull secret and SSH public
key injection remain an operator step immediately before installer execution.

The SNO trial uses a separate renderer and requires both a valid,
project-bound operator lease and a short-lived aggregate render admission:

```bash
python3 scripts/trial_lease.py create \
  --project-id '<ephemeral-trial-project>' \
  --operator-identity-digest 'sha256:<operator-identity-digest>' \
  --hours 8 \
  --output restricted/trial-leases/current.json

python3 scripts/render_sno_trial_install_config.py \
  --values restricted/sno-trial-install-values.json \
  --lease restricted/trial-leases/current.json \
  --admission restricted/sno-render-<timestamp>.json \
  --output install-dir/trial/install-config.rendered.yaml
```

Create the admission with `make create-sno-trial-render-admission` after
refreshing the provider-readiness, network-hygiene, DNS-delegation, and
operator-path reports. It also binds the verified local toolchain intake and
the active lease. The first four reports and the resulting admission each have
a maximum 15-minute lifetime.

This only authorizes and renders a secret-free input. It neither creates a GCP
project nor permits firewall mutation or runs the installer.

## Delivery boundary

Repository CI proves syntax, topology invariants, strict gate shapes,
secret-exclusion rules, Terraform formatting/validation, and deterministic
installer rendering. The vendored certification inputs prove a pinned contract
intake only. They are not OpenShift deployment or campaign evidence. Live
evidence must be produced by the signed certification runner under the v2
contracts in `prometa-platform` and retained in the configured evidence
bucket.
