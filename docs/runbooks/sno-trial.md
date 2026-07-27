# Cost-bounded OpenShift SNO trial

## Purpose and boundary

This runbook operates the `orchestra-ocp-sno-trial-amd64-v1` engineering
profile. It exists to test real OpenShift installation, product manifests, and
basic integration without funding the six-node OpenShift plus three-node GKE
production reference topology.

The trial is not a smaller certification profile.

| Property | Trial value |
|---|---|
| Target class | `engineering-trial` |
| Certification eligible | No |
| Campaign evidence | No |
| Reference/customer/Red Hat certification | No |
| Production support or SLA | No |
| HA or RPO/RTO proof | No |
| Permitted certification slots | None |

Never copy trial results into an evidence-v2 campaign report. Never change the
production lock, certification policy, active reference GitOps overlays, or
production prerequisite projection to accept this profile.

## Supported shape and cost boundary

Red Hat's OpenShift 4.20 SNO documentation lists Google Cloud x86_64 as a
supported provider. It requires installer-provisioned installation, one
control-plane replica, zero compute replicas, OVN-Kubernetes, at least 8 vCPU,
and at least 120 GB storage:

- <https://docs.redhat.com/en/documentation/openshift_container_platform/4.20/html/installing_on_a_single_node/preparing-to-install-sno>
- <https://docs.redhat.com/en/documentation/openshift_container_platform/4.20/html/installing_on_a_single_node/install-sno-installing-sno>

This profile uses one `n2-standard-8` VM and 150 GB `pd-balanced` storage in
`europe-west1-b`. The installer also creates temporary bootstrap and networking
resources. Actual GCP prices, taxes, network egress, DNS, load balancers,
snapshots, and idle disks remain variable.

The `$75` monthly budget is an alert threshold, not a provider-side hard cap.
Because the authorized Google billing account is denominated in TRY, the
provider-side amount is 3,500 TRY. That is about $74.08 at the TCMB
`ForexSelling` rate of 47.2497 TRY/USD on 2026-07-24 and remains below the
locked USD ceiling. The conversion is bound separately in
`config/sno-trial-billing-execution.lock.json`. A DNS-domain change updates the
canonical profile digest and therefore refreshes its workload and
product-artifact bindings; prior live replay reports remain historical.
The operational limits are:

- GCP budget alerts at 10, 25, 50, 75, 90, and 100 percent.
- No more than 48 active node-hours per month.
- An 8-hour first-session recommendation and a maximum 12-hour lease for each
  install or test session.
- Explicit renewal and explicit teardown.
- Project deletion only after `openshift-install destroy cluster` succeeds or
  an operator has reconciled every installer-owned resource.

## Prerequisites

Do not create a lease until all of these are true:

1. The Red Hat OpenShift Container Platform trial is active.
2. Exact `4.20.27` linux/amd64 installer and client archives pass the official
   checksum.
3. The pull secret is mode `0600` under ignored `restricted/` storage and
   contains `cloud.openshift.com`, `quay.io`, and `registry.redhat.io`.
4. One dedicated, disposable GCP project has billing enabled.
5. Project quota supports a temporary bootstrap VM, one `n2-standard-8`,
   persistent disks, load balancers, forwarding rules, external IPs, and DNS.
6. The project has a 3,500 TRY budget, bound to the `$75` ceiling, with the six
   locked alert thresholds.
7. `ocp-lab.planeon.ai` is available for the `orchestra-trial` cluster DNS
   namespace.
8. A Linux AMD64 administration host has short-lived GCP credentials. The
   downloaded linux binaries do not execute natively on macOS.
9. The operator has recorded the current public source CIDR and a post-install
   API/administration allowlist procedure.

The external API and routes reduce trial infrastructure cost. They are an
explicit security compromise relative to the private production profile.
Authentication is still required, but do not install until source-IP
restriction and teardown responsibility have named owners.

## Acquire and verify the public OpenShift toolchain

The installer and client archives do not require a paid Red Hat account. Fetch
only the exact versioned linux/amd64 names from the public OpenShift mirror;
do not use the unversioned aliases:

```bash
mkdir -p restricted/redhat/4.20.27

curl --fail --show-error --location \
  --output restricted/redhat/4.20.27/sha256sum.txt \
  https://mirror.openshift.com/pub/openshift-v4/clients/ocp/4.20.27/sha256sum.txt

curl --fail --show-error --location \
  --output restricted/redhat/4.20.27/sha256sum.txt.gpg \
  https://mirror.openshift.com/pub/openshift-v4/clients/ocp/4.20.27/sha256sum.txt.gpg

curl --fail --show-error --location \
  --output restricted/redhat/4.20.27/red-hat-release-key-2.asc \
  https://www.redhat.com/security/data/fd431d51.txt

curl --fail --show-error --location --continue-at - \
  --output restricted/redhat/4.20.27/openshift-install-linux-4.20.27.tar.gz \
  https://mirror.openshift.com/pub/openshift-v4/clients/ocp/4.20.27/openshift-install-linux-4.20.27.tar.gz

curl --fail --show-error --location --continue-at - \
  --output restricted/redhat/4.20.27/openshift-client-linux-4.20.27.tar.gz \
  https://mirror.openshift.com/pub/openshift-v4/clients/ocp/4.20.27/openshift-client-linux-4.20.27.tar.gz
```

Inspect the files against the immutable repository lock:

```bash
TOOLCHAIN_ID=sno-toolchain-operator-$(date -u +%Y%m%d%H%M%S).1

make inspect-sno-trial-toolchain \
  ARCHIVE_DIR=restricted/redhat/4.20.27 \
  INTAKE_ID="$TOOLCHAIN_ID" \
  OUTPUT="restricted/$TOOLCHAIN_ID.json"

make verify-sno-trial-toolchain \
  REPORT="restricted/$TOOLCHAIN_ID.json"
```

The verifier imports the exact locked Red Hat release key into a fresh
temporary GnuPG home, requires fingerprint
`567E347AD0044ADE55BA8A5F199E2F91FD431D51`, verifies the signed checksum
payload byte-for-byte, and checks both exact archive sizes and SHA-256 values
plus the complete tar-member shape without extraction. It rejects aliases,
key or signature substitution, signed-payload drift, path traversal, symbolic
links, unexpected members, and digest or size drift.

The result is deliberately not the `openshiftInstaller` prerequisite
observation. The extracted `openshift-install version` plus ELF linux/amd64
identity must still pass in the downstream trusted Linux lane. The Red Hat pull
secret is account-gated and is never stored in this report. Archive inspection
creates no lease and grants no cloud, installation, campaign, or certification
authority.

## Review the inert workload candidate

Before authoring any trial values or dependency manifests, validate the locked
source-only capacity candidate:

```bash
make validate-sno-trial-workload-candidate
```

The candidate assigns one replica each to the platform, runtime host, model
plane, PostgreSQL, ClickHouse, JetStream, Valkey, CPU model backend, and
synthetic tenant kit. It reserves 3 vCPU and 12 GiB for OpenShift/system
services, limits steady workload requests to 3.4 vCPU and 14.375 GiB, allows
only one serial 250m/256 MiB transient operation, and records 48 GiB of
persistent volumes.

Do not render or apply this file. It contains artifact observations and
capacity assumptions, not Kubernetes resources. The production chart profiles
cannot be reused because their replica and availability contracts differ.
Before a future activation review, dependency owners must define direct
single-instance runtime contracts, and operators must resolve immutable Valkey
and CPU model-backend artifacts by digest. The three product planes now expose
source-only SNO values, but their registry replay, human admission, Secret/TLS
references, destination pull proofs, live allocatable capacity, calibration,
and OpenShift server-side dry runs must still pass.

After a live cluster exists, compare the candidate reserve against
`oc describe node` allocatable capacity and measured idle system usage. Any
resource, image, mode, storage, or blocker change requires a new candidate ID
and digest. The current candidate always remains blocked and cannot produce
campaign evidence.

## Replay the published three-plane trial artifacts

The platform, runtime, and model-plane owners publish independent UBI images
and charts with source-only SNO values contracts. Their exact releases,
sources, linux/amd64 image manifests, chart packages, and publication runs are
locked in
`config/sno-trial-product-artifacts.lock.json` without changing the production
cross-plane release set:

```bash
make validate-sno-trial-product-artifacts
```

Create the `sno-trial-product-artifact-replay` GitHub environment and populate
these two independent secrets:

- `SNO_ARTIFACT_READ_TOKEN`: a classic token dedicated to this replay and
  limited to package-read access across the locked GHCR namespaces;
- `SNO_SOURCE_RUN_READ_TOKEN`: a fine-grained token limited to Actions-read
  plus required metadata on only the private `caglarsubas/agent-hook-v2`
  repository.

Neither credential receives package-write, source-write, signing, OIDC,
deployment, or cloud authority. The environment and secret values are operator
state and never enter Git.

After the lock is merged to `main`, dispatch `SNO trial product artifact
replay` with the exact reviewed main SHA. The workflow requires each exact
successful tag publication attempt pinned by the lock. Platform and model
artifacts bind attempt 1; runtime binds attempt 1 of run `30171938726` after
publication and verification with the supported Cosign v3 toolchain. The
workflow verifies every UBI image and Helm chart
keyless signature and CycloneDX attestation, checks the exact linux/amd64 child
manifest, pulls each chart package, and validates both package and SNO values
member digests. Its downloadable report contains no registry credentials,
signature payloads, SBOM payloads, Secrets, or customer data.

Exact-main run `30211883723` completed on 2026-07-26 against verifier revision
`985cb37de283193a24776dfe840ab240d34a929a`. Its payload-free report digest is
`sha256:7fe8801345099fa1ad1073cdfdae7204f6aa3f577474a462200c1a5f7b7eb359`.
Artifact `8634695656` is named
`sno-trial-product-artifact-replay-30211883723-1` and expires on
2026-08-09. The downloaded report verifies against the current Planeon-bound
artifact and workload locks. It remains a time-bounded GitHub Actions artifact
and does not by itself record human admission.

A successful replay proves only that the three locked artifacts match their
sources and signed publications. An operator must review and accept the
payload-free report in a later admission step; the workflow cannot mutate the
lock or admit an artifact. Activation remains blocked while destination mirror
and live-cluster pulls, operator Secret/CA inputs, OpenShift server-side dry
runs, and provider readiness are absent. It is not installation, campaign,
reference-profile, customer, Red Hat, or SLA evidence.

### Independently admit the replay

The source contract for that later review is locked in
`config/sno-trial-product-artifact-admission-policy.lock.json`; its output
schema is
`schemas/sno-trial-product-artifact-admission-v1.schema.json`. Policy
`orchestra-sno-trial-product-admission-2026-07-27.1` binds only replay run
`30211883723`, artifact ID `8634695656`, and report digest
`sha256:7fe8801345099fa1ad1073cdfdae7204f6aa3f577474a462200c1a5f7b7eb359`.
Its replay state is `current`; the five deployment and provider blockers remain
unchanged.

Before dispatching `SNO trial product artifact admission`, configure the
`sno-trial-product-artifact-admission` GitHub environment with:

- one non-owner `User` reviewer;
- required-reviewer protection and prevention of self-review;
- a custom deployment-branch policy allowing only `main`;
- no environment Secrets, OIDC, cloud credentials, registry credentials, or
  deployment authority.

The repository owner and workflow initiator cannot approve the run. A rerun
cannot reuse an approval. The workflow downloads only the exact immutable
replay artifact, validates it again, obtains the environment and approval event
through the read-only GitHub API, and emits identity digests rather than user
names, comments, tokens, or API payloads.

The replay must be reviewed within 14 days. The workflow-issued admission
expires after 14 days and can never exceed the policy lifetime maximum of 30
days. It accepts only the source replay and removes only
`product-artifact-replay-review-missing`. Destination mirror and live-cluster
pull verification, Secret/CA inputs, server-side dry run, and provider
readiness remain blocking. The output grants no cloud mutation, deployment,
campaign, certification, production-support, Red Hat, or SLA authority.

## Record the Red Hat trial without identity payload

The statement builder reads a mode-`0600` account identity file and the Red Hat
trial confirmation image, hashes both, and writes only digests and dates. It
does not verify or activate the production entitlement gate.

```bash
python3 scripts/build_red_hat_entitlement_statement.py \
  --account-identity-file restricted/red-hat-account-identity.txt \
  --issuer-evidence restricted/red-hat-trial-confirmation.png \
  --observed-at '<UTC trial observation>' \
  --expires-at '<UTC trial expiry>' \
  --output restricted/red-hat-entitlement.json
```

The exact expiry must come from Red Hat's trial UI or confirmation email. Do
not infer it by adding 60 days to a screenshot. An independent reviewer must
inspect the restricted inputs before any production prerequisite gate can be
projected as verified.

## Create the disposable GCP foundation

The isolated Terraform module creates only the disposable project, required
APIs, project-scoped budget, and public delegation zone. It does not create a
cluster, network, service-account key, parent-domain delegation, or evidence
claim.

Use a globally unique project ID and short-lived user access token. Keep state,
plans, and rendered outputs under ignored `restricted/` storage:

Before planning, inspect every project currently linked to the chosen billing
account and confirm that the account can accept one more association:

```bash
gcloud billing projects list \
  --billing-account="$(
    gcloud billing accounts list \
      --filter='displayName=agentic-hook-billing AND open=true' \
      --format='value(name)'
  )"
```

The list is an inventory, not proof of available quota. A billing account can
still enforce a lower undisclosed project-association limit. If GCP reports
`Cloud billing quota exceeded`, stop; do not move an existing project or use a
different billing account implicitly.

```bash
mkdir -p restricted/terraform/sno-trial

export GOOGLE_OAUTH_ACCESS_TOKEN="$(gcloud auth print-access-token)"
export TF_VAR_billing_account="$(
  gcloud billing accounts list \
    --filter='displayName=agentic-hook-billing AND open=true' \
    --format='value(name)'
)"
export TF_VAR_project_id='<globally-unique-disposable-project-id>'
# Existing prometa-orch-sno-499235 migration only; omit for fresh projects.
export TF_VAR_retain_legacy_prometa_zone=true

terraform -chdir=infra/terraform/sno-trial init -input=false
terraform -chdir=infra/terraform/sno-trial plan \
  -out=../../../restricted/terraform/sno-trial/foundation.tfplan
terraform -chdir=infra/terraform/sno-trial show -no-color \
  ../../../restricted/terraform/sno-trial/foundation.tfplan \
  > restricted/terraform/sno-trial/foundation.txt
```

Review the plan before applying it. It must create one project, the locked API
set, one project-filtered 3,500 TRY budget (the locked `$75` ceiling) with six
thresholds, and one public
`ocp-lab.planeon.ai.` zone. It must not create compute instances, disks, load
balancers, networks, credentials, or production-reference resources.

For the existing `prometa-orch-sno-499235` migration only, set
`TF_VAR_retain_legacy_prometa_zone=true`. The reviewed plan must move the
existing zone's Terraform address without changing it, create the Planeon zone,
and show zero updates and zero destroys. Fresh projects leave this variable
false and never create the legacy Prometa zone.

Apply exactly the reviewed plan, capture only restricted output, and remove the
short-lived environment values:

```bash
terraform -chdir=infra/terraform/sno-trial apply \
  ../../../restricted/terraform/sno-trial/foundation.tfplan
terraform -chdir=infra/terraform/sno-trial output -json \
  > restricted/terraform/sno-trial/foundation-output.json

unset GOOGLE_OAUTH_ACCESS_TOKEN TF_VAR_billing_account TF_VAR_project_id \
  TF_VAR_retain_legacy_prometa_zone
```

If project creation succeeds but billing association fails, Terraform can
retain the unbilled project shell in state. Verify that partial state before
doing anything else:

```bash
terraform -chdir=infra/terraform/sno-trial state list
gcloud projects describe '<disposable-project-id>'
gcloud billing projects describe '<disposable-project-id>'
```

An unbilled shell with no enabled trial APIs, budget, DNS zone, or workloads
incurs no trial infrastructure spend. Keep it only while requesting additional
billing-project quota. After the quota is granted, discard the old saved plan,
refresh credentials, generate and review a new plan, and apply that new plan.
Alternatively, delete the shell through the explicit project-deletion path.

While the provider review is pending, collect a payload-free diagnostic instead
of repeatedly planning or applying:

```bash
READINESS_ID=sno-readiness-operator-$(date -u +%Y%m%d%H%M%S).1

make observe-sno-trial-readiness \
  PROJECT_ID=prometa-orch-sno-499235 \
  QUOTA_REQUEST_STATUS=pending \
  ASSESSMENT_ID="$READINESS_ID" \
  OUTPUT="restricted/$READINESS_ID.json"

make verify-sno-trial-readiness \
  REPORT="restricted/$READINESS_ID.json"
```

The collector executes exactly three read-only operations: project describe,
billing-project describe, and enabled-services list. It reduces the project
number to a digest, drops billing-account identity and raw provider output, and
binds the locked SNO profile plus the exact three-plane release set. Even when
the quota status is `approved`, the report cannot authorize mutation, create a
lease, produce campaign evidence, or reuse the old Terraform plan.
The quota status is an operator-declared input because the three read-only
commands do not observe Google's support-request workflow; independently check
the approval message before changing it to `approved`.

After Google approves the request, run the collector again with
`QUOTA_REQUEST_STATUS=approved`. A valid result with detached billing reports
`READY_FOR_FRESH_PLAN`; this means only that the old plan must be discarded and
a new plan may enter operator review. It does not mean the plan was approved or
applied. After applying the newly reviewed foundation plan, run the diagnostic
again and separately verify the budget, DNS delegation, source CIDR, installer,
pull secret, and active operator lease before creating any compute resource.

For the Google quota request, request only one additional project, select
`Paid Services`, and choose `Associating more projects with my billing
account`. Explain that the project is a temporary single-node OpenShift
engineering trial, has a `$75` alert ceiling, starts with no compute resources,
and is destroyed after the bounded test window.

The module supports projects outside a GCP organization because this
engineering account currently has no visible organization parent. That is a
trial-only concession and does not alter the production profile's organization
and folder requirements.

The budget is alerting, not a hard provider cap. The profile lease and explicit
teardown remain the operational controls. `allow_project_delete` defaults to
false so an ordinary Terraform destroy cannot delete the project before the
OpenShift installer and residual-resource checks have completed.

## Current live checkpoint

The 2026-07-26 bounded foundation apply for `prometa-orch-sno-499235` is
complete. The reviewed remainder created only the project-scoped 3,500 TRY
budget; the earlier partial apply had already attached billing, enabled the
locked APIs, and created the now-legacy public managed zone. Independent API
readback and a post-apply Terraform refresh verified:

- Billing enabled and all 11 required APIs active.
- One 3,500 TRY budget, six thresholds, and the exact project-number filter.
- The unused `ocp-lab.prometa.ai.` Cloud DNS zone with four generated
  nameservers.
- The active `ocp-lab.planeon.ai.` Cloud DNS zone with four generated
  nameservers.
- No Terraform drift and, at that historical checkpoint, no compute, cluster,
  workload, or Secret resources.

The active Planeon zone was applied from an exact-main plan with one add, zero
changes, and zero destroys. The legacy zone moved in Terraform state without a
provider mutation. Independent readback observed both zones, and a post-apply
plan reported no drift. Pre-install readiness report
`sno-readiness-operator-20260726174421.1` has report digest
`sha256:13ba6f6fb93e524b0dcb28d653ff9ab52de1228fd0a2d94db8bdd66511cd56dc`
and remains `DOWNSTREAM_VERIFICATION_REQUIRED`.

Those downstream gates were later satisfied. DNS report
`sno-dns-operator-20260727141303.1` observed the exact parent delegation, and
operator-path report `sno-operator-operator-20260727141147.1` observed the
Linux AMD64 host, single attached operator identity, host-scoped source CIDR,
target project, and exact `4.20.27` tools. Render admission
`sno-render-operator-20260727141325.1` then issued a short-lived
`READY_TO_RENDER` decision bound to an active project/operator lease. These
reports are point-in-time gates and must be refreshed for a new install.

The first network-hygiene observation found a GCP-created default auto-mode
VPC, 42 subnetworks, and four default firewall rules, including three enabled
internet-ingress rules. The initial payload-free report is
`sno-network-operator-20260726141208.1`, with digest
`sha256:f1e011e6b2a9da8c778a64be185e39c0d92daefc9c09b2eff37b05c677c3242e`.
An immediate dependency inventory found no instances, instance groups,
addresses, forwarding rules, routers, VPN gateways, backend services, network
endpoint groups, or peerings. The bounded operator cleanup removed exactly the
four default firewall rules, the auto-created internet route, and the unused
`default` VPC.

Fresh report `sno-network-operator-20260726174421.1` is `CLEAN`,
has report digest
`sha256:fb074a14e51f012c750954f766bcd1d09bf05d8f10a40352fee4f8235f870380`,
binds the current Planeon profile, and observes zero networks, subnetworks,
firewall rules, and internet-ingress rules. Re-run the payload-free assessment
before relying on this point-in-time observation:

```bash
NETWORK_ID=sno-network-operator-$(date -u +%Y%m%d%H%M%S).1

make observe-sno-trial-network-hygiene \
  PROJECT_ID=prometa-orch-sno-499235 \
  ASSESSMENT_ID="$NETWORK_ID" \
  OUTPUT="restricted/$NETWORK_ID.json"

make verify-sno-trial-network-hygiene \
  REPORT="restricted/$NETWORK_ID.json"
```

The report stores counts and canonical inventory digests, not raw firewall
sources or provider responses. It never authorizes cleanup or installation.
Proceed only while a fresh report remains `CLEAN`.

The clean installer state completed OpenShift `4.20.27` on 2026-07-27. Do not
reuse an installer metadata directory after `create cluster` has started; run
the exact installer destroy operation, verify cleanup, and render a fresh
directory for a retry. The completed cluster had one ready schedulable
`n2-standard-8` control-plane/worker node, zero worker Machines,
`SingleReplica` topology, `Manual` credentials with the locked workload
identity issuer, two CSI storage classes, a host-scoped API firewall, a
reachable console, no bootstrap instance, and 34 of 34 healthy cluster
operators.

Exact-main live observation `sno-cluster-main-20260727160232.1`, generated
from commit `dffb6931bc5d656fc38d6e84e07f65fbb600998a`, has report digest
`sha256:440b40b3e9b173ebe3c8ddba6020406b4a9651b3931a11c1ffd3ffcc88ae21c6`
and status `TRIAL_CLUSTER_OBSERVED`. It is payload-free and read-only. Product
workloads were never deployed. Exact-main cost/dry-run checkpoints and the
later clean teardown are recorded below.

## Delegate the trial DNS zone

Read the generated nameservers from the restricted Terraform output and add
four DNS-only `NS` records for host `ocp-lab` in the Cloudflare-hosted
`planeon.ai` parent. Do not modify `www.planeon.ai`, the apex nameservers, or
website records. Do not install until an external authoritative lookup returns
the complete generated NS set. After the operator reports that the parent
records are complete, create and verify a fresh read-only observation:

```bash
DNS_ID=sno-dns-operator-$(date -u +%Y%m%d%H%M%S).1

make observe-sno-trial-dns-delegation \
  PROJECT_ID=prometa-orch-sno-499235 \
  ASSESSMENT_ID="$DNS_ID" \
  OUTPUT="restricted/$DNS_ID.json"

make verify-sno-trial-dns-delegation \
  REPORT="restricted/$DNS_ID.json"
```

The collector runs only `gcloud dns managed-zones describe` and `dig NS`.
Reports store counts and canonical set digests, not raw provider responses or
nameserver values. `WAITING_DELEGATION` means the authoritative answer is
empty; `BLOCKED` means the managed-zone identity or nameserver sets do not
match; `DELEGATION_OBSERVED` means the public answer exactly matches all four
Cloud DNS nameservers.

The Terraform output proves only that the managed zone exists, and
`DELEGATION_OBSERVED` proves only the point-in-time public delegation. The
report always keeps DNS mutation, cloud mutation, installation, campaign, and
certification authority false. Source CIDR, administration path, and operator
lease remain separate prerequisites.

## Observe the administration path and source CIDR

Perform this step on the Linux AMD64 host that would run the installer, not on
macOS. Extract the already verified `openshift-install` and `oc` binaries under
ignored `restricted/redhat/4.20.27/` storage. Record exactly one current public
host network in a private input file:

```bash
install -d -m 0700 restricted/operator
printf '%s\n' '<public-ip>/32' > restricted/operator/source-cidr.txt
chmod 0600 restricted/operator/source-cidr.txt
```

Use `/128` for a single public IPv6 address. Wider ranges, private addresses,
and mode-permissive or symlinked files fail closed. Then collect and verify:

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

The collector runs only local version commands and read-only `gcloud auth
list` / `gcloud config get-value project`. It requires Linux AMD64, exactly one
active identity, the exact project, exact `4.20.27` tools, and a public
host-scoped CIDR. The report stores only identity-set, project, and CIDR
digests. `OPERATOR_PATH_OBSERVED` does not change any firewall and does not
authorize installation. Re-run it if the host, identity, project, tools, or
public address changes.

## Create and verify an operator lease

Create a lease immediately before rendering:

```bash
python3 scripts/trial_lease.py create \
  --project-id '<ephemeral-trial-project>' \
  --operator-identity-digest 'sha256:<operator-identity-digest>' \
  --hours 8 \
  --output restricted/trial-leases/current.json

python3 scripts/trial_lease.py verify \
  --lease restricted/trial-leases/current.json \
  --project-id '<ephemeral-trial-project>'
```

The lease binds the exact trial-profile digest, project, operator digest,
budget, active-hour ceiling, and expiry. An expired, not-yet-active, modified,
or cross-project lease fails closed. The lease is one aggregate-admission
input, not install authority or an automatic shutdown mechanism.

## Create a short-lived render admission

Refresh the provider-readiness, network-hygiene, DNS-delegation, and
operator-path reports immediately before rendering. The first four reports
must be no older than 15 minutes. The signed local toolchain intake may be no
older than 30 days. Then bind all five reports to the active lease:

```bash
ADMISSION_ID=sno-render-operator-$(date -u +%Y%m%d%H%M%S).1

make create-sno-trial-render-admission \
  READINESS=restricted/<fresh-readiness-report>.json \
  NETWORK=restricted/<fresh-network-report>.json \
  DNS=restricted/<fresh-dns-report>.json \
  OPERATOR_PATH=restricted/<fresh-operator-path-report>.json \
  TOOLCHAIN=restricted/<verified-toolchain-report>.json \
  LEASE=restricted/trial-leases/current.json \
  PROJECT_ID=prometa-orch-sno-499235 \
  ADMISSION_ID="$ADMISSION_ID" \
  OUTPUT="restricted/$ADMISSION_ID.json"

make verify-sno-trial-render-admission \
  ADMISSION="restricted/$ADMISSION_ID.json" \
  LEASE=restricted/trial-leases/current.json \
  PROJECT_ID=prometa-orch-sno-499235
```

`READY_TO_RENDER` requires live, fresh, accepted evidence; exact project
agreement; and a lease operator digest matching the single identity observed
on the administration host. The admission expires after at most 15 minutes.
It authorizes only secret-free installer-input rendering. Cloud, firewall, and
cluster-creation authority remain false.

## Render the secret-free installer input

Create an ignored values file:

```json
{
  "TARGET_PROJECT_ID": "<ephemeral-trial-project>"
}
```

Render only under `install-dir/trial/`:

```bash
python3 scripts/render_sno_trial_install_config.py \
  --values restricted/sno-trial-install-values.json \
  --lease restricted/trial-leases/current.json \
  --admission "restricted/$ADMISSION_ID.json" \
  --output install-dir/trial/install-config.rendered.yaml
```

The renderer verifies both the active lease and unexpired aggregate admission,
then locks one 8-vCPU control-plane node, zero workers, 150 GB balanced disk,
one zone, OVN-Kubernetes, and external publishing. It refuses pull secrets in
the values file and leaves `${PULL_SECRET_JSON}` and `${SSH_PUBLIC_KEY}` for a
final restricted operator step.

Generate a dedicated trial SSH key under ignored storage and materialize the
two file-backed values while the same admission is still active:

```bash
install -d -m 0700 restricted/operator install-dir/trial/operator
ssh-keygen -q -t ed25519 -N '' \
  -f restricted/operator/orchestra-trial
chmod 0600 restricted/operator/orchestra-trial.pub

make materialize-sno-trial-install-config \
  RENDERED=install-dir/trial/install-config.rendered.yaml \
  PULL_SECRET=restricted/pull-secret.json \
  SSH_PUBLIC_KEY=restricted/operator/orchestra-trial.pub \
  LEASE=restricted/trial-leases/current.json \
  ADMISSION="restricted/$ADMISSION_ID.json" \
  PROJECT_ID=prometa-orch-sno-499235 \
  OUTPUT=install-dir/trial/operator/install-config.yaml
```

The materializer accepts private regular files only, parses the pull secret
with duplicate-key rejection, validates the SSH public-key shape, revalidates
the lease and admission, and creates the final file at mode `0600`. Secret
values never enter command arguments or output. It is create-only and still
does not authorize cluster creation.

The locked template sets `credentialsMode: Manual`. Run the installer from a
Linux AMD64 GCE administration host with an attached, short-lived service
account; do not create or download a user-managed service-account key. Prepare
the release-matched `ccoctl` utility and GCP Workload Identity resources before
cluster creation so cluster components use short-lived credentials rather than
an administrator credential stored in the cluster.

The attached installer service account must be able to sign blobs as itself.
Grant `roles/iam.serviceAccountTokenCreator` on that service account resource,
not project-wide. The target project must expose the IAM, resource-manager, and
STS APIs needed by `ccoctl`. Its installer identity needs the Red Hat-documented
GCP installer roles plus project IAM-policy read/write for the component
service-account bindings. Prefer a minimal custom project role containing only
`resourcemanager.projects.get`, `resourcemanager.projects.getIamPolicy`, and
`resourcemanager.projects.setIamPolicy` for that last requirement.

Extract the seven release-matched `CredentialsRequest` objects and run
`ccoctl gcp create-service-accounts` before `openshift-install create cluster`.
Copy only the generated cluster-authentication and component credential
manifests plus the service-account signing material into a fresh installer
directory. Restrict signer private material to mode `0600`. Record the OIDC
bucket, workload-identity pool/provider, component service-account, and custom
role inventory under ignored storage without recording credential values.

Use the exact `4.20.27` linux/amd64 installer to validate the materialized
configuration on the Linux administration host before creating resources.
Keep the secret-bearing `install-config.yaml`, installer metadata, kubeconfig,
and auth directory under ignored restricted storage. Never place secret values
in command history, workflow inputs, logs, or Git.

Treat an installer directory as single-use once `create cluster` starts. If an
attempt fails after metadata or ignition generation, preserve its logs and run
the exact installer `destroy cluster` against that directory. Independently
verify that its instances, disks, addresses, load balancers, DNS records,
firewalls, and buckets are gone, then rebuild a new installer directory from
the original materialized config and `ccoctl` output. Never replay a directory
whose bootstrap ignition or metadata came from a failed attempt.

## Provisioning sequence

1. Verify the lease again.
2. Verify active billing, quota, budget alerts, DNS authority, and current
   source CIDR.
3. Materialize the pull secret and SSH public key only in the ignored
   installer directory.
4. Run the installer from a Linux AMD64 administration host.
5. Record the installer version, archive checksum, project digest, cluster ID,
   start/end time, and created resource inventory without credentials.
6. Restrict API and administration ingress to the reviewed source CIDR.
7. Confirm one schedulable control-plane node, zero workers, healthy cluster
   operators, default storage, console access, and registry pull.
8. Deploy only the minimal single-replica engineering dependencies named in
   the trial lock. Do not deploy Vault, Harbor, Keycloak, Thanos, Sentinel, or
   any HA topology.
9. Keep platform production tool execution disabled. Synthetic MCP remains
   read-only.
10. Stop testing before the lease expires and begin teardown with enough time
    to reconcile failures.

The Terraform module provisions the bounded project foundation only. DNS
delegation, installer execution, source-IP allowlisting, cluster workloads,
and teardown remain explicit live operator steps.

The installer creates cluster firewall rules during execution. Watch for the
`<infra-id>-api` and temporary `<infra-id>-bootstrap-in-ssh` rules and replace
their broad source ranges with the exact private source-CIDR file as soon as
they appear. Keep the documented Google health-check source ranges on health
probe rules and leave internal source-tag rules intact. Before accepting the
install, independently verify that no cluster administrative rule has
`0.0.0.0/0` or `::/0`.

## Observe the live trial cluster

After the installer reports completion, collect a payload-free observation
from the same Linux AMD64 operator host:

```bash
CLUSTER_ID=sno-cluster-operator-$(date -u +%Y%m%d%H%M%S).1

make observe-sno-trial-cluster \
  PROJECT_ID=prometa-orch-sno-499235 \
  SOURCE_CIDR_FILE=restricted/operator/source-cidr.txt \
  CLIENT=restricted/redhat/4.20.27/oc \
  ASSESSMENT_ID="$CLUSTER_ID" \
  OUTPUT="restricted/$CLUSTER_ID.json"

make verify-sno-trial-cluster \
  REPORT="restricted/$CLUSTER_ID.json"
```

The collector performs only read operations against OpenShift, GCP, and the
console route. It requires exact `4.20.27`, one ready schedulable
`n2-standard-8` control-plane node, zero worker machines, all observed cluster
operators healthy, `SingleReplica` GCP topology, `Manual` credentials, the
locked WIF issuer, the default expandable `standard-csi` storage class, a
console `200`, no bootstrap VM, and an API firewall restricted to the private
source-CIDR input. Node, infrastructure, instance, console-host, and source-CIDR
identities are stored only as digests.

`TRIAL_CLUSTER_OBSERVED` is engineering evidence only. It grants no workload,
cloud, teardown, campaign, certification, production, HA, RPO/RTO, Red Hat, or
SLA authority. A simulated fixture can exercise the contract in CI but cannot
impersonate a live collection.

## Observe cost exposure and teardown residuals

The resource-exposure report uses the dated catalog rates in
`config/sno-trial-cost-rate-card.lock.json` for N2/E2 compute and zonal
balanced-disk capacity. It records elapsed resource hours, installer/CCO/WIF
resource counts, inventory digests, and an estimate. It does not query or
verify billed spend. Load balancing, external IP, DNS, egress, tax, credits,
and discounts remain explicit exclusions.

Collect the active state before any product dry-run:

```bash
EXPOSURE_ID=sno-exposure-operator-$(date -u +%Y%m%d%H%M%S).1

make observe-sno-trial-resource-exposure \
  TARGET_PROJECT_ID=prometa-orch-sno-499235 \
  OPERATOR_PROJECT_ID=prometa-staging-ah \
  OPERATOR_INSTANCE_NAME=orchestra-sno-operator-20260727 \
  PHASE=active \
  ASSESSMENT_ID="$EXPOSURE_ID" \
  OUTPUT="restricted/$EXPOSURE_ID.json"

make verify-sno-trial-resource-exposure \
  REPORT="restricted/$EXPOSURE_ID.json"
```

`ACTIVE_EXPOSURE_OBSERVED` requires exactly one managed target VM/disk, one
operator VM/disk, only priced machine and disk types, and an estimated dominant
subtotal below the monthly alert ceiling. The estimate is intentionally
incomplete and the budget remains an alert, not a hard cap.

After installer destroy, CCO/WIF cleanup, and operator-host deletion, repeat
the same command with `PHASE=post-teardown`. `TEARDOWN_RESIDUALS_CLEAN`
requires zero managed target resources and zero operator VM/disk resources.
The collector stores no names, IPs, credentials, raw provider output, or
billing-account identity and never authorizes cleanup or teardown.

## Observe product server dry-runs and live capacity

Render the three locked product charts into ignored `restricted/` custody.
Keep every image digest-pinned and use the existing application Secret and CA
references; do not create those external inputs for this observation. Run the
collector from the Linux AMD64 operator host against a previously verified
`TRIAL_CLUSTER_OBSERVED` report:

```bash
DRY_RUN_ID=sno-product-dry-run-operator-$(date -u +%Y%m%d%H%M%S).1

make observe-sno-trial-product-dry-run \
  CLUSTER_REPORT=restricted/sno-cluster-<exact-main>.json \
  CLIENT=restricted/redhat/4.20.27/oc \
  KUBECONFIG=restricted/operator/install-clean-<date>/auth/kubeconfig \
  PLATFORM_MANIFEST=restricted/live-artifacts/<date>/prometa.rendered.yaml \
  RUNTIME_MANIFEST=restricted/live-artifacts/<date>/runtime.rendered.yaml \
  MODEL_MANIFEST=restricted/live-artifacts/<date>/model.rendered.yaml \
  ASSESSMENT_ID="$DRY_RUN_ID" \
  OUTPUT="restricted/$DRY_RUN_ID.json"

make verify-sno-trial-product-dry-run \
  REPORT="restricted/$DRY_RUN_ID.json"
```

The collector reads node allocatable capacity and effective non-terminal pod
requests, then projects the locked candidate peak. It invokes only
`oc apply --dry-run=server --validate=strict` in the existing `default`
namespace and checks each rendered identity immediately afterward with
`--ignore-not-found`. Any persisted object, rejected manifest, unhealthy
cluster baseline, or negative projected headroom blocks the report.

The payload-free report stores object, image, Secret-reference, node, pod, and
namespace counts or canonical digests, never their names or raw manifests.
`SERVER_DRY_RUN_OBSERVED_WITH_GAPS` proves API/schema acceptance and
non-persistence only. It does not prove image pulls, destination mirroring,
external Secret/CA/dependency resolution, scheduling, startup, readiness,
service behavior, deployment, admission, or certification. An image present
in a rendered chart but absent from the locked artifact set remains an
explicit blocker rather than being silently admitted by the observation.

The 2026-07-27 exact-main observation
`sno-product-dry-run-main-20260727170500.1` has report digest
`sha256:9394ce8fed98e92c46ff01479d86c0f40ee330409d12b8a8e350866d303b2ae1`.
It accepted 18 of 18 rendered objects, observed no persisted object, and
projected `628m` CPU plus `2214 MiB` memory headroom. It remains
`SERVER_DRY_RUN_OBSERVED_WITH_GAPS` because the capacity margin is tight, the
platform migration image is not bound by the artifact lock, and external
references, live pulls, and destination mirroring were not verified. Do not
remove the lock's activation blockers based on this report.

## Teardown and reconciliation

Run the exact installer destroy operation from the original metadata directory.
Do not delete metadata first.

After destroy completes, independently query the project for remaining:

- Compute instances and instance groups.
- Disks, snapshots, images, and addresses.
- Forwarding rules, target pools, health checks, and load balancers.
- Networks, subnets, routers, NAT, firewall rules, and DNS zones/records.
- Service accounts, keys, IAM grants, and installer-created buckets.

Delete or reconcile every residual resource, then delete the disposable project
if policy allows. Project deletion requires a final Terraform plan with
`-var='allow_project_delete=true'`, reviewed only after the installer destroy
and residual inventory are clean. Close the lease with an operator note kept
under `restricted/`; do not commit raw provider output. Budget alerts do not
prove that teardown succeeded.

The 2026-07-27 bounded trial ran the installer destroy from the original
metadata directory, removed the separately created CCO/WIF resources, and
deleted the operator VM. Independent post-teardown report
`sno-exposure-post-teardown-20260727172000.1` has report digest
`sha256:98b62fa0b69ef12a362e4915b9ababff3c5b5193652bf9143d9d3508c32fdf70`
and status `TEARDOWN_RESIDUALS_CLEAN`. It observed zero target
instances/disks, zero resources in every managed trial class, and zero
operator VM/disks. The retained project foundation, budget, APIs, and
delegated DNS zone are outside that managed set and were intentionally not
deleted.

## Allowed result wording

The maximum valid statement is:

> Orchestra engineering trial exercised on a single-node OpenShift 4.20.27
> GCP topology.

It must be followed by: non-HA, non-production, non-certifying, no RPO/RTO or
availability claim, and not the locked reference profile.
