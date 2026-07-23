# Threat model

## Protected assets

- OpenShift and GKE administrative authority.
- Terraform state and provider identity.
- Vault roots, PKI intermediates, and External Secret references.
- Harbor signing/admission trust roots.
- Evidence KMS keys, immutable reports, and reviewer attestations.
- Tenant-isolated runtime, telemetry, routing, budget, and receipt state.
- Campaign identity, topology digest, release set, and dependency BOM.

## Trust roles

| Role | May do | Must not do |
|---|---|---|
| Bootstrap administrator | Create projects, WIF, state custody | Execute campaign drills or approve results |
| GitOps executor | Reconcile reviewed manifests | Read reviewer keys or mutate evidence |
| Kubernetes mutator | Operate approved cluster resources | Change cloud fault state or approve campaign |
| Datastore operator | Backup, restore, rotate data services | Sign fault or certification attestations |
| Fault controller | Execute authorized provider mutations | Write primary evidence or review its own drill |
| Evidence writer | Create immutable payload-free objects | Overwrite/delete objects or mutate infrastructure |
| Read-only observer | Read health and evidence metadata | Mutate workloads, stores, faults, or gates |
| Security reviewer | Approve frozen manifest independently | Execute drills or share certification signing key |
| Certification reviewer | Final independent approval | Execute drills or share security signing key |

## Primary threats and controls

| Threat | Control |
|---|---|
| Static cloud credential disclosure | GitHub OIDC WIF, short-lived tokens, no service-account key resource, repository scan |
| Arbitrary workflow obtains or cross-assumes a lab service account | Numeric repository/owner claims, exact workflow/ref/environment WIF conditions, provider-prefixed subject mapping, single-subject impersonation grants, machine-checked current-run approvals, and separate plan/apply providers |
| Value-bearing saved plan leaks through Actions or broad reviewer access | Plan/log/JSON excluded from GitHub artifacts, private CMEK state bucket, create-only package publisher, group-only managed-folder viewer, restricted local review path, and explicit post-review deletion |
| A substituted, stale, partial, destructive, or unreviewed plan is applied | Exact main/run/package ID and statement digest, five-object inventory, pre-download size limits, generation/metageneration-pinned downloads, last-marker ordering, detached signature, 24-hour age, replayed action summary, delete/replace rejection, and a separate current-run approval |
| The apply executor upgrades its own receipt into independent evidence | Separate receipt key and prefix, strict `receiptSelfAttested: true` and `independentlyObserved: false`, no campaign claims, and a separately federated post-apply read-only observation lane |
| The observer hides direct inherited or storage-scoped authority that could alter its evidence | Exact direct project, service-account, custom-role, bucket, managed-folder, KMS, WIF, and ancestor-role inventory; externally managed ancestor `roles/iam.securityReviewer` is the only allowed direct inherited grant; any extra direct grant fails closed |
| A stale receipt, substituted plan, state race, or provider drift is reported as a clean apply | Generation-pinned plan, receipt, and state reads; independent signature replay; receipt/state lineage and serial binding; stable state generation around refresh-only planning; and exact signed-plan resource identity comparison |
| Preflight identity is reused for scanning, mirroring, or evidence mutation | Separate exact-workflow WIF provider, current-run non-owner approval, key-level signer role only, no project/bucket/mirror grant, short-lived release token, and a statically enforced `--preflight-only` workflow |
| Full-collection identity overwrites, reads back, deletes, or promotes evidence | Separate exact-workflow WIF provider and current-run approval, no project role, key-level signer plus raw-bucket object-creator only, generation-zero uploads, detached signature uploaded last, and no signed-evidence or mirror grant |
| Partial raw upload is mistaken for a completed collection | Unique evidence prefix, create-only writes, detached signature as the last completion marker, no success output after a failed marker upload, and later independent generation/signature verification |
| Custody verifier reads unrelated raw evidence or existing signed reports | Managed-folder IAM limits raw viewing to `dependency-risk/` and signed creation to `dependency-risk-custody/`; the verifier has no bucket/project role and no signed-object read/delete grant |
| Raw objects change between listing and verification, or a reordered marker is accepted | Exact four-object inventory, immutable generation and metageneration capture, precondition-pinned downloads, digest replay, and detached signature required as the newest object |
| A malicious raw archive escapes extraction or exhausts the verifier | Bounded compressed/member/expanded sizes, one expected root, path normalization, and rejection of links, devices, FIFOs, traversal, or extra members before deep replay |
| A forged or valid custody report is treated as source admission or activation | Strict false authorization claims, distinct report-signing key, offline signature replay against an independently expected key digest, create-only evidence role, no mirror/admission/activation grant, and separate later human and source-replay gates |
| Public control-plane exposure | Private OCP/GKE endpoints, no VM external IP, IAP tunnel only |
| Peering used as broad trust | Non-transitive peering, explicit port/CIDR firewall, flow logs, namespace default deny |
| Public DNS takeover or private-name leakage | Terraform-owned exact public zone, external delegation review, no public cluster records, installer-owned private records, and one-way read-only DNS peering |
| Dependency outage causes local safety downgrade | Product fail-closed contracts and typed-degradation evidence; no fallback to in-process production state |
| Cross-tenant confused deputy | Alpha/beta identities, signed tenant bindings, negative campaign cases, no shared credentials |
| Fault actor forges success | Independent fault attestation and separate signing authority |
| Evidence tampering or run mixing | Canonical digests, object generations, CMEK, retention lock, campaign/topology edges |
| Certification contract substitution or semantic widening | Platform revision and release binding, byte and canonical digests, strict semantic validation, fixture/live separation, and operator replay of pinned Git objects |
| Reviewer substitution | Different identity and key digests, post-window attestations, two-person closure |
| Supply-chain substitution | Immutable image refs, mirrored signature verification, admission policy, release-set binding |
| Mutable or substituted lab-owned service publication | Exact-main first-attempt workflow, non-reusable release-plus-revision tags, pre-push absence proof, distinct image/index digests, bound AMD64 and attestation manifests, pinned SBOM generator, maximum provenance, exact-workflow keyless signatures, and post-push registry replay |
| Harbor bootstrap cycle bypasses admission | Immutable Artifact Registry seed, distinct mirror identity, source/destination digest edge, deny-all dependency AppProject |
| Secret/payload leakage | No Secret values in Git, payload-free reports, raw/reports split, content scanning |
| Accidental irreversible bucket lock | Certification-mode precondition plus exact lock acknowledgement and review runbook |
| Terraform drift during soak | GitOps/Terraform drift checks; material changes cancel the campaign |
| Automated rollback gains deployment authority | External receiver and Argo CD own action; Orchestra sends signed recommendation only |
| Webhook replay or state regression | Raw-body HMAC with bounded age, event/header binding, PostgreSQL event idempotency, and monotonic validation heads |
| Receiver crash silently repeats a GitOps action | Transactional inbox/outbox, stable event id, expired claims become `INDETERMINATE`, and evidence-bound operator reconciliation |
| GitHub App crosses tenant or repository boundary | Locked App identity and read-only permissions, complete App-installation enumeration, App-JWT creation of an unrestricted installation token, exact one-repository enumeration before use, mandatory token revocation, repository-narrowed operational tokens, bounded dispatch payload, and no OpenShift credential |
| Forged or replayed synthetic tenant identity | Exact RS256 issuer/audience/tenant/scope/time checks, strict JWT JSON, bounded JWKS cache, unknown-key refresh, and fail-closed expiry |
| Tenant gateway becomes an Orchestra proxy | Gateway egress is limited to Keycloak and runtime; it receives no platform credential and exposes only the runtime execute contract |
| Synthetic MCP accepts cross-tenant or side-effecting calls | Constant-time bearer and tenant binding, one read-only/idempotent tool, protocol-level annotations, and separate failure deployments |
| Runtime silently trusts an invalid MCP certificate | Vault PKI trust is explicit; the untrusted-certificate lane uses a separate CA absent from the runtime bundle and must fail before MCP |

## Explicit residual risks

- A prerequisite observation proves only what the read-only collector saw. The
  GitHub check can prove configured non-owner reviewers but, outside a workflow
  run, cannot prove that one approved a particular operation or grant
  provisioning admission. Live observations must be independently reviewed and
  projected into the separate gate contract; diagnostic `fixture/simulated`
  output is never admissible.
- Initial project bootstrap necessarily uses a privileged human or enterprise
  provisioning identity before WIF exists. Its token lifecycle and audit trail
  are external prerequisites.
- GitHub environment protection is external state. The verifier checks the
  required-reviewer configuration and one current-run approval by a configured
  non-owner distinct from the initiator. GitHub's read API does not expose the
  administrator-bypass toggle, so disabling bypass remains a manually reviewed
  Enterprise-environment precondition. Reruns are rejected because review
  history is run-scoped rather than attempt-scoped.
- The operator-control-plane collector verifies all six configured environments,
  requires the App's complete installation set to contain only the locked
  account installation, and creates a full-scope installation token to
  enumerate the real repository set before revoking it. It cannot observe GitHub's administrator
  bypass setting, prove that a reviewer approved a later workflow, or create
  provisioning admission. The locked App slug, installation, protected
  environments, secrets, and live observation remain external state until
  configured and independently reviewed.
- The foundation executor retains broad services-project roles, including
  Artifact Registry and storage administration. Source validation forbids
  mirror operations in the apply workflow, but this is not equivalent to an
  IAM deny. Its receipt is therefore self-attested. A purpose-specific custom
  executor role remains a hardening requirement. The independently signed
  post-apply observation lane is source-declared and fixture-tested, but its
  WIF provider, service account, protected environment, ancestor
  `roles/iam.securityReviewer` grants, provider refresh, and signed report have
  not been created or exercised live.
- The observer proves exact direct IAM bindings. It has no Google Workspace
  group-reader authority, so group-transitive access is not expanded by this
  lane. An independent group-membership review, or a separately authorized
  Cloud Asset Policy Analyzer query that completes group expansion, remains a
  live-readiness prerequisite.
- Saved Terraform plans can contain sensitive values. The reviewer group and
  apply executor can read private plan packages by design. Membership,
  short-lived authentication, endpoint hygiene, review-directory deletion,
  and access-log review are external operational controls; no plan package may
  enter GitHub artifacts or campaign evidence.
- IP allowlists do not provide domain-aware egress policy. A later proxy lane
  must pin domain/TLS destinations before the frozen campaign.
- The declared GKE singleton Binary Authorization policy is not equivalent to
  RHTAS admission on OpenShift. Each plane needs its own tested policy.
- The repository has no live SAML certification; synthetic OIDC/SCIM is the
  identity target until strict SAML validation is shipped in the product.
- No control here proves Red Hat supportability or customer certification.
- CI validates the locked, vendored certification contract but has no private
  platform-repository credential. An authorized operator must perform the
  upstream Git-object replay before campaign intake; until then, CI proves
  internal consistency and provenance claims, not independent source custody.
- Several upstream charts do not yet have verified publisher signatures in
  the dependency BOM. They cannot be activated until verification or a named,
  time-bounded security exception is recorded.
- The atomic risk collector and detached verifier have not yet run with the
  approved lab WIF identities and Cloud KMS key. Separate preflight and
  full-collection providers, service accounts, protected workflows, signing,
  and create-only raw custody are source-declared only. They have not been
  applied or independently observed, and the external GitHub environments/App
  installation do not exist merely because their source contracts do. The
  collector intentionally cannot read raw objects or record their immutable
  generations. The independent custody-verification authority, managed-folder
  IAM, protected workflow, deep replay, and signed report are now
  source-declared and fixture-tested, but none is applied or live-observed.
  There is no independently signed live custody report. Fixture tests prove
  contract, generation/order checks, bounded extraction, upload ordering, and
  tamper behavior only; they are not vulnerability, licence, source-admission,
  mirror, or campaign evidence.
- The first-party Valkey chart does not currently satisfy the locked Sentinel
  topology. Selecting a third-party operator or changing topology requires a
  reviewed architecture decision and a new dependency BOM.
- GitHub `repository_dispatch` has no provider-side idempotency guarantee. The
  tenant workflow must durably deduplicate the stable event id; ambiguous
  dispatches remain blocked until reconciliation.
- The receiver source has not yet been published, mirrored, admitted, deployed,
  restored, fault-tested, or soaked. CI and a successful image build are not
  live reference-lab evidence.
- The synthetic tenant kit source has not yet been published, mirrored,
  admitted, deployed, connected to Keycloak/runtime, fault-tested, or soaked.
  Its local OIDC and official MCP tests are not live identity, PKI, network, or
  tenant-isolation evidence.
- The lab-service publication lane uses repository-scoped GitHub package write
  authority and public Sigstore transparency services. Its source contract is
  CI-tested, but the workflow has not run. A successful run would prove only
  GHCR source publication, embedded BuildKit attestations, and the exact
  workflow's keyless signature. The embedded Syft version is not the locked
  certification scanner, and neither a successful build nor its observation
  authorizes mirroring, admission, deployment, or campaign evidence. A partial
  publication leaves immutable unadmitted tags and requires a new release
  candidate.
