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
| Public control-plane exposure | Private OCP/GKE endpoints, no VM external IP, IAP tunnel only |
| Peering used as broad trust | Non-transitive peering, explicit port/CIDR firewall, flow logs, namespace default deny |
| Dependency outage causes local safety downgrade | Product fail-closed contracts and typed-degradation evidence; no fallback to in-process production state |
| Cross-tenant confused deputy | Alpha/beta identities, signed tenant bindings, negative campaign cases, no shared credentials |
| Fault actor forges success | Independent fault attestation and separate signing authority |
| Evidence tampering or run mixing | Canonical digests, object generations, CMEK, retention lock, campaign/topology edges |
| Reviewer substitution | Different identity and key digests, post-window attestations, two-person closure |
| Supply-chain substitution | Immutable image refs, mirrored signature verification, admission policy, release-set binding |
| Harbor bootstrap cycle bypasses admission | Immutable Artifact Registry seed, distinct mirror identity, source/destination digest edge, deny-all dependency AppProject |
| Secret/payload leakage | No Secret values in Git, payload-free reports, raw/reports split, content scanning |
| Accidental irreversible bucket lock | Certification-mode precondition plus exact lock acknowledgement and review runbook |
| Terraform drift during soak | GitOps/Terraform drift checks; material changes cancel the campaign |
| Automated rollback gains deployment authority | External receiver and Argo CD own action; Orchestra sends signed recommendation only |
| Webhook replay or state regression | Raw-body HMAC with bounded age, event/header binding, PostgreSQL event idempotency, and monotonic validation heads |
| Receiver crash silently repeats a GitOps action | Transactional inbox/outbox, stable event id, expired claims become `INDETERMINATE`, and evidence-bound operator reconciliation |
| GitHub App crosses tenant or repository boundary | Single synthetic repository installation, short-lived installation tokens, bounded dispatch payload, and no OpenShift credential |
| Forged or replayed synthetic tenant identity | Exact RS256 issuer/audience/tenant/scope/time checks, strict JWT JSON, bounded JWKS cache, unknown-key refresh, and fail-closed expiry |
| Tenant gateway becomes an Orchestra proxy | Gateway egress is limited to Keycloak and runtime; it receives no platform credential and exposes only the runtime execute contract |
| Synthetic MCP accepts cross-tenant or side-effecting calls | Constant-time bearer and tenant binding, one read-only/idempotent tool, protocol-level annotations, and separate failure deployments |
| Runtime silently trusts an invalid MCP certificate | Vault PKI trust is explicit; the untrusted-certificate lane uses a separate CA absent from the runtime bundle and must fail before MCP |

## Explicit residual risks

- A prerequisite observation proves only what the read-only collector saw. It
  cannot prove reviewer independence or grant provisioning admission. Live
  observations must be independently reviewed and projected into the separate
  gate contract; diagnostic `fixture/simulated` output is never admissible.
- Initial project bootstrap necessarily uses a privileged human or enterprise
  provisioning identity before WIF exists. Its token lifecycle and audit trail
  are external prerequisites.
- IP allowlists do not provide domain-aware egress policy. A later proxy lane
  must pin domain/TLS destinations before the frozen campaign.
- The declared GKE singleton Binary Authorization policy is not equivalent to
  RHTAS admission on OpenShift. Each plane needs its own tested policy.
- The repository has no live SAML certification; synthetic OIDC/SCIM is the
  identity target until strict SAML validation is shipped in the product.
- No control here proves Red Hat supportability or customer certification.
- Several upstream charts do not yet have verified publisher signatures in
  the dependency BOM. They cannot be activated until verification or a named,
  time-bounded security exception is recorded.
- The atomic risk collector and detached verifier have not yet run with the
  approved lab WIF identity and Cloud KMS key. Fixture tests prove contract and
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
