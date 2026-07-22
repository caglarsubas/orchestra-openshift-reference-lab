# Runbook index

Runbooks are delivered incrementally and must be rehearsed before the frozen
campaign. Every destructive procedure requires named operators, an
authorization digest, independent timing, and cleanup verification.

| Runbook | State |
|---|---|
| Prerequisite verification | Implemented in `docs/prerequisites.md` |
| Project/state bootstrap | Procedure implemented; live rehearsal pending |
| Read-only foundation plan | Workflow and payload-free summary implemented; protected GitHub environment and live run pending |
| Network/dependency foundation | Procedure implemented; live rehearsal pending |
| Split-horizon DNS and delegation | Procedure and Terraform contract implemented; live delegation pending |
| Private OpenShift installation | Template delivered; live procedure pending gates |
| GitOps bootstrap | Pending Wave 1 operator installation |
| Dependency image admission | Source contract and offline values candidate implemented; live mirror intake and admitted overlay pending |
| Dependency supply-chain intake | Bounded signature observation and risk/exception contracts implemented; live runner evidence, approvals, and mirror receipts pending |
| Dependency risk review | Fail-closed launch preflight, isolated KMS/WIF authority, protected preflight-only workflow, atomic signed-runner collector, detached verification, builder, strict schemas, and empty intake implemented; Terraform application, external gate/App setup, live preflight, collection, and human reviews pending |
| Certification contract intake | Exact platform policy/schema/fixture bytes pinned, semantically CI-validated, and operator source replay implemented; live campaign pending |
| Release-validation receiver | Procedure implemented; publication and live rehearsal pending |
| Synthetic tenant and MCP surfaces | Procedure implemented; publication and live rehearsal pending |
| Upgrade and rollback | Pending immutable release publication |
| Backup and restore | Pending dependency operators and backup targets |
| Credential/certificate rotation | Pending Vault/ESO deployment |
| Fault campaign | Pending fault-controller deployment and authorization flow |
| Evidence review/finalization | Platform contract intake is pinned; live custody, reviews, and closure pending |
| Cost control and teardown | Procedure implemented; live rehearsal pending |

The table is intentionally not a readiness claim. A runbook becomes
`rehearsed` only when its payload-free report is signed under the active
campaign.
