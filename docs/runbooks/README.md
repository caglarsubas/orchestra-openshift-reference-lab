# Runbook index

Runbooks are delivered incrementally and must be rehearsed before the frozen
campaign. Every destructive procedure requires named operators, an
authorization digest, independent timing, and cleanup verification.

| Runbook | State |
|---|---|
| Prerequisite verification | Implemented in `docs/prerequisites.md` |
| Project/state bootstrap | Procedure implemented; live rehearsal pending |
| Network/dependency foundation | Procedure implemented; live rehearsal pending |
| Private OpenShift installation | Template delivered; live procedure pending gates |
| GitOps bootstrap | Pending Wave 1 operator installation |
| Upgrade and rollback | Pending immutable release publication |
| Backup and restore | Pending dependency operators and backup targets |
| Credential/certificate rotation | Pending Vault/ESO deployment |
| Fault campaign | Pending fault-controller deployment and authorization flow |
| Evidence review/finalization | Contract exists in `prometa-platform`; live custody pending |
| Cost control and teardown | Procedure implemented; live rehearsal pending |

The table is intentionally not a readiness claim. A runbook becomes
`rehearsed` only when its payload-free report is signed under the active
campaign.
