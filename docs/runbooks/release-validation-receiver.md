# Release-validation receiver operations

This runbook covers the lab-owned durable receiver. It does not authorize a
campaign, publish an image, mutate GitOps, or certify a target by itself.

## Preconditions

- The source-artifact stage in `docs/runbooks/lab-service-publication.md` has
  completed for the exact release and revision.
- The receiver image is built from reviewed source, scanned, signed, mirrored
  by digest, and admitted by the lab policy controller.
- External PostgreSQL backup, PITR, TLS, and least-privilege roles are ready.
- Vault and External Secrets project the database DSN, current/previous webhook
  Secrets, operator token, and GitHub App key. Git contains only Secret names.
- The GitHub App is installed only on the synthetic tenant GitOps repository.
- The target `repository_dispatch` workflow deduplicates the stable event id
  before changing desired state.
- Public ingress reaches only the webhook path. Internal status,
  reconciliation, readiness, and metrics paths use separate private routing.

## Install or upgrade

1. Record the image, source, migration, configuration, and Secret-generation
   digests in the change authorization.
2. Run `orchestra-release-receiver-migrate` as a one-shot Job using the
   datastore-operator identity. Verify schema version `1`.
3. Roll API Pods, confirm `/readyz`, and send a correctly signed hold fixture
   that targets no active deployment.
4. Roll worker Pods. Confirm the fixture reaches `DELIVERED`, the GitHub request
   id is recorded, and the tenant workflow records the same event id once.
5. Confirm old Pods drain, no `CLAIMED` lease expires, and no action becomes
   `INDETERMINATE` during rollout.

## Rotate webhook signing Secrets

1. Project current and next values as two lines in the webhook Secret file.
2. Roll all API Pods and prove both signatures are accepted.
3. Switch Orchestra delivery to the next Secret and wait past the maximum
   delivery retry plus signature-tolerance window.
4. Project only the next value, roll all API Pods, and prove the predecessor is
   rejected.
5. Record only Secret version/resource digests and timestamps in evidence.

## Rotate the GitHub App key

1. Add a new GitHub App key and project it to a new Secret generation.
2. Drain workers. Do not rotate while an action is `CLAIMED`.
3. Roll workers with the new key and execute a non-mutating synthetic hold.
4. Revoke the predecessor key and prove fresh token minting fails under it.
5. Preserve key identity digests, never key bytes, in the rotation report.

## Reconcile an indeterminate dispatch

Automatic replay is prohibited. An independent operator must inspect the
synthetic GitOps repository and Actions history for the stable event id.

- If the event definitely ran, reconcile to `DELIVERED`.
- If the event definitely did not reach GitHub, reconcile to `RETRY`.
- If safe determination is impossible or policy rejects the action, reconcile
  to `DEAD_LETTER` and open an incident.

Submit the private reconciliation endpoint a status plus evidence and actor
digests. The database records the prior status and immutable reconciliation
entry. Never use `RETRY` merely because a timeout occurred.

## Backup and restore

Back up the receiver schema with the infrastructure-services PostgreSQL
cluster. Restore into a clean cluster, then verify:

- every inbox event and validation head agrees;
- each `APPLIED` inbox event has exactly one outbox row;
- terminal and indeterminate states retain attempt and reason metadata;
- reconciliation rows still bind actor and evidence digests; and
- no `CLAIMED` row is resumed automatically after restore.

Convert restored `CLAIMED` rows to `INDETERMINATE` before workers start. Run a
read-only consistency query and obtain reviewer approval before reconnecting
the GitHub App.

## Alerts

Page on readiness loss, any `INDETERMINATE` action, dead letters, an expired
claim, sustained retries, migration failure, or Secret projection failure.
Alert on pending age and PostgreSQL backup freshness. Do not include raw
webhook bodies, Secrets, tokens, or private keys in logs or alerts.
