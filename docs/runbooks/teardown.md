# Cost control and teardown runbook

Teardown is not deletion of certification custody. Signed reports and required
backups survive workload teardown according to their retention policies.

1. Close or cancel the active campaign. Freeze final probe and cost metrics.
2. Verify every authorized fault was cleaned up and all workers/zones/routes
   are restored.
3. Export Argo CD state, OpenShift resources, OADP backups, datastore backup
   catalogs, and payload-free dependency inventories.
4. Stop the soak and synthetic traffic, then remove product applications
   through GitOps. Do not use manual `oc delete` for managed workloads.
5. Remove dependency applications and persistent volumes only after backup
   restore verification and two-person approval.
6. Destroy OpenShift with the same pinned installer release and capture its
   metadata. Remove residual load balancers, disks, DNS, firewall rules, and
   service accounts only after inventory reconciliation.
7. Destroy the GKE/foundation layer from a reviewed Terraform plan. Resource
   protection and evidence-bucket retention will intentionally block complete
   deletion.
8. Disable nonessential APIs and revoke WIF/IAP bindings. Preserve state,
   evidence, KMS, and approved backups.
9. Record monthly residual cost and a dated owner for final retained-resource
   disposal after legal/campaign retention expires.

Any unexplained resource, failed cleanup check, or retained credential marks
campaign cleanup unresolved and prevents BOM finalization.
