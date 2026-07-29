# DNS delegation and private resolution runbook

This procedure establishes three separate authorities without treating one as
proof of another:

1. Terraform creates the public `ocp-lab.planeon.ai.` managed zone in the
   services/evidence project. It proves the intended zone exists, not that the
   parent domain delegates to it.
2. An external DNS operator publishes the zone's generated NS set at the
   `planeon.ai` parent. That change is outside Terraform and requires
   independent review.
3. The OpenShift installer creates the private
   `orchestra.ocp-lab.planeon.ai.` authority and records in the target VPC.
   The services project contains only a peering zone that queries the target
   VPC's resolution order.

## Foundation apply

1. Require the independently reviewed `foundation` prerequisite stage.
2. Review the saved Terraform plan. It must create exactly these DNS objects:
   `orchestra-ocp-lab-public` with public visibility and
   `orchestra-services-to-ocp-private` with private peering visibility.
3. Apply the approved plan and capture the non-secret output under ignored
   evidence storage:

   ```bash
   terraform -chdir=infra/terraform/foundation output -json dns_contract \
     > artifacts/dns-contract.json
   ```

4. Confirm the public zone contains only provider-managed SOA and NS records.
   Do not add public `api`, `api-int`, or `*.apps` records for the private
   cluster.
5. Confirm the peering zone is bound to `orchestra-services-network`, targets
   `orchestra-ocp-network`, and has no directly managed record sets.

## External delegation

1. A DNS operator who did not apply Terraform compares the generated NS set in
   `artifacts/dns-contract.json` with a fresh Cloud DNS read from the
   services/evidence project.
2. The operator delegates `ocp-lab.planeon.ai.` at the `planeon.ai` parent to
   exactly that NS set. Record only actor, authorization, change, and resulting
   evidence digests; do not store registrar credentials.
3. A second observer waits for authoritative propagation and verifies the
   complete set from outside both lab VPCs:

   ```bash
   dig +short NS ocp-lab.planeon.ai. | sort
   gcloud dns managed-zones describe orchestra-ocp-lab-public \
     --project='<services-evidence-project>' --format=json
   ```

4. Run the signed prerequisite collector with
   `--dns-managed-zone orchestra-ocp-lab-public`. A Terraform output, a
   registrar screenshot, or a successful `dig` alone cannot verify the gate.
   Independent review projects the resulting digest into the separate
   `dnsDelegation` prerequisite gate.

## Private OpenShift resolution

1. Require the independently admitted `openshift-install` stage, then execute
   the pinned `4.20.27` installer with `publish: Internal` from a host that can
   reach the target VPC.
2. Verify that the installer, not foundation Terraform, created the private
   cluster zone in the target project and attached it only to the target VPC.
3. From the target VPC, resolve `api`, `api-int`, and an admitted application
   route under `orchestra.ocp-lab.planeon.ai.` and confirm private answers.
4. From the services VPC, repeat the same lookups. Cloud DNS must select
   `orchestra-services-to-ocp-private` and resolve through the target VPC.
5. From an external resolver, confirm those private names return no private
   address and no public cluster record.
6. Record target and services observations separately. Missing, stale, public,
   or inconsistent answers block OpenShift deployment evidence and campaign
   admission.

## Failure and cleanup

- A public NS mismatch blocks installation admission; never work around it by
  adding public cluster records.
- A services-only private lookup failure is a peering/IAM problem. Do not copy
  private records into the services project.
- Remove parent delegation before destroying the public zone. `force_destroy`
  is disabled so unexpected records stop cleanup for review.
- Remove the services peering zone before either VPC. The OpenShift destroy
  flow owns deletion of its private zone and records.
- DNS creation, delegation, and successful lookup are infrastructure facts,
  not certification evidence slots or a reference-profile verification.
