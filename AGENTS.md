# Repository operating rules

- This repository owns reference-lab infrastructure, GitOps declarations,
  synthetic tenant surfaces, campaign orchestration, and runbooks. Product
  behavior remains in its product repository.
- Never commit Secret values, pull secrets, kubeconfigs, Terraform state,
  provider credentials, signing keys, live evidence, or customer data.
- Never run `terraform apply`, `openshift-install create cluster`, destructive
  drills, bucket locking, or campaign finalization from an ordinary pull
  request workflow.
- Live mutations require a named campaign, short-lived identity, approved
  authorization digest, two-person approval where destructive, and a cleanup
  verification step.
- Fixture and K3s evidence must remain `fixture/simulated`; it cannot be copied
  into a vendor-reference-lab or customer-production evidence slot.
- The only claim this lab can produce is reference-profile verification.
  Customer certification, Red Hat certification, and contractual SLA claims
  remain false.
- Use branches prefixed with `codex/`, open a pull request, monitor CI, and
  merge only after required checks succeed.
