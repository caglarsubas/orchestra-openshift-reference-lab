# Provisioning gates

Provisioning is fail-closed. A human-readable assertion or a file path is not
evidence; each gate needs a payload-free digest, verification timestamp, and
short-lived verifier identity digest.

| Gate | Required proof |
|---|---|
| Red Hat entitlement | Active subscription/entitlement verification digest |
| Pull secret | Presence and access check digest; never the secret itself |
| Installer | Exact `4.20.27` linux/amd64 archive digest and signature result |
| GCP billing/quotas | Approved quotas for six OCP nodes, GKE, PD, LB, DNS, KMS, and probes |
| Target project | Distinct project identity digest and billing attachment |
| Services/evidence project | Distinct project identity digest and billing attachment |
| DNS | Delegation/control proof for `ocp-lab.prometa.ai` |
| WIF | GitHub/environment subject restriction and short-lived token proof |
| Runner | Published signed UBI9 linux/amd64 image and toolchain digest |
| Release set | Canonical cross-plane release set including runner subject |

Copy `config/prerequisites.example.json` to ignored
`restricted/prerequisites.json`. Change a gate to `verified` only when all
three evidence fields are populated with canonical values. Run:

```bash
python3 scripts/validate_repository.py \
  --prerequisites restricted/prerequisites.json \
  --require-ready
```

This validates admission to provisioning; it does not provision anything and
does not satisfy a certification evidence slot.
