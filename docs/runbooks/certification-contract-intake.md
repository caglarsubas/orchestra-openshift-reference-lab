# Certification contract intake

## Purpose and authority

`prometa-platform` owns the certification-v2 policy, schemas, aggregation
semantics, and certification-runner implementation. This repository consumes
those contracts for campaign orchestration; it must not fork or silently
reinterpret them.

The intake lock at
`config/reference-lab-certification-contract.lock.json` binds the exact
platform release, Git revision, certification-runner image, toolchain, lab
profile, topology, cross-plane release set, dependency BOM, and three vendored
contract artifacts. It also freezes the live policy's 18 evidence slots and
the bounded reference-profile claim.

The vendored fixture is deliberately `fixture/simulated`. It is a contract
test vector, not a campaign template to edit into a live record. It cannot
satisfy the `vendor-reference-lab/live` policy.

## Local and CI verification

The default, network-free validation checks vendored bytes, canonical JSON,
semantic invariants, topology and release bindings, strict schemas, fixture
isolation, and the non-authorizing claim:

```bash
python3 scripts/validate_reference_lab_contract_intake.py
```

CI runs that command without private cross-repository credentials. An operator
with an authorized checkout of the platform repository must additionally
replay the exact Git objects:

```bash
make verify-platform-contract-source \
  PLATFORM_REPOSITORY=/absolute/path/to/agent-hook-v2
```

This resolves every source path at the pinned commit using `git show`, compares
the upstream bytes with the vendored bytes, and rechecks the locked digests.
It does not trust the platform checkout's working tree.

## Intake upgrade procedure

1. Publish the immutable platform release and update the cross-plane release
   set first.
2. Obtain an authorized platform checkout containing the pinned Git revision.
3. Copy the three contract artifacts byte-for-byte from that revision. Do not
   reformat or hand-edit them in this repository.
4. Update the intake lock's source identity, bindings, byte digests, canonical
   digests, and expected semantics.
5. Run the default validator, the upstream Git-object replay, unit tests, and
   repository validation.
6. Review policy/schema changes as a cross-plane contract change. A change to
   the measured path creates a new immutable release set and campaign.

Never combine artifacts from different platform revisions or mutate an
existing live campaign to adopt a new contract. Remediate in the owning
repository, publish a new artifact, and rerun affected evidence.

## Live campaign boundary

A live campaign is created only after prerequisite admission by the released,
signed certification runner. Live manifests, reports, signatures, and raw
provider artifacts belong in the configured evidence custody or ignored
`restricted/` working storage, never in Git.

Passing this intake proves only that the lab repository is prepared to consume
the pinned platform contract. It does not start a campaign, fill an evidence
slot, verify the reference profile, certify a customer, establish Red Hat
certification, or create a contractual SLA.
