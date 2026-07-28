# Production model artifacts and source intake

This runbook governs the source-only chat and embedding model candidate for the
`orchestra-ocp-4.20-amd64-v1` reference profile. The candidate closes the
source-selection ambiguity without activating either production model service.
It emits no manifest, Secret, Argo CD Application, destination mirror, or
campaign evidence.

The immutable candidate is
`config/production-model-artifact-candidate.lock.json`, digest
`sha256:cae278d46301c9777265df6b8a093e577472e7ee90ba26ad92eef233c90589dc`.
It binds its strict schema, the current dependency BOM, the current dependency
admission contract, and the cross-plane release set. The current BOM remains
unchanged and continues to mark `model-backend` and `embedding-model` as
`unselected` with `MODEL_ARTIFACT_CONTRACT_MISSING`.

The source-file inspection policy is
`config/production-model-artifact-intake-policy.lock.json`, digest
`sha256:625372044bb5db2271f2c545a2420e95af6a4dd867f9c5775f73903fb7317ca7`.
It is bound to the candidate and its strict payload-free observation schema.

## Locked source candidate

| Role | Artifact | Immutable source | Expected SHA-256 | Size |
|---|---|---|---|---:|
| Chat | Qwen2.5 0.5B Instruct Q4_K_M GGUF | Revision `9217f5db79a29953eb74d5343926648285ec7e67` | `74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db` | 491,400,032 bytes |
| Embedding | Nomic Embed Text v1.5 Q4_K_M GGUF | Revision `f750a25aba2d24830d874eb4e1af468f37248a37` | `d4e388894e09cf3816e8b0896d81d265b55e7a9fff9ab03fe8bf4ef5e11295ac` | 84,106,624 bytes |
| Server | llama.cpp CPU server `b10143` | Source revision `88b47a755c72fed4b22fba0fd262e2d7b7d01583` | linux/amd64 manifest `7a670b0633a2b33d915ca958fc1e4977334924590c9bd5ffc9d4813dd168d77b` | Image manifest |

The upstream source records are:

- [Qwen GGUF repository](https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/tree/main)
- [Nomic GGUF object](https://huggingface.co/nomic-ai/nomic-embed-text-v1.5-GGUF/blob/f750a25aba2d24830d874eb4e1af468f37248a37/nomic-embed-text-v1.5.Q4_K_M.gguf)
- [llama.cpp server contract](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)

These links are provenance inputs, not custody proof. A source digest written
in Git does not prove that the lab downloaded, reviewed, mirrored, or executed
those bytes.

## Runtime boundary

The candidate defines two internal HTTPS services:

- two chat replicas serving `/v1/chat/completions`; and
- one embedding replica serving `/v1/embeddings` with embedding mode and mean
  pooling.

Both use API-key files and operator-provided TLS files, accept ingress only
from the model plane, run with an arbitrary UID and read-only root filesystem,
and mount pre-staged model bytes from read-only PVCs. Runtime downloads are
forbidden. Secret values and certificate bytes remain outside Git and outside
payload-free evidence.

This is a capacity and interface contract, not a production-performance claim.
Chat quality, embedding quality, throughput, availability, fallback behavior,
and OpenShift compatibility remain unverified.

## Source review

1. Run the source-only validator:

   ```bash
   make validate-production-model-artifact-candidate
   make validate-production-model-artifact-intake
   ```

2. An independent reviewer confirms each upstream revision, object size,
   digest, licence, model card, and usage restriction. Record review evidence
   under restricted custody; never add downloaded model bytes to Git.
3. Scan the exact llama.cpp image manifest with the signed certification
   runner. Review its SBOM, vulnerabilities, licence inventory, and
   arbitrary-UID/read-only-root behavior.
4. If the unsigned upstream image remains governed by a reviewed exception,
   bind the exact platform digest and an unexpired two-person decision. A
   generic repository exception is insufficient.

## Local source-file inspection

Download and licence review are operator responsibilities. The repository
inspector never makes a network request and never copies a model. Place both
operator-obtained files under a private directory beneath ignored
`restricted/`, then run:

```bash
mkdir -m 700 restricted/production-model-intake
make inspect-production-model-artifacts \
  CHAT_MODEL="$PWD/restricted/production-model-intake/qwen2.5-0.5b-instruct-q4_k_m.gguf" \
  EMBEDDING_MODEL="$PWD/restricted/production-model-intake/nomic-embed-text-v1.5.Q4_K_M.gguf" \
  OBSERVATION_ID="production-model-intake-$(date -u +%Y%m%d%H%M%S).1" \
  OUTPUT="$PWD/restricted/production-model-intake/observation.json"
```

For each file, the inspector:

1. rejects a missing path, symlink, non-regular object, path outside
   `restricted/`, or group/world-writable file;
2. compares the filesystem size with the exact expected size and maximum before
   calling `open` or reading a byte;
3. walks every ancestor using descriptor-relative `O_NOFOLLOW` directory opens,
   opens the leaf relative to that verified parent, and compares the file
   descriptor with the pre-read device, inode, size, and modification time;
4. streams SHA-256 with a bounded byte count; and
5. rechecks descriptor identity and size after reading.

The report is created once with mode `0600`. It contains artifact identities,
sizes, digests, booleans, reason codes, timestamps, and contract bindings. It
contains no file path, model byte, credential, or Secret value. Verify it with:

```bash
make verify-production-model-artifact-intake \
  REPORT="$PWD/restricted/production-model-intake/observation.json"
```

`SOURCE_BYTES_OBSERVED` means only that two local files matched the locked
source metadata during one bounded inspection. The report is unsigned, expires
after 24 hours, and explicitly keeps artifact custody, licence approval, source
admission, mirror authorization, deployment, campaign evidence, and every
certification claim false. A simulated snapshot always produces `SIMULATED`,
even if its declared identifiers match.

## Materialize and admit

1. Download each model from its revision-bound URL into restricted staging.
   Enforce the declared maximum size before and during transfer.
2. Run the local source-file inspection before making the object available to
   any cluster or registry process. Reject a mismatch without retrying from a
   mutable URL. This local report is review input, not custody evidence.
3. Copy approved objects into the lab's immutable model custody store. Record
   object generation, digest, actor identity digest, and source candidate
   digest.
4. Mirror the exact llama.cpp linux/amd64 manifest into the lab registry and
   apply the lab KMS signature. Verify the destination digest and admission
   policy from both cluster planes.
5. Materialize model PVCs through the operator path. Confirm read-only mounts,
   expected filenames, sizes, digests, ownership compatible with arbitrary
   UIDs, and absence of network download permissions.
6. Resolve Secret and certificate references without exposing their values.
7. Render manifests privately and run server-side dry runs against the exact
   OpenShift API and restricted SCC.

Every output remains non-deployable until a new immutable dependency BOM and
dependency admission contract bind the reviewed custody and destination
receipts.

## Live qualification

After an admitted overlay exists, test each service independently:

1. TLS, wrong-audience API key, expired key, and rotated-key behavior.
2. Chat and embedding response shape against the declared OpenAI-compatible
   endpoints.
3. Real embedding similarity quality with a frozen labelled corpus.
4. Chat completion correctness with a frozen, non-sensitive prompt suite.
5. Pod replacement, replica loss, overload, graceful drain, and read-only PVC
   remount behavior.
6. Isolation from tenant-beta identities, namespaces, Secrets, telemetry, and
   budgets.
7. Model-plane fallback and conservative failure when either backend is
   unavailable.

Payload-free reports may describe results only after binding the exact image,
model objects, release set, cluster identity, and test-policy digests. These
tests are not campaign evidence unless the active campaign policy explicitly
admits them.

## Promotion

Promotion requires a new reviewable chain:

1. reissue the dependency BOM with selected providers and immutable model
   custody references;
2. reissue dependency admission with destination image, signature, PVC,
   Secret/TLS, dry-run, and live-quality receipts;
3. create a separate admitted GitOps candidate;
4. obtain the required independent approvals; and
5. let Argo CD perform the deployment.

Do not edit this source candidate to claim admission. Do not add its filename
to an active Kustomization. Orchestra remains outside tenant synchronous
production requests, and the control plane receives no production deployment
credential.

## Current blockers

The candidate remains `blocked` until all twelve machine-readable reason codes
are closed. In particular, source selection does not satisfy mirror custody,
lab signing, licence review, PVC materialization, Secret/TLS resolution,
OpenShift dry run, live quality, or live dependency connectivity. Therefore:

- `deploymentAuthorized` is false;
- `campaignEligible` is false;
- `referenceProfileVerified` is false; and
- every certification and production-support claim is false.
