# SNO trial dependency manifest candidate

This directory is an inactive, source-only Kubernetes candidate for the two
SNO dependencies whose artifacts are pinned independently:

- Valkey 9.1.0 for shared rate-limit and budget state.
- llama.cpp `b10143` serving the pinned Qwen2.5 0.5B GGUF model.

`kubectl kustomize` can render the directory, but no active Kustomization or
Argo CD Application references it. The manifests contain no Secret values and
cannot materialize the model. They require operator-owned objects:

| Kind | Namespace | Name | Required content |
|---|---|---|---|
| `StorageClass` | cluster | `ORCHESTRA_SNO_STORAGE_CLASS_REQUIRED` | Observed default-compatible RWO class with `WaitForFirstConsumer` and expansion |
| `Secret` | `orchestra-sno-valkey` | `orchestra-sno-valkey-auth` | `password` |
| `Secret` | `orchestra-sno-valkey` | `orchestra-sno-valkey-server-tls` | `tls.crt`, `tls.key`, `ca.crt` |
| `PersistentVolumeClaim` | `orchestra-sno-model-backend` | `orchestra-sno-model-artifact` | Pre-staged, digest-verified GGUF; mounted read-only |
| `Secret` | `orchestra-sno-model-backend` | `orchestra-sno-model-auth` | `api-keys` |
| `Secret` | `orchestra-sno-model-backend` | `orchestra-sno-model-server-tls` | `tls.crt`, `tls.key` |

The uppercase storage-class value is an unresolved identifier, not a shell
template. The payload-free observer in
`scripts/sno_trial_dependency_inputs.py` verifies all six live references
without reading Secret values. The private materializer in
`scripts/materialize_sno_trial_dependency_manifests.py` then replaces exactly
one identifier and emits a new digest-bound artifact under ignored
`restricted/` storage. See `docs/runbooks/sno-trial.md` for the operator
commands. Applying this source directory or the private artifact directly is
not authorized.

Validate the candidate with:

```bash
make validate-sno-trial-dependency-manifests
```

The controlling contract is
[`config/sno-trial-dependency-manifest-candidate.lock.json`](../../../../config/sno-trial-dependency-manifest-candidate.lock.json).
It remains blocked on upstream review, destination admission, a live input
observation, model digest and certificate proof, live capacity, OpenShift
server-side dry-run, connectivity proof, and activation review.
