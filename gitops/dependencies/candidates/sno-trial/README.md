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
template. A later materialization step must replace it with the exact
live-observed class and produce a new digest-bound artifact before server-side
dry-run. Applying this source directory directly is not authorized.

Validate the candidate with:

```bash
make validate-sno-trial-dependency-manifests
```

The controlling contract is
[`config/sno-trial-dependency-manifest-candidate.lock.json`](../../../../config/sno-trial-dependency-manifest-candidate.lock.json).
It remains blocked on upstream review, destination admission, operator inputs,
model materialization, live capacity, OpenShift server-side dry-run, and
connectivity proof.
