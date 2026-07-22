# OpenShift GitOps ownership

This tree is reconciled by OpenShift GitOps/Argo CD. It contains no Secret
values and grants Orchestra no Argo CD credential.

The `clusters/reference-lab` overlay creates only the namespace, quota,
storage-class, and default-deny floor. The independently applied
`products/reference-lab` overlay contains the digest-bound Argo Applications,
ExternalSecret references, cert-manager Certificates, and migration policy.
Separating them prevents a foundation apply from activating workloads before
release mirroring and prerequisite admission pass. Charts and GitOps never
create credential values.

Manual workload edits are prohibited. Before a frozen campaign, the lab is
destroyed and reconstructed from reviewed declarations, then Argo CD drift
must remain zero for the 72-hour burn-in and 30-day soak.

The separate `dependencies/reference-lab` overlay targets the private GKE
services plane. It currently creates only namespaces, default-deny policies,
and a continuously denied AppProject. It contains no dependency Applications
until a complete image/mirror/Secret admission lock is reviewed. Services-plane
Argo CD cannot reconcile OpenShift product namespaces.

`dependencies/candidates/reference-lab` is a separate, source-only review
surface. It contains digest-bound values for five source-resolved charts and
six blocked service-resource plans, but no Kustomization or deployable YAML.
CI proves that the active overlay does not reference it. Offline Helm output
belongs only under ignored `restricted/` storage and may not be applied.
