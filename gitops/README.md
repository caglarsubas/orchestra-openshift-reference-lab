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
