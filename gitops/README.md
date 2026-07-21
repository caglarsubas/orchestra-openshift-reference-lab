# OpenShift GitOps ownership

This tree is reconciled by OpenShift GitOps/Argo CD. It contains no Secret
values and grants Orchestra no Argo CD credential.

The initial overlay creates only the namespace, quota, storage-class, and
default-deny floor. Product applications enter in later pull requests after
their immutable image/chart/release-set digests exist. External Secrets may
reference Vault objects, but charts and GitOps never create credential values.

Manual workload edits are prohibited. Before a frozen campaign, the lab is
destroyed and reconstructed from reviewed declarations, then Argo CD drift
must remain zero for the 72-hour burn-in and 30-day soak.
