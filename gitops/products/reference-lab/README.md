# Reference-lab product activation

This overlay declares, but does not prove deployment of, the frozen
three-plane release set. Its three Argo CD Applications bind:

- platform platform-v0.1.0-rc.5;
- runtime v0.18.3;
- model plane v0.1.10; and
- release-set digest
  sha256:7be0106ffe6ff7c79a4d4cc5dadd77f74201dcc7913e12711a05e6ea27dfc635.

The source chart digest is an Application annotation and the image digest is
the actual Helm value. Argo resolves an exact chart version from the private
Harbor repository. Before applying this overlay, mirror intake must prove that
each destination chart/version and image digest is the verified source
subject, then record destination repository and digest bindings as deployment
evidence. A matching version string alone is insufficient.

## Activation order

1. Pass every live prerequisite gate with at least two independent verifier
   identities.
2. Verify source signatures and attestations, mirror each subject by digest,
   apply the lab KMS signature, and pass RHTAS admission dry runs.
3. Populate the declared Vault paths, configure orchestra-vault as a
   ClusterSecretStore, and make orchestra-vault-pki ready.
4. Verify all ExternalSecrets, Certificates, and injected CA ConfigMaps are
   ready without reading their values into evidence.
5. Run a server-side dry run and diff for both the cluster floor and product
   overlay.
6. Apply the product overlay through the OpenShift GitOps bootstrap path after
   two-person approval. Argo then owns pruning and self-healing.

Manual workload edits are prohibited.

## Deliberate campaign blocks

- Platform agent querying, tool execution, bundled model services, and all
  production tool paths remain disabled.
- Runtime and model listeners use Secret-backed server TLS. Client
  authentication remains bearer/policy based; mTLS is not claimed.
- Platform release validation remains disabled until the durable PostgreSQL
  receiver and GitHub App executor are deployed and exercised.
- The platform Route currently uses edge TLS termination because the released
  platform pod has no TLS listener. The frozen campaign cannot start until a
  reviewed backend-TLS proxy/sidecar or equivalent chart capability closes the
  router-to-pod plaintext leg.

These blocks keep the overlay useful for integration work without allowing a
renderable manifest to be mistaken for campaign readiness.
