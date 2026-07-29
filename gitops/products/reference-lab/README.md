# Reference-lab product activation

This overlay declares, but does not prove deployment of, the frozen
three-plane release set. Its three Argo CD Applications bind:

- platform platform-v0.1.0-rc.10;
- runtime v0.18.3;
- model plane v0.1.10; and
- release-set digest
  sha256:4f571fade2a1566a53d797c82561f30292734fcfcc75b23667dc08007ee8b6fe.

The source chart digest is an Application annotation and the image digest is
the actual Helm value. Argo resolves an exact chart version from the private
Harbor repository. Before applying this overlay, mirror intake must prove that
each destination chart/version and image digest is the verified source
subject, then record destination repository and digest bindings as deployment
evidence. A matching version string alone is insufficient.

Every Application also binds dependency BOM
`sha256:fabec47064381d067ca759ba99c47470cc66628ecaacd2e0521f50bb29aad5dc`.
Changing the dependency catalog therefore requires a reviewed product-overlay
update and cannot silently reuse a prior deployment declaration.

The Applications and AppProject also bind dependency admission
`sha256:73282faf172793398120509087930691e362f2290d4b60cc7f13ef4f99bf4219`.
They additionally bind source-verification observation
`sha256:75539cd9e8b0fce8e556b7d3cd8a7437d2e6f26525e96639085feff431478ed8`.
That observation is partial and non-campaign: three subjects verified and
eight still need exceptions, while signed-runner replay remains outstanding.
The AppProject has an enforced continuous deny window with manual sync
disabled. Removing that window is a reviewed activation change after mirror,
identity, storage, dry-run, and approval evidence exists; the activation
annotation alone is not treated as enforcement.

## Activation order

1. Pass every live prerequisite gate with at least two independent verifier
   identities.
2. Verify source signatures and attestations, mirror each subject by digest,
   apply the lab KMS signature, and pass RHTAS admission dry runs.
3. Populate the declared Vault paths, configure orchestra-vault as a
   ClusterSecretStore, and make orchestra-vault-pki ready.
4. Verify all ExternalSecrets, cert-manager Certificates, the platform service
   serving certificate, and injected CA ConfigMaps are ready without reading
   their values into evidence.
5. Run a server-side dry run and diff for both the cluster floor and product
   overlay.
6. Apply the product overlay through the OpenShift GitOps bootstrap path after
   two-person approval. Argo then owns pruning and self-healing.

Manual workload edits are prohibited.

## Deliberate campaign blocks

- Platform agent querying, tool execution, bundled model services, and all
  production tool paths remain disabled.
- Runtime and model listeners use Vault-PKI-backed Secrets. The platform uses
  an OpenShift service serving certificate for the router-to-Service re-encrypt
  leg and a chart-created, service-CA-injected public trust ConfigMap. Client
  authentication remains bearer/policy based; mTLS is not claimed.
- Platform release validation remains disabled until the durable PostgreSQL
  receiver and GitHub App executor are deployed and exercised.

These blocks keep the overlay useful for integration work without allowing a
renderable manifest to be mistaken for campaign readiness.
