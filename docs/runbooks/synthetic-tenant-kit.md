# Synthetic tenant kit runbook

## Purpose and authority

This procedure activates customer-like tenant ingress and read-only MCP fault
surfaces after all infrastructure gates pass. It does not activate a production
customer integration, grant Orchestra deployment authority, or produce an
evidence slot by itself.

OpenShift GitOps owns the tenant gateway deployment. Services-plane Argo CD
owns the MCP deployments. Vault and External Secrets own credentials and PKI
material. No Secret value is accepted through Git.

## Publication gate

Before adding any GitOps reference:

1. Complete `docs/runbooks/lab-service-publication.md` for the exact reviewed
   source revision. This produces the immutable GHCR image, embedded SBOM and
   provenance, keyless signature, source-publication observation, separate
   read-only replay, and digest-bound `published` inventory entry.
2. Run the separate certification risk collector against that exact digest.
   Resolve critical/high findings or record an approved, time-bounded waiver.
3. Sign the image with the lab KMS identity, record source and destination
   digests, mirror by digest into Harbor, and prove RHTAS admission rejection
   for unsigned and wrong-key images.
4. Update the inventory with the Harbor destination and admission evidence in a
   separate reviewed change. Do not set `gitOpsReferenced` until Keycloak,
   Vault/ESO, PKI, runtime TLS, and network policy gates are independently
   verified.

## Identity preparation

Create the synthetic Keycloak realm declaratively:

- audience `orchestra-tenant-gateway`;
- required `runtime:execute` scope;
- exact `org_id` protocol mapper;
- `tenant-alpha` users for successful journeys;
- `tenant-beta` users for negative isolation journeys;
- short access-token lifetime no longer than the gateway's configured maximum;
- MFA for human operators and client credentials only for automated probes.

Record the realm/client configuration digest and Keycloak issuer/JWKS
certificate chain. Do not export tokens into evidence. Confirm an unknown
signing `kid` refreshes JWKS and that an expired cache fails closed while
Keycloak is unavailable.

## Secret and PKI preparation

Create Vault paths and ExternalSecret references for:

- gateway-to-runtime bearer credential;
- optional gateway-to-runtime client certificate and key;
- MCP bearer credentials for alpha and beta lanes;
- server certificate/key for each gateway and MCP deployment;
- optional inbound client CA.

Normal and failure endpoints use lab PKI. The invalid-certificate endpoint uses
a dedicated synthetic CA intentionally absent from the runtime trust bundle.
Store only Secret names and certificate/public-key digests in campaign input.

## Deployments and network policy

Deploy at least two tenant-gateway replicas in the tenant namespace with
restricted-v2, arbitrary UID, read-only root, dropped capabilities,
runtime-default seccomp, resources, probes, PDB, and topology spread. Permit
egress only to DNS, Keycloak JWKS, and the runtime host. Permit ingress only
from the private tenant route/probe namespace.

Deploy separate services-plane MCP instances for `normal`, `slow`,
`unavailable`, `wrong-tenant`, and `invalid-certificate`. Permit ingress only
from runtime-host egress addresses and probes. The normal/slow/unavailable
instances bind tenant-alpha; wrong-tenant binds tenant-beta. Every deployment
uses the same immutable image and a distinct configuration digest.

## Acceptance sequence

Run payload-free probes and record only status, latency, request-id digest,
identity digest, configuration digest, and certificate digest:

1. Alpha JWT -> gateway -> runtime model-only execution succeeds.
2. Beta JWT, wrong audience, missing scope, expired token, duplicate JWT claim,
   and unknown signing key are rejected without a runtime call.
3. Key rotation overlap accepts current/new keys and rejects the retired key
   after the frozen overlap window.
4. Normal MCP performs the official initialize/list/call sequence and exposes
   only `lookup_order_status` with read-only/idempotent annotations.
5. Slow MCP crosses the configured runtime timeout and produces typed failure.
6. Unavailable MCP returns typed transport failure without safety downgrade.
7. Alpha credentials against wrong-tenant MCP fail before tool execution.
8. Invalid-certificate MCP fails TLS before protocol initialization.
9. Platform agent querying and production tool-execution routes remain disabled.
10. Network flow logs show no gateway-to-platform or MCP-to-platform request.

Any unexpected tool, write/destructive annotation, payload in evidence, public
route, ambient proxy use, redirect follow, cross-tenant success, or platform
credential cancels the rehearsal.

## Cleanup

Argo CD removes the five MCP and gateway Applications. Vault revokes synthetic
credentials and leaf certificates. Keycloak disables probe clients and users.
Operators verify no Service, Route, ExternalSecret, token, certificate, or
temporary NetworkPolicy remains. Evidence objects are retained under campaign
policy; local tokens and raw test output are destroyed.
