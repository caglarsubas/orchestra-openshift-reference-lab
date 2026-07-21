# Synthetic tenant kit

This lab-owned source candidate supplies customer-like ingress and read-only
tool dependencies without introducing a customer system or moving Orchestra
into the tenant request path.

It has two process roles selected by `SYNTHETIC_SERVICE_ROLE`:

- `tenant-gateway` verifies a Keycloak-issued RS256 JWT for one configured
  tenant and scope, then calls the tenant runtime host's
  `POST /v1/runtime/execute` endpoint with a Secret-backed service credential.
- `mcp` exposes one deterministic read-only `lookup_order_status` tool over the
  official MCP Streamable HTTP transport.

The source and image build do not constitute deployment, live test, evidence,
soak, or reference-profile verification. The image is not published and no
GitOps root references it.

## Tenant gateway boundary

The gateway accepts `POST /v1/tenant/execute` plus payload-free `GET /healthz`,
`GET /readyz`, and `GET /metrics`. It:

1. Bounds the request before reading it and validates exactly one bearer token.
2. Strictly parses JWT header and claims, rejects duplicate JSON members, and
   accepts only RS256 keys fetched from the configured HTTPS JWKS endpoint.
3. Requires exact issuer, audience, tenant claim, subject, issue/expiry time,
   and `runtime:execute` scope. An unknown `kid` triggers one JWKS refresh;
   expired key state fails closed.
4. Strictly validates the runtime request envelope before forwarding it.
5. Uses no ambient proxy, refuses redirects, requires HTTPS, and optionally
   presents a client certificate to the runtime host.
6. Returns only a validated runtime success envelope or a stable synthetic
   error. It does not expose upstream headers or transport details.

The gateway contacts Keycloak and the runtime host only. It has no Prometa API
key or deployment credential.

## MCP fault lanes

`SYNTHETIC_MCP_MODE` selects one immutable deployment behavior:

| Mode | Behavior |
|---|---|
| `normal` | Authenticated, deterministic read-only response |
| `slow` | Sleeps for the configured interval before returning |
| `unavailable` | Returns HTTP 503 before MCP processing |
| `wrong-tenant` | Is bound to a different tenant and rejects alpha credentials |

The invalid-certificate lane uses the normal application behind a certificate
issued by a CA absent from the runtime trust bundle. Certificate material is
created by the lab PKI and is never stored in Git.

MCP access requires a Secret-backed bearer token and exact
`X-Orchestra-Tenant` header. The process exposes no write/destructive tool and
does not contact Orchestra.

## Secret inputs

All Secret values are file-backed and support Kubernetes projected-Secret
symlinks:

| Setting | Used by |
|---|---|
| `SYNTHETIC_RUNTIME_TOKEN_FILE` | Tenant gateway |
| `SYNTHETIC_MCP_TOKEN_FILE` | MCP |
| `SYNTHETIC_TLS_CERTIFICATE_FILE` | Both roles |
| `SYNTHETIC_TLS_PRIVATE_KEY_FILE` | Both roles |
| `SYNTHETIC_TLS_CLIENT_CA_FILE` | Optional inbound mTLS |
| `SYNTHETIC_RUNTIME_CLIENT_CERTIFICATE_FILE` | Optional gateway-to-runtime mTLS |
| `SYNTHETIC_RUNTIME_CLIENT_KEY_FILE` | Optional gateway-to-runtime mTLS |

JWKS and runtime CA bundles are public trust inputs, but are also mounted by
path so rotation can trigger an explicit rollout.

## Local verification

Install the package in an isolated Python 3.12 environment and run:

```bash
python -m unittest discover \
  -s services/synthetic-tenant-kit/tests \
  -t services/synthetic-tenant-kit -p 'test_*.py' -v
```

CI runs the suite, verifies an official MCP client handshake/tool call, builds
the SHA-256-locked UBI image for `linux/amd64`, and imports it under an
OpenShift-style arbitrary UID with a read-only root filesystem.
