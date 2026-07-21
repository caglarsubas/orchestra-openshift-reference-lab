# Durable release-validation receiver

This lab-owned service consumes Orchestra's existing signed
`release.validation.completed.v1` CloudEvent and passes a bounded recommendation
to tenant-owned GitOps. It is outside `prometa-platform`; the platform receives
no GitHub App, Argo CD, or deployment credential.

The implementation is a source candidate. It is not referenced by the active
GitOps root and has no published lab image yet. Building or testing it does not
set `referenceProfileVerified` and cannot fill an evidence slot.

## Processing contract

The API applies this order:

1. Bound the raw request body and verify `X-Prometa-Signature` plus
   `X-Prometa-Timestamp` before JSON parsing. One old and one current Secret may
   overlap during rotation.
2. Strictly parse the CloudEvents 1.0 envelope and the version-one release
   validation data contract. Extra properties, changed authority, mismatched
   status/recommendation, unsorted reason codes, or malformed digests fail.
3. Bind event, state-version, event-type, and idempotency headers to the signed
   body.
4. In one PostgreSQL transaction, serialize by organization and validation,
   reject same-version conflicts, record stale events, advance the monotonic
   head, and enqueue a payload-free action.
5. A separate worker mints a short-lived GitHub App installation token and
   sends a `repository_dispatch` carrying the stable event id and bounded
   release/evidence identity. The tenant workflow must deduplicate that id.

Explicit GitHub `429` and `5xx` responses use bounded retry. A network failure
after dispatch begins or an expired worker lease becomes `INDETERMINATE` and is
never replayed automatically. An operator must reconcile it with evidence as
`RETRY`, `DELIVERED`, or `DEAD_LETTER`.

The receiver stores no webhook Secret, GitHub private key, token, raw body, or
deployment credential in PostgreSQL. It stores event identity, release and
evidence digests, recommendation, delivery state, and reconciliation digests.

## Endpoints

| Method and path | Purpose |
|---|---|
| `POST /v1/release-validation/completed` | Signed public ingress; returns only after durable admission |
| `GET /healthz` | Process liveness |
| `GET /readyz` | PostgreSQL readiness |
| `GET /metrics` | Payload-free delivery-state gauges |
| `GET /internal/v1/actions/{eventId}` | Bearer-protected operator status |
| `POST /internal/v1/actions/{eventId}/reconcile` | Bearer-protected indeterminate-action reconciliation |

The internal paths must not be exposed through public ingress.

## Secret and identity inputs

Production manifests must project these from External Secrets or an equivalent
customer-managed Secret controller. Values do not belong in Git.

| Setting | Contract |
|---|---|
| `RECEIVER_DATABASE_URL_FILE` | File containing the external PostgreSQL DSN |
| `RECEIVER_WEBHOOK_SECRETS_FILE` | One or two newline-separated 32-4096 byte HMAC Secrets |
| `RECEIVER_ADMIN_TOKEN_FILE` | File containing the operator API bearer token |
| `RECEIVER_GITHUB_PRIVATE_KEY_FILE` | GitHub App RSA private key file |
| `RECEIVER_GITHUB_APP_ID` | Numeric App id |
| `RECEIVER_GITHUB_INSTALLATION_ID` | Numeric installation id |
| `RECEIVER_GITHUB_REPOSITORY_OWNER` | Tenant GitOps repository owner |
| `RECEIVER_GITHUB_REPOSITORY_NAME` | Tenant GitOps repository name |
| `RECEIVER_WORKER_ID` | Pod-unique worker identity, normally the Pod name |
| `RECEIVER_TLS_CERTIFICATE_FILE` | Optional server certificate path; required with the private key |
| `RECEIVER_TLS_PRIVATE_KEY_FILE` | Optional server private-key path; required with the certificate |
| `RECEIVER_TLS_CLIENT_CA_FILE` | Optional client CA path; when set, Gunicorn requires mTLS |

The GitHub App requires repository metadata read and contents write solely on
the synthetic tenant GitOps repository. It has no access to the OpenShift API.
Argo CD observes the resulting Git state and remains deployment authority.

## Database and processes

Run migrations as a separate authenticated Job before rolling API or worker
Pods:

```bash
orchestra-release-receiver-migrate
```

Run the API with Gunicorn (the image default) and the dispatcher as a separate
Deployment:

```bash
orchestra-release-receiver-worker
```

Use at least two API replicas and two workers. Configure a PodDisruptionBudget,
topology spread, default-deny NetworkPolicy, read-only root filesystem,
arbitrary UID, a size-bounded `emptyDir` at `/tmp`, dropped capabilities,
runtime-default seccomp, and TLS. Worker egress is limited to PostgreSQL, DNS,
and GitHub API; API egress is limited to PostgreSQL and DNS. The worker does not
accept ingress.

## Local verification

Install in an isolated environment and provide a disposable PostgreSQL 16 URL:

```bash
python -m pip install ./services/release-validation-receiver
RECEIVER_TEST_DATABASE_URL=postgresql://... \
  python -m unittest discover \
    -s services/release-validation-receiver/tests -t services/release-validation-receiver -v
```

Repository CI runs the same suite against a disposable PostgreSQL service and
builds the pinned UBI image for `linux/amd64`. Container dependencies come from
`requirements-linux-amd64.lock`; every direct and transitive wheel is both
version- and SHA-256-bound for the pinned base image. Changing the base image,
architecture, or a dependency requires regenerating and reviewing that lock.
Publication, signing, mirror admission, GitOps activation, backup/restore,
fault, and soak evidence remain separate steps.
