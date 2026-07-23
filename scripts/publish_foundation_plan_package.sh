#!/usr/bin/env bash
set -Eeuo pipefail

umask 077
export LC_ALL=C
export TZ=UTC

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AUTHORITY="$ROOT/config/foundation-apply-execution.lock.json"
PACKAGE_MODULE="$ROOT/scripts/foundation_plan_package.py"

PLAN=""
SUMMARY=""
STATE_BUCKET=""
PLAN_ID=""
SIGNING_KEY=""
EXPECTED_SIGNING_PUBLIC_KEY_DIGEST=""
ENVIRONMENT_APPROVAL_DIGEST=""

usage() {
  cat <<'EOF'
Usage: publish_foundation_plan_package.sh \
  --plan <foundation.tfplan> \
  --summary <foundation-plan-summary.json> \
  --state-bucket <bootstrap-state-bucket> \
  --plan-id orchestra-foundation-plan-<run>.<attempt> \
  --signing-key gcpkms://projects/.../cryptoKeyVersions/... \
  --expected-signing-public-key-digest sha256:<digest> \
  --environment-approval-digest sha256:<digest>

Sign and create an immutable five-object saved-plan package. The detached
signature is uploaded last as the completion marker. The saved plan is
value-bearing and is never uploaded to a GitHub artifact.
EOF
}

fail() {
  printf 'foundation_plan_package_publish_failed code=%s\n' "$1" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required_command_missing:$1"
}

require_digest() {
  [[ "$1" =~ ^sha256:[a-f0-9]{64}$ ]] || fail "$2"
}

raw_digest() {
  printf 'sha256:%s' "$(sha256sum "$1" | awk '{print $1}')"
}

while (($# > 0)); do
  case "$1" in
    --plan)
      PLAN="${2:-}"
      shift 2
      ;;
    --summary)
      SUMMARY="${2:-}"
      shift 2
      ;;
    --state-bucket)
      STATE_BUCKET="${2:-}"
      shift 2
      ;;
    --plan-id)
      PLAN_ID="${2:-}"
      shift 2
      ;;
    --signing-key)
      SIGNING_KEY="${2:-}"
      shift 2
      ;;
    --expected-signing-public-key-digest)
      EXPECTED_SIGNING_PUBLIC_KEY_DIGEST="${2:-}"
      shift 2
      ;;
    --environment-approval-digest)
      ENVIRONMENT_APPROVAL_DIGEST="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      fail "argument_invalid:$1"
      ;;
  esac
done

[[ -f "$PLAN" && -f "$SUMMARY" ]] || fail "plan_artifacts_missing"
[[ "$STATE_BUCKET" =~ ^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$ ]] || fail "state_bucket_invalid"
[[ "$PLAN_ID" =~ ^orchestra-foundation-plan-[1-9][0-9]*\.[1-9][0-9]*$ ]] || fail "plan_id_invalid"
if [[ "$SIGNING_KEY" =~ ^gcpkms://projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/locations/europe-west1/keyRings/orchestra-lab-foundation-execution/cryptoKeys/foundation-plan-signing/cryptoKeyVersions/[1-9][0-9]*$ ]]; then
  :
else
  fail "plan_signing_key_version_invalid"
fi
require_digest "$EXPECTED_SIGNING_PUBLIC_KEY_DIGEST" "expected_plan_public_key_digest_invalid"
require_digest "$ENVIRONMENT_APPROVAL_DIGEST" "environment_approval_digest_invalid"

for command_name in awk cosign curl date gcloud mktemp python3 sha256sum; do
  require_command "$command_name"
done
for contract_file in "$AUTHORITY" "$PACKAGE_MODULE"; do
  [[ -f "$contract_file" ]] || fail "contract_file_missing:$(basename "$contract_file")"
done

TEMP_DIR="$(mktemp -d "${RUNNER_TEMP:-/tmp}/foundation-plan-package.XXXXXX")"
chmod 0700 "$TEMP_DIR"
cleanup() {
  rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

PLAN_PUBLIC_KEY="$TEMP_DIR/foundation-plan-package-public-key.pem"
STATEMENT="$TEMP_DIR/foundation-plan-package-statement.json"
SIGNATURE="$TEMP_DIR/foundation-plan-package-signature.sigstore.json"
CURL_CONFIG="$TEMP_DIR/gcs-upload.curlrc"
SIGNED_AT="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

cosign public-key --key "$SIGNING_KEY" >"$PLAN_PUBLIC_KEY"
chmod 0600 "$PLAN_PUBLIC_KEY"
[[ "$(raw_digest "$PLAN_PUBLIC_KEY")" == "$EXPECTED_SIGNING_PUBLIC_KEY_DIGEST" ]] \
  || fail "plan_signing_public_key_digest_mismatch"

python3 "$PACKAGE_MODULE" build \
  --plan "$PLAN" \
  --summary "$SUMMARY" \
  --bucket "$STATE_BUCKET" \
  --plan-id "$PLAN_ID" \
  --environment-approval-digest "$ENVIRONMENT_APPROVAL_DIGEST" \
  --signing-key "$SIGNING_KEY" \
  --signing-public-key "$PLAN_PUBLIC_KEY" \
  --expected-public-key-digest "$EXPECTED_SIGNING_PUBLIC_KEY_DIGEST" \
  --signed-at "$SIGNED_AT" \
  --output "$STATEMENT" >/dev/null

cosign sign-blob \
  --yes \
  --key "$SIGNING_KEY" \
  --bundle "$SIGNATURE" \
  "$STATEMENT" >/dev/null
chmod 0600 "$STATEMENT" "$SIGNATURE"
python3 "$PACKAGE_MODULE" validate \
  --statement "$STATEMENT" \
  --signing-public-key "$PLAN_PUBLIC_KEY" \
  --signature-bundle "$SIGNATURE" \
  --expected-public-key-digest "$EXPECTED_SIGNING_PUBLIC_KEY_DIGEST" >/dev/null

PREFIX="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["package"]["prefix"])' "$STATEMENT")"
[[ "$PREFIX" == "foundation-plans/v1/orchestra-ocp-4.20-amd64-v1/"*"/$PLAN_ID" ]] \
  || fail "plan_package_prefix_invalid"

ACCESS_TOKEN="$(gcloud auth print-access-token)"
[[ -n "$ACCESS_TOKEN" && "$ACCESS_TOKEN" != *$'\n'* ]] \
  || fail "gcs_access_token_invalid"
{
  printf 'silent\n'
  printf 'show-error\n'
  printf 'fail-with-body\n'
  printf 'connect-timeout = 30\n'
  printf 'max-time = 600\n'
  printf 'header = "Authorization: Bearer %s"\n' "$ACCESS_TOKEN"
  printf 'header = "Content-Type: application/octet-stream"\n'
} >"$CURL_CONFIG"
unset ACCESS_TOKEN
chmod 0600 "$CURL_CONFIG"

upload_create_only() {
  local source="$1"
  local object_name="$2"
  local encoded_name
  encoded_name="$(
    python3 -c \
      'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' \
      "$PREFIX/$object_name"
  )"
  curl \
    --config "$CURL_CONFIG" \
    --request POST \
    --data-binary "@$source" \
    "https://storage.googleapis.com/upload/storage/v1/b/$STATE_BUCKET/o?uploadType=media&name=$encoded_name&ifGenerationMatch=0" \
    >/dev/null
}

upload_create_only "$PLAN" "foundation.tfplan"
upload_create_only "$SUMMARY" "foundation-plan-summary.json"
upload_create_only "$PLAN_PUBLIC_KEY" "foundation-plan-package-public-key.pem"
upload_create_only "$STATEMENT" "foundation-plan-package-statement.json"
# The detached signature is the immutable completion marker and remains last.
upload_create_only "$SIGNATURE" "foundation-plan-package-signature.sigstore.json"

printf 'foundation_plan_package_published planId=%s prefix=%s statement=%s plan=%s applyAuthorized=false infrastructureApplied=false independentlyObserved=false campaignEvidence=false referenceProfileVerified=false\n' \
  "$PLAN_ID" "$PREFIX" "$(raw_digest "$STATEMENT")" "$(raw_digest "$PLAN")"
