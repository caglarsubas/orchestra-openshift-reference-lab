#!/usr/bin/env bash
set -Eeuo pipefail

umask 077
export LC_ALL=C
export TZ=UTC

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FOUNDATION_DIR="$ROOT/infra/terraform/foundation"
PLAN_VERIFIER="$ROOT/scripts/verify_foundation_plan_package.py"
RECEIPT_MODULE="$ROOT/scripts/foundation_apply_receipt.py"

STATE_BUCKET=""
SOURCE_REVISION=""
PLAN_ID=""
EXPECTED_PLAN_STATEMENT_DIGEST=""
PLAN_SIGNING_KEY=""
EXPECTED_PLAN_PUBLIC_KEY_DIGEST=""
RECEIPT_SIGNING_KEY=""
EXPECTED_RECEIPT_PUBLIC_KEY_DIGEST=""
APPLY_ID=""
ENVIRONMENT_APPROVAL_DIGEST=""
ACTOR_ID=""
REASON=""

usage() {
  cat <<'EOF'
Usage: verify_and_apply_foundation_plan.sh \
  --state-bucket <bootstrap-state-bucket> \
  --source-revision <exact-main-sha> \
  --plan-id orchestra-foundation-plan-<run>.<attempt> \
  --expected-plan-statement-digest sha256:<digest> \
  --plan-signing-key gcpkms://projects/.../cryptoKeyVersions/... \
  --expected-plan-public-key-digest sha256:<digest> \
  --receipt-signing-key gcpkms://projects/.../cryptoKeyVersions/... \
  --expected-receipt-public-key-digest sha256:<digest> \
  --apply-id orchestra-foundation-apply-<run>.<attempt> \
  --environment-approval-digest sha256:<digest> \
  --actor-id <numeric-github-actor-id> \
  --reason <reviewed-reason>

Generation-pin and verify one immutable plan package, replay its payload-free
summary from the downloaded saved plan, apply that exact plan with state
locking, and publish a signed self-attested receipt. Independent post-apply
observation remains required.
EOF
}

fail() {
  printf 'foundation_plan_apply_failed code=%s\n' "$1" >&2
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
    --state-bucket)
      STATE_BUCKET="${2:-}"
      shift 2
      ;;
    --source-revision)
      SOURCE_REVISION="${2:-}"
      shift 2
      ;;
    --plan-id)
      PLAN_ID="${2:-}"
      shift 2
      ;;
    --expected-plan-statement-digest)
      EXPECTED_PLAN_STATEMENT_DIGEST="${2:-}"
      shift 2
      ;;
    --plan-signing-key)
      PLAN_SIGNING_KEY="${2:-}"
      shift 2
      ;;
    --expected-plan-public-key-digest)
      EXPECTED_PLAN_PUBLIC_KEY_DIGEST="${2:-}"
      shift 2
      ;;
    --receipt-signing-key)
      RECEIPT_SIGNING_KEY="${2:-}"
      shift 2
      ;;
    --expected-receipt-public-key-digest)
      EXPECTED_RECEIPT_PUBLIC_KEY_DIGEST="${2:-}"
      shift 2
      ;;
    --apply-id)
      APPLY_ID="${2:-}"
      shift 2
      ;;
    --environment-approval-digest)
      ENVIRONMENT_APPROVAL_DIGEST="${2:-}"
      shift 2
      ;;
    --actor-id)
      ACTOR_ID="${2:-}"
      shift 2
      ;;
    --reason)
      REASON="${2:-}"
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

[[ "$STATE_BUCKET" =~ ^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$ ]] || fail "state_bucket_invalid"
[[ "$SOURCE_REVISION" =~ ^[a-f0-9]{40}$ ]] || fail "source_revision_invalid"
[[ "$PLAN_ID" =~ ^orchestra-foundation-plan-[1-9][0-9]*\.[1-9][0-9]*$ ]] || fail "plan_id_invalid"
[[ "$APPLY_ID" =~ ^orchestra-foundation-apply-[1-9][0-9]*\.1$ ]] || fail "apply_id_invalid"
[[ "$ACTOR_ID" =~ ^[1-9][0-9]*$ ]] || fail "actor_id_invalid"
[[ ${#REASON} -ge 12 && ${#REASON} -le 500 ]] || fail "reason_invalid"
require_digest "$EXPECTED_PLAN_STATEMENT_DIGEST" "expected_plan_statement_digest_invalid"
require_digest "$EXPECTED_PLAN_PUBLIC_KEY_DIGEST" "expected_plan_public_key_digest_invalid"
require_digest "$EXPECTED_RECEIPT_PUBLIC_KEY_DIGEST" "expected_receipt_public_key_digest_invalid"
require_digest "$ENVIRONMENT_APPROVAL_DIGEST" "environment_approval_digest_invalid"
if [[ "$PLAN_SIGNING_KEY" =~ ^gcpkms://projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/locations/europe-west1/keyRings/orchestra-lab-foundation-execution/cryptoKeys/foundation-plan-signing/cryptoKeyVersions/[1-9][0-9]*$ ]]; then
  :
else
  fail "plan_signing_key_version_invalid"
fi
if [[ "$RECEIPT_SIGNING_KEY" =~ ^gcpkms://projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/locations/europe-west1/keyRings/orchestra-lab-foundation-execution/cryptoKeys/foundation-apply-receipt-signing/cryptoKeyVersions/[1-9][0-9]*$ ]]; then
  :
else
  fail "receipt_signing_key_version_invalid"
fi

for command_name in awk cmp cosign curl date gcloud jq mktemp python3 sha256sum terraform; do
  require_command "$command_name"
done
for contract_file in "$PLAN_VERIFIER" "$RECEIPT_MODULE"; do
  [[ -f "$contract_file" ]] || fail "contract_file_missing:$(basename "$contract_file")"
done

TEMP_DIR="$(mktemp -d "${RUNNER_TEMP:-/tmp}/foundation-plan-apply.XXXXXX")"
chmod 0700 "$TEMP_DIR"
cleanup() {
  rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

PROFILE_ID="orchestra-ocp-4.20-amd64-v1"
PLAN_PREFIX="foundation-plans/v1/$PROFILE_ID/$SOURCE_REVISION/$PLAN_ID"
RAW_INVENTORY="$TEMP_DIR/gcloud-plan-inventory.json"
INVENTORY="$TEMP_DIR/plan-inventory.json"
DOWNLOAD_DIR="$TEMP_DIR/downloads"
VERIFIED_PACKAGE="$TEMP_DIR/verified-package.json"
PLAN_JSON="$TEMP_DIR/foundation-plan-replayed.json"
STATE_BEFORE="$TEMP_DIR/state-before.json"
STATE_AFTER="$TEMP_DIR/state-after.json"
STATE_OBJECT_RESPONSE="$TEMP_DIR/state-object-response.json"
STATE_QUERY_CONFIG="$TEMP_DIR/gcs-state-query.curlrc"
mkdir -m 0700 "$DOWNLOAD_DIR"

gcloud storage ls \
  --json \
  --limit=6 \
  "gs://$STATE_BUCKET/$PLAN_PREFIX/*" >"$RAW_INVENTORY"
jq -eS \
  --arg bucket "$STATE_BUCKET" \
  --arg prefix "$PLAN_PREFIX" \
  '
    def utc:
      if type != "string" then error("timestamp_invalid")
      elif endswith("+00:00") then sub("\\+00:00$"; "Z")
      elif endswith("Z") then .
      else error("timestamp_timezone_invalid")
      end;
    if type != "array" or length != 5 then error("object_count_invalid") else
      {
        schemaVersion: 1,
        bucket: $bucket,
        prefix: $prefix,
        objects: (
          map(
            if .type != "cloud_object"
              or (.metadata | type) != "object"
              or .metadata.bucket != $bucket
            then error("object_metadata_invalid")
            else {
              name: .metadata.name,
              generation: .metadata.generation,
              metageneration: .metadata.metageneration,
              sizeBytes: (.metadata.size | tonumber),
              crc32c: .metadata.crc32c,
              md5Hash: (.metadata.md5Hash // null),
              etag: .metadata.etag,
              timeCreated: (.metadata.timeCreated | utc),
              updated: (.metadata.updated | utc)
            } end
          ) | sort_by(.name)
        )
      }
    end
  ' "$RAW_INVENTORY" >"$INVENTORY"
chmod 0600 "$INVENTORY"
rm -f "$RAW_INVENTORY"
python3 "$PLAN_VERIFIER" inventory \
  --inventory "$INVENTORY" \
  --source-revision "$SOURCE_REVISION" \
  --plan-id "$PLAN_ID" >/dev/null

OBJECT_NAMES=(
  foundation.tfplan
  foundation-plan-summary.json
  foundation-plan-package-public-key.pem
  foundation-plan-package-statement.json
  foundation-plan-package-signature.sigstore.json
)
for object_name in "${OBJECT_NAMES[@]}"; do
  full_name="$PLAN_PREFIX/$object_name"
  metadata="$(jq -cer --arg name "$full_name" '.objects | map(select(.name == $name)) | if length == 1 then .[0] else error("object_missing") end' "$INVENTORY")"
  generation="$(jq -er '.generation' <<<"$metadata")"
  metageneration="$(jq -er '.metageneration' <<<"$metadata")"
  gcloud storage cp \
    --if-generation-match="$generation" \
    --if-metageneration-match="$metageneration" \
    --quiet \
    "gs://$STATE_BUCKET/$full_name" \
    "$DOWNLOAD_DIR/$object_name" >/dev/null
  chmod 0600 "$DOWNLOAD_DIR/$object_name"
done

PLAN_KMS_PUBLIC_KEY="$TEMP_DIR/plan-kms-public-key.pem"
RECEIPT_PUBLIC_KEY="$TEMP_DIR/foundation-apply-receipt-public-key.pem"
cosign public-key --key "$PLAN_SIGNING_KEY" >"$PLAN_KMS_PUBLIC_KEY"
cosign public-key --key "$RECEIPT_SIGNING_KEY" >"$RECEIPT_PUBLIC_KEY"
chmod 0600 "$PLAN_KMS_PUBLIC_KEY" "$RECEIPT_PUBLIC_KEY"
[[ "$(raw_digest "$PLAN_KMS_PUBLIC_KEY")" == "$EXPECTED_PLAN_PUBLIC_KEY_DIGEST" ]] \
  || fail "plan_public_key_digest_mismatch"
[[ "$(raw_digest "$RECEIPT_PUBLIC_KEY")" == "$EXPECTED_RECEIPT_PUBLIC_KEY_DIGEST" ]] \
  || fail "receipt_public_key_digest_mismatch"
cmp -s "$PLAN_KMS_PUBLIC_KEY" "$DOWNLOAD_DIR/foundation-plan-package-public-key.pem" \
  || fail "plan_public_key_bytes_mismatch"

terraform -chdir="$FOUNDATION_DIR" fmt -check
terraform -chdir="$FOUNDATION_DIR" init \
  -input=false \
  -lockfile=readonly \
  -backend-config="bucket=$STATE_BUCKET" \
  -backend-config="prefix=foundation" >/dev/null
terraform -chdir="$FOUNDATION_DIR" validate >/dev/null
if ! terraform -chdir="$FOUNDATION_DIR" show -json \
  "$DOWNLOAD_DIR/foundation.tfplan" >"$PLAN_JSON" 2>"$TEMP_DIR/plan-show.log"; then
  fail "saved_plan_render_failed"
fi

VERIFIED_AT="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
python3 "$PLAN_VERIFIER" verify \
  --inventory "$INVENTORY" \
  --download-dir "$DOWNLOAD_DIR" \
  --plan-json "$PLAN_JSON" \
  --source-revision "$SOURCE_REVISION" \
  --plan-id "$PLAN_ID" \
  --expected-statement-digest "$EXPECTED_PLAN_STATEMENT_DIGEST" \
  --expected-public-key-digest "$EXPECTED_PLAN_PUBLIC_KEY_DIGEST" \
  --verified-at "$VERIFIED_AT" \
  --output "$VERIFIED_PACKAGE" >/dev/null

STATE_ACCESS_TOKEN="$(gcloud auth print-access-token)"
[[ -n "$STATE_ACCESS_TOKEN" && "$STATE_ACCESS_TOKEN" != *$'\n'* ]] \
  || fail "foundation_state_access_token_invalid"
{
  printf 'silent\n'
  printf 'show-error\n'
  printf 'connect-timeout = 30\n'
  printf 'max-time = 120\n'
  printf 'header = "Authorization: Bearer %s"\n' "$STATE_ACCESS_TOKEN"
  printf 'header = "Accept: application/json"\n'
} >"$STATE_QUERY_CONFIG"
unset STATE_ACCESS_TOKEN
chmod 0600 "$STATE_QUERY_CONFIG"
if ! state_http_status="$(
  curl \
    --config "$STATE_QUERY_CONFIG" \
    --request GET \
    --output "$STATE_OBJECT_RESPONSE" \
    --write-out '%{http_code}' \
    "https://storage.googleapis.com/storage/v1/b/$STATE_BUCKET/o/foundation%2Fdefault.tfstate?fields=name%2Cgeneration"
)"; then
  fail "foundation_state_inventory_failed"
fi
chmod 0600 "$STATE_OBJECT_RESPONSE"
case "$state_http_status" in
  200)
    jq -e \
      '.name == "foundation/default.tfstate"
        and (.generation | type) == "string"
        and (.generation | test("^[1-9][0-9]*$"))' \
      "$STATE_OBJECT_RESPONSE" >/dev/null \
      || fail "foundation_state_inventory_invalid"
    state_count="1"
    ;;
  404)
    jq -e '.error.code == 404' "$STATE_OBJECT_RESPONSE" >/dev/null \
      || fail "foundation_state_inventory_invalid"
    state_count="0"
    ;;
  *)
    fail "foundation_state_inventory_failed"
    ;;
esac
if [[ "$state_count" == "1" ]]; then
  if ! terraform -chdir="$FOUNDATION_DIR" state pull >"$STATE_BEFORE" 2>"$TEMP_DIR/state-before.log"; then
    fail "foundation_state_before_read_failed"
  fi
else
  rm -f "$STATE_BEFORE"
fi

STARTED_AT="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
if ! terraform -chdir="$FOUNDATION_DIR" apply -input=false -lock=true -lock-timeout=300s "$DOWNLOAD_DIR/foundation.tfplan" \
  >"$TEMP_DIR/foundation-apply.log" 2>&1; then
  fail "terraform_saved_plan_apply_failed"
fi
COMPLETED_AT="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
if ! terraform -chdir="$FOUNDATION_DIR" state pull >"$STATE_AFTER" 2>"$TEMP_DIR/state-after.log"; then
  fail "foundation_state_after_read_failed"
fi
chmod 0600 "$STATE_AFTER"
if [[ -f "$STATE_BEFORE" ]]; then
  chmod 0600 "$STATE_BEFORE"
fi

RECEIPT_NAME="foundation-apply-receipt.json"
RECEIPT_PUBLIC_KEY_NAME="foundation-apply-receipt-public-key.pem"
RECEIPT_SIGNATURE_NAME="foundation-apply-receipt-signature.sigstore.json"
RECEIPT="$TEMP_DIR/$RECEIPT_NAME"
RECEIPT_SIGNATURE="$TEMP_DIR/$RECEIPT_SIGNATURE_NAME"
APPLY_RUN_ID="${APPLY_ID#orchestra-foundation-apply-}"
APPLY_RUN_ID="${APPLY_RUN_ID%.1}"
RECEIPT_ARGUMENTS=(
  build
  --verified-package "$VERIFIED_PACKAGE"
  --state-after "$STATE_AFTER"
  --apply-id "$APPLY_ID"
  --environment-approval-digest "$ENVIRONMENT_APPROVAL_DIGEST"
  --actor-id "$ACTOR_ID"
  --reason "$REASON"
  --source-revision "$SOURCE_REVISION"
  --workflow-run-id "$APPLY_RUN_ID"
  --workflow-run-attempt "1"
  --started-at "$STARTED_AT"
  --completed-at "$COMPLETED_AT"
  --signing-key "$RECEIPT_SIGNING_KEY"
  --signing-public-key "$RECEIPT_PUBLIC_KEY"
  --expected-public-key-digest "$EXPECTED_RECEIPT_PUBLIC_KEY_DIGEST"
  --expected-plan-statement-digest "$EXPECTED_PLAN_STATEMENT_DIGEST"
  --output "$RECEIPT"
)
if [[ -f "$STATE_BEFORE" ]]; then
  RECEIPT_ARGUMENTS+=(--state-before "$STATE_BEFORE")
fi
python3 "$RECEIPT_MODULE" "${RECEIPT_ARGUMENTS[@]}" >/dev/null

cosign sign-blob \
  --yes \
  --key "$RECEIPT_SIGNING_KEY" \
  --bundle "$RECEIPT_SIGNATURE" \
  "$RECEIPT" >/dev/null
chmod 0600 "$RECEIPT" "$RECEIPT_SIGNATURE"
python3 "$RECEIPT_MODULE" validate \
  --receipt "$RECEIPT" \
  --signing-public-key "$RECEIPT_PUBLIC_KEY" \
  --signature-bundle "$RECEIPT_SIGNATURE" \
  --expected-public-key-digest "$EXPECTED_RECEIPT_PUBLIC_KEY_DIGEST" >/dev/null

REPORT_PREFIX="foundation-apply-reports/v1/$PROFILE_ID/$SOURCE_REVISION/$PLAN_ID/$APPLY_ID"
upload_create_only() {
  local source="$1"
  local object_name="$2"
  gcloud storage cp \
    --if-generation-match=0 \
    --quiet \
    "$source" \
    "gs://$STATE_BUCKET/$REPORT_PREFIX/$object_name" >/dev/null
}

upload_create_only "$RECEIPT" "$RECEIPT_NAME"
upload_create_only "$RECEIPT_PUBLIC_KEY" "$RECEIPT_PUBLIC_KEY_NAME"
# The detached receipt signature is the completion marker and remains last.
upload_create_only "$RECEIPT_SIGNATURE" "$RECEIPT_SIGNATURE_NAME"

printf 'foundation_apply_receipt_published applyId=%s planId=%s prefix=%s receipt=%s infrastructureApplied=true receiptSelfAttested=true independentlyObserved=false campaignEvidence=false referenceProfileVerified=false\n' \
  "$APPLY_ID" "$PLAN_ID" "$REPORT_PREFIX" "$(raw_digest "$RECEIPT")"
