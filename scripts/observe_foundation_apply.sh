#!/usr/bin/env bash
set -Eeuo pipefail

umask 077
export LC_ALL=C
export TZ=UTC

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FOUNDATION_DIR="$ROOT/infra/terraform/foundation"
REPORT_MODULE="$ROOT/scripts/foundation_observation_report.py"
AUTHORITY_COLLECTOR="$ROOT/scripts/collect_foundation_observer_authority.py"
PLAN_INVENTORY_MODULE="$ROOT/scripts/verify_foundation_plan_package.py"

STATE_BUCKET=""
SOURCE_REVISION=""
PLAN_ID=""
APPLY_ID=""
EXPECTED_RECEIPT_DIGEST=""
PLAN_SIGNING_KEY=""
EXPECTED_PLAN_PUBLIC_KEY_DIGEST=""
RECEIPT_SIGNING_KEY=""
EXPECTED_RECEIPT_PUBLIC_KEY_DIGEST=""
OBSERVATION_SIGNING_KEY=""
EXPECTED_OBSERVATION_PUBLIC_KEY_DIGEST=""
OBSERVATION_ID=""
ENVIRONMENT_APPROVAL_DIGEST=""
ACTOR_ID=""
REASON=""

usage() {
  cat <<'EOF'
Usage: observe_foundation_apply.sh \
  --state-bucket <bootstrap-state-bucket> \
  --source-revision <exact-main-sha> \
  --plan-id orchestra-foundation-plan-<run>.1 \
  --apply-id orchestra-foundation-apply-<run>.1 \
  --expected-receipt-digest sha256:<digest> \
  --plan-signing-key gcpkms://projects/.../cryptoKeyVersions/... \
  --expected-plan-public-key-digest sha256:<digest> \
  --receipt-signing-key gcpkms://projects/.../cryptoKeyVersions/... \
  --expected-receipt-public-key-digest sha256:<digest> \
  --observation-signing-key gcpkms://projects/.../cryptoKeyVersions/... \
  --expected-observation-public-key-digest sha256:<digest> \
  --observation-id orchestra-foundation-observation-<run>.1 \
  --environment-approval-digest sha256:<digest> \
  --actor-id <numeric-github-actor-id> \
  --reason <reviewed-reason>

Verify the immutable plan and self-attested apply receipt, pin the current
foundation state generation, run a read-only provider refresh without state
locking, reject all drift or identity mismatch, and publish a separately
signed observation. This is not campaign evidence or reference verification.
EOF
}

fail() {
  printf 'foundation_observation_failed code=%s\n' "$1" >&2
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
    --apply-id)
      APPLY_ID="${2:-}"
      shift 2
      ;;
    --expected-receipt-digest)
      EXPECTED_RECEIPT_DIGEST="${2:-}"
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
    --observation-signing-key)
      OBSERVATION_SIGNING_KEY="${2:-}"
      shift 2
      ;;
    --expected-observation-public-key-digest)
      EXPECTED_OBSERVATION_PUBLIC_KEY_DIGEST="${2:-}"
      shift 2
      ;;
    --observation-id)
      OBSERVATION_ID="${2:-}"
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

[[ "$STATE_BUCKET" =~ ^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$ ]] \
  || fail "state_bucket_invalid"
[[ "$SOURCE_REVISION" =~ ^[a-f0-9]{40}$ ]] \
  || fail "source_revision_invalid"
[[ "$PLAN_ID" =~ ^orchestra-foundation-plan-[1-9][0-9]*\.1$ ]] \
  || fail "plan_id_invalid"
[[ "$APPLY_ID" =~ ^orchestra-foundation-apply-[1-9][0-9]*\.1$ ]] \
  || fail "apply_id_invalid"
[[ "$OBSERVATION_ID" =~ ^orchestra-foundation-observation-[1-9][0-9]*\.1$ ]] \
  || fail "observation_id_invalid"
[[ "$ACTOR_ID" =~ ^[1-9][0-9]*$ ]] || fail "actor_id_invalid"
[[ ${#REASON} -ge 12 && ${#REASON} -le 500 ]] || fail "reason_invalid"
require_digest "$EXPECTED_RECEIPT_DIGEST" "expected_receipt_digest_invalid"
require_digest "$EXPECTED_PLAN_PUBLIC_KEY_DIGEST" \
  "expected_plan_public_key_digest_invalid"
require_digest "$EXPECTED_RECEIPT_PUBLIC_KEY_DIGEST" \
  "expected_receipt_public_key_digest_invalid"
require_digest "$EXPECTED_OBSERVATION_PUBLIC_KEY_DIGEST" \
  "expected_observation_public_key_digest_invalid"
require_digest "$ENVIRONMENT_APPROVAL_DIGEST" \
  "environment_approval_digest_invalid"
[[ "$PLAN_SIGNING_KEY" =~ ^gcpkms://projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/locations/europe-west1/keyRings/orchestra-lab-foundation-execution/cryptoKeys/foundation-plan-signing/cryptoKeyVersions/[1-9][0-9]*$ ]] \
  || fail "plan_signing_key_invalid"
[[ "$RECEIPT_SIGNING_KEY" =~ ^gcpkms://projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/locations/europe-west1/keyRings/orchestra-lab-foundation-execution/cryptoKeys/foundation-apply-receipt-signing/cryptoKeyVersions/[1-9][0-9]*$ ]] \
  || fail "receipt_signing_key_invalid"
[[ "$OBSERVATION_SIGNING_KEY" =~ ^gcpkms://projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/locations/europe-west1/keyRings/orchestra-lab-foundation-execution/cryptoKeys/foundation-observation-signing/cryptoKeyVersions/[1-9][0-9]*$ ]] \
  || fail "observation_signing_key_invalid"

for command_name in awk cmp cosign curl date gcloud jq mktemp python3 sha256sum terraform; do
  require_command "$command_name"
done
for contract_file in \
  "$REPORT_MODULE" \
  "$AUTHORITY_COLLECTOR" \
  "$PLAN_INVENTORY_MODULE"; do
  [[ -f "$contract_file" ]] || fail "contract_file_missing:$(basename "$contract_file")"
done
[[ "${TF_VAR_target_project_id:-}" =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]] \
  || fail "target_project_id_invalid"
[[ "${TF_VAR_services_project_id:-}" =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]] \
  || fail "services_project_id_invalid"

TEMP_DIR="$(mktemp -d "${RUNNER_TEMP:-/tmp}/foundation-observation.XXXXXX")"
chmod 0700 "$TEMP_DIR"
cleanup() {
  rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

PROFILE_ID="orchestra-ocp-4.20-amd64-v1"
PLAN_PREFIX="foundation-plans/v1/$PROFILE_ID/$SOURCE_REVISION/$PLAN_ID"
RECEIPT_PREFIX="foundation-apply-reports/v1/$PROFILE_ID/$SOURCE_REVISION/$PLAN_ID/$APPLY_ID"
REPORT_PREFIX="foundation-observations/v1/$PROFILE_ID/$SOURCE_REVISION/$PLAN_ID/$APPLY_ID/$OBSERVATION_ID"
DOWNLOAD_DIR="$TEMP_DIR/downloads"
mkdir -m 0700 "$DOWNLOAD_DIR"

OBSERVER_AUTHORITY_OBSERVATION="$TEMP_DIR/observer-authority-observation.json"
python3 "$AUTHORITY_COLLECTOR" \
  --target-project-id "$TF_VAR_target_project_id" \
  --services-project-id "$TF_VAR_services_project_id" \
  --state-bucket "$STATE_BUCKET" \
  --output "$OBSERVER_AUTHORITY_OBSERVATION" >/dev/null

collect_inventory() {
  local prefix="$1"
  local expected_count="$2"
  local output="$3"
  local raw
  raw="$TEMP_DIR/inventory-raw-$(basename "$output")"
  gcloud storage ls \
    --json \
    --limit="$((expected_count + 1))" \
    "gs://$STATE_BUCKET/$prefix/*" >"$raw"
  jq -eS \
    --arg bucket "$STATE_BUCKET" \
    --arg prefix "$prefix" \
    --argjson expected "$expected_count" \
    '
      def utc:
        if type != "string" then error("timestamp_invalid")
        elif endswith("+00:00") then sub("\\+00:00$"; "Z")
        elif endswith("Z") then .
        else error("timestamp_timezone_invalid")
        end;
      if type != "array" or length != $expected
      then error("object_count_invalid")
      else {
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
      } end
    ' "$raw" >"$output" \
    || fail "object_inventory_invalid"
  chmod 0600 "$output"
  rm -f "$raw"
}

download_from_inventory() {
  local inventory="$1"
  local prefix="$2"
  local object_name="$3"
  local destination="$4"
  local full_name="$prefix/$object_name"
  local metadata
  local generation
  local metageneration
  metadata="$(jq -cer \
    --arg name "$full_name" \
    '.objects | map(select(.name == $name))
      | if length == 1 then .[0] else error("object_missing") end' \
    "$inventory")" || fail "inventory_object_missing:$object_name"
  generation="$(jq -er '.generation' <<<"$metadata")"
  metageneration="$(jq -er '.metageneration' <<<"$metadata")"
  gcloud storage cp \
    --if-generation-match="$generation" \
    --if-metageneration-match="$metageneration" \
    --quiet \
    "gs://$STATE_BUCKET/$full_name" \
    "$destination" >/dev/null \
    || fail "generation_pinned_download_failed:$object_name"
  chmod 0600 "$destination"
}

RECEIPT_INVENTORY="$TEMP_DIR/receipt-inventory.json"
PLAN_INVENTORY="$TEMP_DIR/plan-inventory.json"
collect_inventory "$RECEIPT_PREFIX" 3 "$RECEIPT_INVENTORY"
collect_inventory "$PLAN_PREFIX" 5 "$PLAN_INVENTORY"
python3 "$REPORT_MODULE" receipt-inventory \
  --inventory "$RECEIPT_INVENTORY" \
  --bucket "$STATE_BUCKET" \
  --prefix "$RECEIPT_PREFIX" >/dev/null \
  || fail "receipt_inventory_pre_download_validation_failed"
python3 "$PLAN_INVENTORY_MODULE" inventory \
  --inventory "$PLAN_INVENTORY" \
  --source-revision "$SOURCE_REVISION" \
  --plan-id "$PLAN_ID" >/dev/null \
  || fail "plan_inventory_pre_download_validation_failed"

RECEIPT="$DOWNLOAD_DIR/foundation-apply-receipt.json"
RECEIPT_PUBLIC_KEY="$DOWNLOAD_DIR/foundation-apply-receipt-public-key.pem"
RECEIPT_SIGNATURE="$DOWNLOAD_DIR/foundation-apply-receipt-signature.sigstore.json"
download_from_inventory "$RECEIPT_INVENTORY" "$RECEIPT_PREFIX" \
  "foundation-apply-receipt.json" "$RECEIPT"
download_from_inventory "$RECEIPT_INVENTORY" "$RECEIPT_PREFIX" \
  "foundation-apply-receipt-public-key.pem" "$RECEIPT_PUBLIC_KEY"
download_from_inventory "$RECEIPT_INVENTORY" "$RECEIPT_PREFIX" \
  "foundation-apply-receipt-signature.sigstore.json" "$RECEIPT_SIGNATURE"

PLAN_SUMMARY="$DOWNLOAD_DIR/foundation-plan-summary.json"
PLAN_PUBLIC_KEY="$DOWNLOAD_DIR/foundation-plan-package-public-key.pem"
PLAN_STATEMENT="$DOWNLOAD_DIR/foundation-plan-package-statement.json"
PLAN_SIGNATURE="$DOWNLOAD_DIR/foundation-plan-package-signature.sigstore.json"
download_from_inventory "$PLAN_INVENTORY" "$PLAN_PREFIX" \
  "foundation-plan-summary.json" "$PLAN_SUMMARY"
download_from_inventory "$PLAN_INVENTORY" "$PLAN_PREFIX" \
  "foundation-plan-package-public-key.pem" "$PLAN_PUBLIC_KEY"
download_from_inventory "$PLAN_INVENTORY" "$PLAN_PREFIX" \
  "foundation-plan-package-statement.json" "$PLAN_STATEMENT"
download_from_inventory "$PLAN_INVENTORY" "$PLAN_PREFIX" \
  "foundation-plan-package-signature.sigstore.json" "$PLAN_SIGNATURE"

[[ "$(raw_digest "$RECEIPT")" == "$EXPECTED_RECEIPT_DIGEST" ]] \
  || fail "receipt_digest_mismatch"
PLAN_KMS_PUBLIC_KEY="$TEMP_DIR/plan-kms-public-key.pem"
RECEIPT_KMS_PUBLIC_KEY="$TEMP_DIR/receipt-kms-public-key.pem"
OBSERVATION_PUBLIC_KEY="$TEMP_DIR/foundation-observation-public-key.pem"
cosign public-key --key "$PLAN_SIGNING_KEY" >"$PLAN_KMS_PUBLIC_KEY"
cosign public-key --key "$RECEIPT_SIGNING_KEY" >"$RECEIPT_KMS_PUBLIC_KEY"
cosign public-key --key "$OBSERVATION_SIGNING_KEY" >"$OBSERVATION_PUBLIC_KEY"
chmod 0600 \
  "$PLAN_KMS_PUBLIC_KEY" \
  "$RECEIPT_KMS_PUBLIC_KEY" \
  "$OBSERVATION_PUBLIC_KEY"
[[ "$(raw_digest "$PLAN_KMS_PUBLIC_KEY")" == "$EXPECTED_PLAN_PUBLIC_KEY_DIGEST" ]] \
  || fail "plan_public_key_digest_mismatch"
[[ "$(raw_digest "$RECEIPT_KMS_PUBLIC_KEY")" == "$EXPECTED_RECEIPT_PUBLIC_KEY_DIGEST" ]] \
  || fail "receipt_public_key_digest_mismatch"
[[ "$(raw_digest "$OBSERVATION_PUBLIC_KEY")" == "$EXPECTED_OBSERVATION_PUBLIC_KEY_DIGEST" ]] \
  || fail "observation_public_key_digest_mismatch"
cmp -s "$PLAN_KMS_PUBLIC_KEY" "$PLAN_PUBLIC_KEY" \
  || fail "plan_public_key_bytes_mismatch"
cmp -s "$RECEIPT_KMS_PUBLIC_KEY" "$RECEIPT_PUBLIC_KEY" \
  || fail "receipt_public_key_bytes_mismatch"

STATE_ACCESS_TOKEN="$(gcloud auth print-access-token)"
[[ -n "$STATE_ACCESS_TOKEN" && "$STATE_ACCESS_TOKEN" != *$'\n'* ]] \
  || fail "state_access_token_invalid"
STATE_QUERY_CONFIG="$TEMP_DIR/state-query.curlrc"
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

capture_state_metadata() {
  local output="$1"
  local raw
  raw="$TEMP_DIR/state-metadata-raw-$(basename "$output")"
  local status
  status="$(
    curl \
      --config "$STATE_QUERY_CONFIG" \
      --request GET \
      --output "$raw" \
      --write-out '%{http_code}' \
      "https://storage.googleapis.com/storage/v1/b/$STATE_BUCKET/o/foundation%2Fdefault.tfstate?fields=name%2Cgeneration%2Cmetageneration%2Csize%2Ccrc32c%2Cmd5Hash%2Cetag%2CtimeCreated%2Cupdated"
  )" || fail "state_metadata_read_failed"
  [[ "$status" == "200" ]] || fail "state_object_missing"
  jq -eS \
    '
      def utc:
        if type != "string" then error("timestamp_invalid")
        elif endswith("+00:00") then sub("\\+00:00$"; "Z")
        elif endswith("Z") then .
        else error("timestamp_timezone_invalid")
        end;
      (.size | tonumber) as $size |
      if .name != "foundation/default.tfstate"
        or (.generation | type) != "string"
        or (.metageneration | type) != "string"
        or $size <= 0
        or $size > 67108864
      then error("state_metadata_invalid")
      else {
        name: .name,
        generation: .generation,
        metageneration: .metageneration,
        sizeBytes: $size,
        crc32c: .crc32c,
        md5Hash: (.md5Hash // null),
        etag: .etag,
        timeCreated: (.timeCreated | utc),
        updated: (.updated | utc)
      } end
    ' "$raw" >"$output" \
    || fail "state_metadata_invalid"
  chmod 0600 "$output"
  rm -f "$raw"
}

STATE_METADATA_BEFORE="$TEMP_DIR/state-metadata-before.json"
STATE_METADATA_AFTER="$TEMP_DIR/state-metadata-after.json"
STATE_OBJECT_DOWNLOAD="$TEMP_DIR/foundation-state-object.json"
STATE_PULL="$TEMP_DIR/foundation-state-pull.json"
capture_state_metadata "$STATE_METADATA_BEFORE"
state_generation="$(jq -er '.generation' "$STATE_METADATA_BEFORE")"
state_metageneration="$(jq -er '.metageneration' "$STATE_METADATA_BEFORE")"
gcloud storage cp \
  --if-generation-match="$state_generation" \
  --if-metageneration-match="$state_metageneration" \
  --quiet \
  "gs://$STATE_BUCKET/foundation/default.tfstate" \
  "$STATE_OBJECT_DOWNLOAD" >/dev/null \
  || fail "state_generation_pinned_download_failed"
chmod 0600 "$STATE_OBJECT_DOWNLOAD"

terraform -chdir="$FOUNDATION_DIR" fmt -check
terraform -chdir="$FOUNDATION_DIR" init \
  -input=false \
  -lockfile=readonly \
  -backend-config="bucket=$STATE_BUCKET" \
  -backend-config="prefix=foundation" >/dev/null
terraform -chdir="$FOUNDATION_DIR" validate >/dev/null
terraform -chdir="$FOUNDATION_DIR" state pull >"$STATE_PULL" \
  || fail "state_pull_failed"
chmod 0600 "$STATE_PULL"

REFRESH_PLAN="$TEMP_DIR/foundation-refresh.tfplan"
REFRESH_PLAN_JSON="$TEMP_DIR/foundation-refresh.json"
STARTED_AT="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
set +e
terraform -chdir="$FOUNDATION_DIR" plan \
  -refresh-only \
  -lock=false \
  -detailed-exitcode \
  -input=false \
  -out="$REFRESH_PLAN" >"$TEMP_DIR/refresh-plan.log" 2>&1
refresh_exit=$?
set -e
case "$refresh_exit" in
  0)
    ;;
  2)
    fail "terraform_provider_drift_detected"
    ;;
  *)
    fail "terraform_provider_refresh_failed"
    ;;
esac
terraform -chdir="$FOUNDATION_DIR" show -json "$REFRESH_PLAN" \
  >"$REFRESH_PLAN_JSON" \
  || fail "refresh_plan_render_failed"
chmod 0600 "$REFRESH_PLAN_JSON"
capture_state_metadata "$STATE_METADATA_AFTER"
cmp -s "$STATE_METADATA_BEFORE" "$STATE_METADATA_AFTER" \
  || fail "state_generation_changed_during_observation"
COMPLETED_AT="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

REPORT="$TEMP_DIR/foundation-observation.json"
REPORT_SIGNATURE="$TEMP_DIR/foundation-observation-signature.sigstore.json"
OBSERVATION_RUN_ID="${OBSERVATION_ID#orchestra-foundation-observation-}"
OBSERVATION_RUN_ID="${OBSERVATION_RUN_ID%.1}"
python3 "$REPORT_MODULE" build \
  --receipt "$RECEIPT" \
  --receipt-inventory "$RECEIPT_INVENTORY" \
  --receipt-public-key "$RECEIPT_PUBLIC_KEY" \
  --receipt-signature "$RECEIPT_SIGNATURE" \
  --expected-receipt-public-key-digest "$EXPECTED_RECEIPT_PUBLIC_KEY_DIGEST" \
  --expected-receipt-digest "$EXPECTED_RECEIPT_DIGEST" \
  --plan-statement "$PLAN_STATEMENT" \
  --plan-summary "$PLAN_SUMMARY" \
  --plan-inventory "$PLAN_INVENTORY" \
  --plan-public-key "$PLAN_PUBLIC_KEY" \
  --plan-signature "$PLAN_SIGNATURE" \
  --expected-plan-public-key-digest "$EXPECTED_PLAN_PUBLIC_KEY_DIGEST" \
  --state-object "$STATE_OBJECT_DOWNLOAD" \
  --state-pull "$STATE_PULL" \
  --state-metadata-before "$STATE_METADATA_BEFORE" \
  --state-metadata-after "$STATE_METADATA_AFTER" \
  --refresh-plan "$REFRESH_PLAN_JSON" \
  --observer-authority-observation "$OBSERVER_AUTHORITY_OBSERVATION" \
  --observation-id "$OBSERVATION_ID" \
  --environment-approval-digest "$ENVIRONMENT_APPROVAL_DIGEST" \
  --actor-id "$ACTOR_ID" \
  --reason "$REASON" \
  --source-revision "$SOURCE_REVISION" \
  --workflow-run-id "$OBSERVATION_RUN_ID" \
  --workflow-run-attempt "1" \
  --started-at "$STARTED_AT" \
  --completed-at "$COMPLETED_AT" \
  --signing-key "$OBSERVATION_SIGNING_KEY" \
  --signing-public-key "$OBSERVATION_PUBLIC_KEY" \
  --expected-signing-public-key-digest "$EXPECTED_OBSERVATION_PUBLIC_KEY_DIGEST" \
  --output "$REPORT" >/dev/null

cosign sign-blob \
  --yes \
  --key "$OBSERVATION_SIGNING_KEY" \
  --bundle "$REPORT_SIGNATURE" \
  "$REPORT" >/dev/null
chmod 0600 "$REPORT" "$REPORT_SIGNATURE"
python3 "$REPORT_MODULE" validate \
  --report "$REPORT" \
  --signing-public-key "$OBSERVATION_PUBLIC_KEY" \
  --signature-bundle "$REPORT_SIGNATURE" \
  --expected-public-key-digest "$EXPECTED_OBSERVATION_PUBLIC_KEY_DIGEST" \
  >/dev/null

upload_create_only() {
  local source="$1"
  local object_name="$2"
  gcloud storage cp \
    --if-generation-match=0 \
    --quiet \
    "$source" \
    "gs://$STATE_BUCKET/$REPORT_PREFIX/$object_name" >/dev/null \
    || fail "observation_upload_failed:$object_name"
}

upload_create_only "$REPORT" "foundation-observation.json"
upload_create_only "$OBSERVATION_PUBLIC_KEY" \
  "foundation-observation-public-key.pem"
# The detached signature is the completion marker and remains last.
upload_create_only "$REPORT_SIGNATURE" \
  "foundation-observation-signature.sigstore.json"

printf 'foundation_observation_published observationId=%s applyId=%s prefix=%s report=%s independentlyObserved=true campaignEvidence=false referenceProfileVerified=false customerCertified=false redHatCertified=false contractualSla=false\n' \
  "$OBSERVATION_ID" "$APPLY_ID" "$REPORT_PREFIX" "$(raw_digest "$REPORT")"
