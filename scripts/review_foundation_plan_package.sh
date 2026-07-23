#!/usr/bin/env bash
set -Eeuo pipefail

umask 077
export LC_ALL=C
export TZ=UTC

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLAN_VERIFIER="$ROOT/scripts/verify_foundation_plan_package.py"

STATE_BUCKET=""
SOURCE_REVISION=""
PLAN_ID=""
EXPECTED_PLAN_STATEMENT_DIGEST=""
EXPECTED_PLAN_PUBLIC_KEY_DIGEST=""
OUTPUT_DIR=""

usage() {
  cat <<'EOF'
Usage: review_foundation_plan_package.sh \
  --state-bucket <bootstrap-state-bucket> \
  --source-revision <exact-main-sha> \
  --plan-id orchestra-foundation-plan-<run>.1 \
  --expected-plan-statement-digest sha256:<digest> \
  --expected-plan-public-key-digest sha256:<digest> \
  --output-dir restricted/foundation-plan-review-<id>

Download one immutable plan package with exact generation preconditions,
verify its detached signature and payload-free replay, and render the full
value-bearing plan into ignored restricted storage for human review. This
command has no apply, signing, evidence, or campaign authority.
EOF
}

fail() {
  printf 'foundation_plan_review_failed code=%s\n' "$1" >&2
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
    --expected-plan-public-key-digest)
      EXPECTED_PLAN_PUBLIC_KEY_DIGEST="${2:-}"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="${2:-}"
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
[[ "$PLAN_ID" =~ ^orchestra-foundation-plan-[1-9][0-9]*\.1$ ]] || fail "plan_id_invalid"
require_digest "$EXPECTED_PLAN_STATEMENT_DIGEST" "expected_plan_statement_digest_invalid"
require_digest "$EXPECTED_PLAN_PUBLIC_KEY_DIGEST" "expected_plan_public_key_digest_invalid"
for command_name in awk cosign date gcloud git jq python3 realpath sha256sum terraform; do
  require_command "$command_name"
done
[[ -f "$PLAN_VERIFIER" ]] || fail "plan_verifier_missing"
[[ "$(git -C "$ROOT" rev-parse HEAD)" == "$SOURCE_REVISION" ]] \
  || fail "source_revision_checkout_mismatch"
[[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=all)" ]] \
  || fail "source_checkout_not_clean"

RESTRICTED_ROOT="$(realpath -m "$ROOT/restricted")"
OUTPUT_DIR="$(realpath -m "$OUTPUT_DIR")"
[[ "$OUTPUT_DIR" == "$RESTRICTED_ROOT/"* && ! -e "$OUTPUT_DIR" ]] \
  || fail "restricted_output_dir_invalid"
mkdir -p "$RESTRICTED_ROOT"
chmod 0700 "$RESTRICTED_ROOT"
mkdir -m 0700 "$OUTPUT_DIR"

PROFILE_ID="orchestra-ocp-4.20-amd64-v1"
PLAN_PREFIX="foundation-plans/v1/$PROFILE_ID/$SOURCE_REVISION/$PLAN_ID"
RAW_INVENTORY="$OUTPUT_DIR/gcloud-plan-inventory.json"
INVENTORY="$OUTPUT_DIR/plan-inventory.json"
DOWNLOAD_DIR="$OUTPUT_DIR/package"
PLAN_JSON="$OUTPUT_DIR/foundation-plan.json"
VERIFIED_PACKAGE="$OUTPUT_DIR/verified-package.json"
REVIEW_TEXT="$OUTPUT_DIR/foundation-plan-review.txt"
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

[[ "$(raw_digest "$DOWNLOAD_DIR/foundation-plan-package-public-key.pem")" == "$EXPECTED_PLAN_PUBLIC_KEY_DIGEST" ]] \
  || fail "plan_public_key_digest_mismatch"
terraform -chdir="$ROOT/infra/terraform/foundation" init \
  -backend=false \
  -input=false \
  -lockfile=readonly >/dev/null
if ! terraform -chdir="$ROOT/infra/terraform/foundation" show -json \
  "$DOWNLOAD_DIR/foundation.tfplan" >"$PLAN_JSON" 2>"$OUTPUT_DIR/plan-show-json.log"; then
  fail "saved_plan_json_render_failed"
fi
python3 "$PLAN_VERIFIER" verify \
  --inventory "$INVENTORY" \
  --download-dir "$DOWNLOAD_DIR" \
  --plan-json "$PLAN_JSON" \
  --source-revision "$SOURCE_REVISION" \
  --plan-id "$PLAN_ID" \
  --expected-statement-digest "$EXPECTED_PLAN_STATEMENT_DIGEST" \
  --expected-public-key-digest "$EXPECTED_PLAN_PUBLIC_KEY_DIGEST" \
  --verified-at "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
  --output "$VERIFIED_PACKAGE" >/dev/null
if ! terraform -chdir="$ROOT/infra/terraform/foundation" show -no-color \
  "$DOWNLOAD_DIR/foundation.tfplan" >"$REVIEW_TEXT" 2>"$OUTPUT_DIR/plan-show-text.log"; then
  fail "saved_plan_review_render_failed"
fi
chmod 0600 "$PLAN_JSON" "$VERIFIED_PACKAGE" "$REVIEW_TEXT"
rm -f "$OUTPUT_DIR/plan-show-json.log" "$OUTPUT_DIR/plan-show-text.log"

printf 'foundation_plan_review_ready planId=%s directory=%s statement=%s applyAuthorized=false infrastructureApplied=false independentlyObserved=false campaignEvidence=false referenceProfileVerified=false\n' \
  "$PLAN_ID" "$OUTPUT_DIR" "$EXPECTED_PLAN_STATEMENT_DIGEST"
