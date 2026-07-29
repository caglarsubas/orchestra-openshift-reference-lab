#!/usr/bin/env bash
set -Eeuo pipefail

umask 077
export LC_ALL=C
export TZ=UTC

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIVE_BUILDER="$ROOT/scripts/production_model_artifact_custody_live.py"
INTAKE="$ROOT/scripts/production_model_artifact_intake.py"
CANDIDATE="$ROOT/config/production-model-artifact-candidate.lock.json"

BUCKET=""
RECORD_ID=""
SOURCE_OBSERVATION=""
CHAT_MODEL=""
EMBEDDING_MODEL=""
ENCRYPTION_KEY=""
UPLOADER_IDENTITY_DIGEST=""

fail() {
  printf 'production_model_custody_upload_failed code=%s\n' "$1" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: upload_production_model_artifact_custody.sh \
  --bucket <dedicated-cmek-bucket> \
  --record-id production-model-custody-... \
  --source-observation <fresh-payload-free-observation.json> \
  --chat-model <fixed-private-inbox/chat.gguf> \
  --embedding-model <fixed-private-inbox/embedding.gguf> \
  --encryption-key projects/.../cryptoKeyVersions/N \
  --uploader-identity-digest sha256:<digest>

The two model files and source observation are copied directly to create-only
GCS objects. A payload-free upload receipt is the completion marker and is
uploaded last. This command creates no GitHub artifact and grants no custody
verification, licence, admission, deployment, or campaign authority.
EOF
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required_command_missing:$1"
}

upload_create_only() {
  local source="$1"
  local object_name="$2"
  gcloud storage cp \
    --if-generation-match=0 \
    --encryption-key="$ENCRYPTION_KEY" \
    --quiet \
    "$source" \
    "gs://$BUCKET/$PREFIX/$object_name" >/dev/null
}

while (($# > 0)); do
  case "$1" in
    --bucket)
      BUCKET="${2:-}"
      shift 2
      ;;
    --record-id)
      RECORD_ID="${2:-}"
      shift 2
      ;;
    --source-observation)
      SOURCE_OBSERVATION="${2:-}"
      shift 2
      ;;
    --chat-model)
      CHAT_MODEL="${2:-}"
      shift 2
      ;;
    --embedding-model)
      EMBEDDING_MODEL="${2:-}"
      shift 2
      ;;
    --encryption-key)
      ENCRYPTION_KEY="${2:-}"
      shift 2
      ;;
    --uploader-identity-digest)
      UPLOADER_IDENTITY_DIGEST="${2:-}"
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

[[ "$BUCKET" =~ ^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$ ]] || fail "bucket_invalid"
[[ "$RECORD_ID" =~ ^production-model-custody-[a-z0-9][a-z0-9._-]{7,127}$ ]] || fail "record_id_invalid"
[[ "$ENCRYPTION_KEY" =~ ^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/locations/europe-west1/keyRings/orchestra-reference-evidence/cryptoKeys/production-model-artifact-custody/cryptoKeyVersions/[1-9][0-9]*$ ]] || fail "encryption_key_version_invalid"
[[ "$UPLOADER_IDENTITY_DIGEST" =~ ^sha256:[a-f0-9]{64}$ ]] || fail "uploader_identity_digest_invalid"
for path in "$SOURCE_OBSERVATION" "$CHAT_MODEL" "$EMBEDDING_MODEL"; do
  [[ -f "$path" && ! -L "$path" ]] || fail "input_regular_file_required"
done
for command_name in gcloud python3 jq date mktemp realpath; do
  require_command "$command_name"
done

python3 "$INTAKE" verify --report "$SOURCE_OBSERVATION" >/dev/null
CHAT_FILENAME="$(jq -er '.models[] | select(.serviceId == "model-backend") | .filename' "$CANDIDATE")"
EMBEDDING_FILENAME="$(jq -er '.models[] | select(.serviceId == "embedding-model") | .filename' "$CANDIDATE")"
[[ "$(basename "$CHAT_MODEL")" == "$CHAT_FILENAME" ]] || fail "chat_model_filename_invalid"
[[ "$(basename "$EMBEDDING_MODEL")" == "$EMBEDDING_FILENAME" ]] || fail "embedding_model_filename_invalid"

TEMP_DIR="$(mktemp -d)"
chmod 0700 "$TEMP_DIR"
cleanup() {
  rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

PROFILE_ID="orchestra-ocp-4.20-amd64-v1"
PREFIX="production-model-artifacts/v1/$PROFILE_ID/$RECORD_ID"
COPY_STARTED_AT="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

upload_create_only \
  "$SOURCE_OBSERVATION" \
  "production-model-artifact-intake-observation.json"
upload_create_only "$CHAT_MODEL" "$CHAT_FILENAME"
upload_create_only "$EMBEDDING_MODEL" "$EMBEDDING_FILENAME"

COPY_COMPLETED_AT="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
RECEIPT="$TEMP_DIR/production-model-artifact-upload-receipt.json"
python3 "$LIVE_BUILDER" build-upload-receipt \
  --source-observation "$SOURCE_OBSERVATION" \
  --record-id "$RECORD_ID" \
  --bucket "$BUCKET" \
  --uploader-identity-digest "$UPLOADER_IDENTITY_DIGEST" \
  --copy-started-at "$COPY_STARTED_AT" \
  --copy-completed-at "$COPY_COMPLETED_AT" \
  --output "$RECEIPT" >/dev/null
python3 "$LIVE_BUILDER" validate-upload-receipt \
  --source-observation "$SOURCE_OBSERVATION" \
  --receipt "$RECEIPT" >/dev/null

# The payload-free receipt is the only upload-completion marker and stays last.
upload_create_only \
  "$RECEIPT" \
  "production-model-artifact-upload-receipt.json"

printf 'production_model_custody_upload_completed recordId=%s sourceObservation=%s receipt=%s createOnly=true defaultEventBasedHoldRequired=true artifactCustodyVerified=false licenseApproved=false admissionAuthorized=false deploymentAuthorized=false campaignEvidence=false referenceProfileVerified=false\n' \
  "$RECORD_ID" \
  "$(jq -er '.reportDigest' "$SOURCE_OBSERVATION")" \
  "$(jq -er '.receiptDigest' "$RECEIPT")"
