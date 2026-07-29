#!/usr/bin/env bash
set -Eeuo pipefail

umask 077
export LC_ALL=C
export TZ=UTC

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIVE_BUILDER="$ROOT/scripts/production_model_artifact_custody_live.py"
CUSTODY_VALIDATOR="$ROOT/scripts/production_model_artifact_custody.py"
CANDIDATE="$ROOT/config/production-model-artifact-candidate.lock.json"

BUCKET=""
RECORD_ID=""
SIGNING_KEY=""
EXPECTED_SIGNING_PUBLIC_KEY_DIGEST=""
VERIFIER_IDENTITY_DIGEST=""

fail() {
  printf 'production_model_custody_verification_failed code=%s\n' "$1" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: verify_and_publish_production_model_artifact_custody.sh \
  --bucket <dedicated-cmek-bucket> \
  --record-id production-model-custody-... \
  --signing-key gcpkms://projects/.../cryptoKeyVersions/N \
  --expected-signing-public-key-digest sha256:<digest> \
  --verifier-identity-digest sha256:<digest>

Inventory all four upload objects, reject oversized objects from metadata,
generation- and metageneration-pin every download, replay both SHA-256 digests,
build the custody record, sign it with the exact KMS key version, and publish
the detached signature last. This operation grants no licence, admission,
deployment, or campaign authority.
EOF
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required_command_missing:$1"
}

raw_digest() {
  printf 'sha256:%s' "$(sha256sum "$1" | awk '{print $1}')"
}

upload_create_only() {
  local source="$1"
  local object_name="$2"
  gcloud storage cp \
    --if-generation-match=0 \
    --quiet \
    "$source" \
    "gs://$BUCKET/$PUBLICATION_PREFIX/$object_name" >/dev/null
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
    --signing-key)
      SIGNING_KEY="${2:-}"
      shift 2
      ;;
    --expected-signing-public-key-digest)
      EXPECTED_SIGNING_PUBLIC_KEY_DIGEST="${2:-}"
      shift 2
      ;;
    --verifier-identity-digest)
      VERIFIER_IDENTITY_DIGEST="${2:-}"
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
[[ "$SIGNING_KEY" =~ ^gcpkms://projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/locations/europe-west1/keyRings/orchestra-reference-evidence/cryptoKeys/production-model-artifact-custody-verification-signing/cryptoKeyVersions/[1-9][0-9]*$ ]] || fail "signing_key_version_invalid"
[[ "$EXPECTED_SIGNING_PUBLIC_KEY_DIGEST" =~ ^sha256:[a-f0-9]{64}$ ]] || fail "expected_signing_public_key_digest_invalid"
[[ "$VERIFIER_IDENTITY_DIGEST" =~ ^sha256:[a-f0-9]{64}$ ]] || fail "verifier_identity_digest_invalid"
for command_name in gcloud python3 jq sha256sum awk mktemp cosign; do
  require_command "$command_name"
done

TEMP_DIR="$(mktemp -d)"
chmod 0700 "$TEMP_DIR"
cleanup() {
  rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

PROFILE_ID="orchestra-ocp-4.20-amd64-v1"
PREFIX="production-model-artifacts/v1/$PROFILE_ID/$RECORD_ID"
PUBLICATION_PREFIX="production-model-custody/v1/$PROFILE_ID/$RECORD_ID"
RAW_INVENTORY="$TEMP_DIR/gcloud-inventory.json"
INVENTORY="$TEMP_DIR/inventory.json"
DOWNLOAD_DIR="$TEMP_DIR/downloads"
mkdir -m 0700 "$DOWNLOAD_DIR"

gcloud storage ls --json "gs://$BUCKET/$PREFIX/*" >"$RAW_INVENTORY"
jq -eS \
  --arg bucket "$BUCKET" \
  --arg prefix "$PREFIX" \
  '
    def utc:
      if type != "string" then error("timestamp_invalid")
      elif endswith("+00:00") then sub("\\+00:00$"; "Z")
      elif endswith("Z") then .
      else error("timestamp_timezone_invalid")
      end;
    if type != "array" or length != 4 then error("object_count_invalid") else
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
              kmsKeyName: .metadata.kmsKeyName,
              eventBasedHold: (.metadata.eventBasedHold // false),
              temporaryHold: (.metadata.temporaryHold // false),
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

SOURCE_NAME="production-model-artifact-intake-observation.json"
RECEIPT_NAME="production-model-artifact-upload-receipt.json"
CHAT_FILENAME="$(jq -er '.models[] | select(.serviceId == "model-backend") | .filename' "$CANDIDATE")"
EMBEDDING_FILENAME="$(jq -er '.models[] | select(.serviceId == "embedding-model") | .filename' "$CANDIDATE")"
OBJECT_NAMES=("$SOURCE_NAME" "$RECEIPT_NAME" "$CHAT_FILENAME" "$EMBEDDING_FILENAME")

for object_name in "${OBJECT_NAMES[@]}"; do
  full_name="$PREFIX/$object_name"
  metadata="$(jq -cer --arg name "$full_name" \
    '.objects | map(select(.name == $name)) | if length == 1 then .[0] else error("object_missing") end' \
    "$INVENTORY")"
  generation="$(jq -er '.generation' <<<"$metadata")"
  metageneration="$(jq -er '.metageneration' <<<"$metadata")"
  size="$(jq -er '.sizeBytes' <<<"$metadata")"
  if [[ "$object_name" == "$SOURCE_NAME" || "$object_name" == "$RECEIPT_NAME" ]]; then
    ((size > 0 && size <= 65536)) || fail "control_object_size_invalid:$object_name"
  else
    expected_size="$(jq -er --arg filename "$object_name" \
      '.models[] | select(.filename == $filename) | .sizeBytes' "$CANDIDATE")"
    [[ "$size" == "$expected_size" ]] || fail "model_object_size_invalid:$object_name"
  fi
  gcloud storage cp \
    --if-generation-match="$generation" \
    --if-metageneration-match="$metageneration" \
    --quiet \
    "gs://$BUCKET/$full_name" \
    "$DOWNLOAD_DIR/$object_name" >/dev/null
  chmod 0600 "$DOWNLOAD_DIR/$object_name"
done

SOURCE_OBSERVATION="$DOWNLOAD_DIR/$SOURCE_NAME"
UPLOAD_RECEIPT="$DOWNLOAD_DIR/$RECEIPT_NAME"
python3 "$LIVE_BUILDER" validate-upload-receipt \
  --source-observation "$SOURCE_OBSERVATION" \
  --receipt "$UPLOAD_RECEIPT" >/dev/null

PUBLIC_KEY="$TEMP_DIR/production-model-artifact-custody-public-key.pem"
RECORD="$TEMP_DIR/production-model-artifact-custody-record.json"
SIGNATURE="$TEMP_DIR/production-model-artifact-custody-signature.sigstore.json"
cosign public-key --key "$SIGNING_KEY" >"$PUBLIC_KEY"
chmod 0600 "$PUBLIC_KEY"
[[ "$(raw_digest "$PUBLIC_KEY")" == "$EXPECTED_SIGNING_PUBLIC_KEY_DIGEST" ]] || fail "signing_public_key_digest_mismatch"

python3 "$LIVE_BUILDER" build-custody-record \
  --source-observation "$SOURCE_OBSERVATION" \
  --upload-receipt "$UPLOAD_RECEIPT" \
  --inventory "$INVENTORY" \
  --download-dir "$DOWNLOAD_DIR" \
  --record-id "$RECORD_ID" \
  --bucket "$BUCKET" \
  --verifier-identity-digest "$VERIFIER_IDENTITY_DIGEST" \
  --output "$RECORD" >/dev/null
python3 "$CUSTODY_VALIDATOR" validate-custody-record --record "$RECORD" >/dev/null

cosign sign-blob \
  --yes \
  --key "$SIGNING_KEY" \
  --bundle "$SIGNATURE" \
  "$RECORD" >/dev/null
chmod 0600 "$SIGNATURE"
cosign verify-blob \
  --key "$PUBLIC_KEY" \
  --bundle "$SIGNATURE" \
  "$RECORD" >/dev/null

upload_create_only "$RECORD" "production-model-artifact-custody-record.json"
upload_create_only "$PUBLIC_KEY" "production-model-artifact-custody-public-key.pem"
# This detached KMS signature is the completion marker and must remain last.
upload_create_only \
  "$SIGNATURE" \
  "production-model-artifact-custody-signature.sigstore.json"

printf 'production_model_custody_verification_published recordId=%s recordDigest=%s signatureDigest=%s generationPinned=true metagenerationPinned=true artifactCustodyVerified=true licenseApproved=false admissionAuthorized=false deploymentAuthorized=false campaignEvidence=false referenceProfileVerified=false\n' \
  "$RECORD_ID" \
  "$(jq -er '.recordDigest' "$RECORD")" \
  "$(raw_digest "$SIGNATURE")"
