#!/usr/bin/env bash
set -Eeuo pipefail

umask 077
export LC_ALL=C
export TZ=UTC

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERIFIER="$ROOT/scripts/verify_sno_trial_dependency_risk_raw_custody.py"
REPORT_VALIDATOR="$ROOT/scripts/validate_sno_trial_dependency_risk_custody_report.py"

RAW_EVIDENCE_BUCKET=""
SIGNED_EVIDENCE_BUCKET=""
EVIDENCE_ID=""
VERIFICATION_ID=""
COLLECTION_SIGNING_KEY=""
EXPECTED_COLLECTION_PUBLIC_KEY_DIGEST=""
VERIFICATION_SIGNING_KEY=""
EXPECTED_VERIFICATION_PUBLIC_KEY_DIGEST=""
ACTOR_IDENTITY_DIGEST=""

usage() {
  cat <<'EOF'
Usage: verify_and_publish_sno_trial_dependency_risk_custody.sh \
  --raw-evidence-bucket <exact-bucket-name> \
  --signed-evidence-bucket <exact-bucket-name> \
  --evidence-id orchestra-sno-trial-dependency-risk-evidence-... \
  --verification-id orchestra-sno-trial-dependency-risk-custody-verification-... \
  --collection-signing-key gcpkms://projects/.../cryptoKeyVersions/... \
  --expected-collection-signing-public-key-digest sha256:<digest> \
  --verification-signing-key gcpkms://projects/.../cryptoKeyVersions/... \
  --expected-verification-signing-public-key-digest sha256:<digest> \
  --actor-identity-digest sha256:<digest>

Capture all four immutable SNO raw-object generations, generation-pin each
download, verify both signatures and the archive, recompute risk evidence,
then create a separately signed custody report. The report signature is
uploaded last and grants no admission, activation, or deployment authority.
EOF
}

fail() {
  printf 'sno_dependency_risk_custody_verification_failed code=%s\n' "$1" >&2
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
    --raw-evidence-bucket)
      RAW_EVIDENCE_BUCKET="${2:-}"
      shift 2
      ;;
    --signed-evidence-bucket)
      SIGNED_EVIDENCE_BUCKET="${2:-}"
      shift 2
      ;;
    --evidence-id)
      EVIDENCE_ID="${2:-}"
      shift 2
      ;;
    --verification-id)
      VERIFICATION_ID="${2:-}"
      shift 2
      ;;
    --collection-signing-key)
      COLLECTION_SIGNING_KEY="${2:-}"
      shift 2
      ;;
    --expected-collection-signing-public-key-digest)
      EXPECTED_COLLECTION_PUBLIC_KEY_DIGEST="${2:-}"
      shift 2
      ;;
    --verification-signing-key)
      VERIFICATION_SIGNING_KEY="${2:-}"
      shift 2
      ;;
    --expected-verification-signing-public-key-digest)
      EXPECTED_VERIFICATION_PUBLIC_KEY_DIGEST="${2:-}"
      shift 2
      ;;
    --actor-identity-digest)
      ACTOR_IDENTITY_DIGEST="${2:-}"
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

[[ "$RAW_EVIDENCE_BUCKET" =~ ^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$ ]] \
  || fail "raw_evidence_bucket_invalid"
[[ "$SIGNED_EVIDENCE_BUCKET" =~ ^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$ ]] \
  || fail "signed_evidence_bucket_invalid"
[[ "$RAW_EVIDENCE_BUCKET" != "$SIGNED_EVIDENCE_BUCKET" ]] \
  || fail "evidence_bucket_separation_invalid"
[[ "$EVIDENCE_ID" =~ ^orchestra-sno-trial-dependency-risk-evidence-[a-z0-9][a-z0-9.-]+$ ]] \
  || fail "evidence_id_invalid"
[[ "$VERIFICATION_ID" =~ ^orchestra-sno-trial-dependency-risk-custody-verification-[a-z0-9][a-z0-9.-]+$ ]] \
  || fail "verification_id_invalid"
if [[ "$COLLECTION_SIGNING_KEY" =~ ^gcpkms://projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/locations/europe-west1/keyRings/orchestra-reference-evidence/cryptoKeys/dependency-risk-collection-signing/cryptoKeyVersions/[1-9][0-9]*$ ]]; then
  :
else
  fail "collection_signing_key_version_invalid"
fi
if [[ "$VERIFICATION_SIGNING_KEY" =~ ^gcpkms://projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/locations/europe-west1/keyRings/orchestra-reference-evidence/cryptoKeys/dependency-risk-custody-verification-signing/cryptoKeyVersions/[1-9][0-9]*$ ]]; then
  :
else
  fail "verification_signing_key_version_invalid"
fi
require_digest "$EXPECTED_COLLECTION_PUBLIC_KEY_DIGEST" \
  "expected_collection_public_key_digest_invalid"
require_digest "$EXPECTED_VERIFICATION_PUBLIC_KEY_DIGEST" \
  "expected_verification_public_key_digest_invalid"
require_digest "$ACTOR_IDENTITY_DIGEST" "actor_identity_digest_invalid"

for command_name in jq sha256sum awk mktemp date cosign gcloud python3 realpath; do
  require_command "$command_name"
done
for contract_file in "$VERIFIER" "$REPORT_VALIDATOR"; do
  [[ -f "$contract_file" ]] \
    || fail "contract_file_missing:$(basename "$contract_file")"
done
python3 "$ROOT/scripts/sno_trial_dependency_risk_custody.py" \
  validate-policy >/dev/null

RESTRICTED_ROOT="$(realpath -m "$ROOT/restricted")"
mkdir -p "$RESTRICTED_ROOT"
chmod 0700 "$RESTRICTED_ROOT"
TEMP_DIR="$(mktemp -d "$RESTRICTED_ROOT/.sno-dependency-risk-custody.XXXXXX")"
chmod 0700 "$TEMP_DIR"
cleanup() {
  rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

PROFILE_ID="orchestra-ocp-sno-trial-amd64-v1"
RAW_PREFIX="dependency-risk/sno-trial/v1/$PROFILE_ID/$EVIDENCE_ID"
REPORT_PREFIX="dependency-risk-custody/sno-trial/v1/$PROFILE_ID/$EVIDENCE_ID/$VERIFICATION_ID"
RAW_INVENTORY="$TEMP_DIR/raw-gcloud-inventory.json"
INVENTORY="$TEMP_DIR/raw-inventory.json"
DOWNLOAD_DIR="$TEMP_DIR/downloads"
mkdir -m 0700 "$DOWNLOAD_DIR"
STARTED_AT="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

gcloud storage ls --json "gs://$RAW_EVIDENCE_BUCKET/$RAW_PREFIX/*" \
  >"$RAW_INVENTORY"
jq -eS \
  --arg bucket "$RAW_EVIDENCE_BUCKET" \
  --arg prefix "$RAW_PREFIX" \
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

OBJECT_NAMES=(
  sno-dependency-risk-raw-collection.tar.gz
  sno-dependency-risk-raw-custody-public-key.pem
  sno-dependency-risk-raw-custody-statement.json
  sno-dependency-risk-raw-custody-signature.sigstore.json
)
for object_name in "${OBJECT_NAMES[@]}"; do
  full_name="$RAW_PREFIX/$object_name"
  metadata="$(jq -cer --arg name "$full_name" \
    '.objects | map(select(.name == $name)) | if length == 1 then .[0] else error("object_missing") end' \
    "$INVENTORY")"
  generation="$(jq -er '.generation' <<<"$metadata")"
  metageneration="$(jq -er '.metageneration' <<<"$metadata")"
  gcloud storage cp \
    --if-generation-match="$generation" \
    --if-metageneration-match="$metageneration" \
    --quiet \
    "gs://$RAW_EVIDENCE_BUCKET/$full_name" \
    "$DOWNLOAD_DIR/$object_name" >/dev/null
  chmod 0600 "$DOWNLOAD_DIR/$object_name"
done

COLLECTION_KMS_PUBLIC_KEY="$TEMP_DIR/collection-kms-public-key.pem"
VERIFICATION_PUBLIC_KEY="$TEMP_DIR/verification-signing-public-key.pem"
cosign public-key --key "$COLLECTION_SIGNING_KEY" \
  >"$COLLECTION_KMS_PUBLIC_KEY"
cosign public-key --key "$VERIFICATION_SIGNING_KEY" \
  >"$VERIFICATION_PUBLIC_KEY"
chmod 0600 "$COLLECTION_KMS_PUBLIC_KEY" "$VERIFICATION_PUBLIC_KEY"
[[ "$(raw_digest "$COLLECTION_KMS_PUBLIC_KEY")" == "$EXPECTED_COLLECTION_PUBLIC_KEY_DIGEST" ]] \
  || fail "collection_public_key_digest_mismatch"
[[ "$(raw_digest "$VERIFICATION_PUBLIC_KEY")" == "$EXPECTED_VERIFICATION_PUBLIC_KEY_DIGEST" ]] \
  || fail "verification_public_key_digest_mismatch"

REPORT_NAME="sno-dependency-risk-custody-verification.json"
REPORT_PUBLIC_KEY_NAME="sno-dependency-risk-custody-verification-public-key.pem"
REPORT_SIGNATURE_NAME="sno-dependency-risk-custody-verification-signature.sigstore.json"
REPORT="$TEMP_DIR/$REPORT_NAME"
REPORT_SIGNATURE="$TEMP_DIR/$REPORT_SIGNATURE_NAME"

python3 "$VERIFIER" \
  --inventory "$INVENTORY" \
  --download-dir "$DOWNLOAD_DIR" \
  --collection-kms-public-key "$COLLECTION_KMS_PUBLIC_KEY" \
  --collection-signing-key "$COLLECTION_SIGNING_KEY" \
  --expected-collection-signing-public-key-digest "$EXPECTED_COLLECTION_PUBLIC_KEY_DIGEST" \
  --verification-signing-key "$VERIFICATION_SIGNING_KEY" \
  --verification-signing-public-key "$VERIFICATION_PUBLIC_KEY" \
  --expected-verification-signing-public-key-digest "$EXPECTED_VERIFICATION_PUBLIC_KEY_DIGEST" \
  --verification-id "$VERIFICATION_ID" \
  --evidence-id "$EVIDENCE_ID" \
  --actor-identity-digest "$ACTOR_IDENTITY_DIGEST" \
  --started-at "$STARTED_AT" \
  --output "$REPORT" >/dev/null
python3 "$REPORT_VALIDATOR" --report "$REPORT" >/dev/null

cosign sign-blob \
  --yes \
  --key "$VERIFICATION_SIGNING_KEY" \
  --bundle "$REPORT_SIGNATURE" \
  "$REPORT" >/dev/null
chmod 0600 "$REPORT" "$REPORT_SIGNATURE"
python3 "$REPORT_VALIDATOR" \
  --report "$REPORT" \
  --verification-public-key "$VERIFICATION_PUBLIC_KEY" \
  --signature-bundle "$REPORT_SIGNATURE" \
  --expected-verification-public-key-digest \
    "$EXPECTED_VERIFICATION_PUBLIC_KEY_DIGEST" >/dev/null

upload_create_only() {
  local source="$1"
  local object_name="$2"
  gcloud storage cp \
    --if-generation-match=0 \
    --quiet \
    "$source" \
    "gs://$SIGNED_EVIDENCE_BUCKET/$REPORT_PREFIX/$object_name" >/dev/null
}

upload_create_only "$REPORT" "$REPORT_NAME"
upload_create_only "$VERIFICATION_PUBLIC_KEY" "$REPORT_PUBLIC_KEY_NAME"
# This detached report signature is the completion marker and must remain last.
upload_create_only "$REPORT_SIGNATURE" "$REPORT_SIGNATURE_NAME"

printf 'sno_dependency_risk_custody_verification_published verificationId=%s evidenceId=%s report=%s signature=%s objectGenerationsRecorded=true custodyVerified=true reportGenerationRecorded=false sourceAdmission=false mirrorAuthorization=false activation=false deployment=false campaignEvidence=false referenceProfileVerified=false\n' \
  "$VERIFICATION_ID" "$EVIDENCE_ID" "$(raw_digest "$REPORT")" \
  "$(raw_digest "$REPORT_SIGNATURE")"
