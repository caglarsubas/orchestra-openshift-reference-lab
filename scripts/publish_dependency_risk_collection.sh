#!/usr/bin/env bash
set -Eeuo pipefail

umask 077
export LC_ALL=C
export TZ=UTC

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AUTHORITY="$ROOT/config/dependency-risk-collection-execution.lock.json"
COLLECTION_MANIFEST_NAME="dependency-risk-scan-manifest.json"
COLLECTION_PUBLIC_KEY_NAME="collection-signing-public-key.pem"
PUBLISHER_SCRIPT_SOURCE="$ROOT/scripts/publish_dependency_risk_collection.sh"
CUSTODY_SCHEMA="$ROOT/schemas/dependency-risk-raw-custody-statement-v1.schema.json"

COLLECTION_DIR=""
RAW_EVIDENCE_BUCKET=""
SIGNING_KEY=""
EXPECTED_SIGNING_PUBLIC_KEY_DIGEST=""
ACTOR_IDENTITY_DIGEST=""

usage() {
  cat <<'EOF'
Usage: publish_dependency_risk_collection.sh \
  --collection-dir restricted/dependency-risk-collection-<run-id> \
  --raw-evidence-bucket <exact-bucket-name> \
  --signing-key gcpkms://projects/.../cryptoKeyVersions/... \
  --expected-signing-public-key-digest sha256:<digest> \
  --actor-identity-digest sha256:<digest>

Verify and package one complete dependency-risk collection, then create four
non-overwritable objects under its unique raw-evidence prefix. The detached
custody signature is uploaded last. This operation records no GCS generation,
does not complete independent custody verification, and grants no source,
mirror, activation, campaign, or reference-profile authority.
EOF
}

fail() {
  printf 'dependency_risk_raw_custody_failed code=%s\n' "$1" >&2
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

canonical_digest() {
  printf 'sha256:%s' "$(jq -S . "$1" | sha256sum | awk '{print $1}')"
}

while (($# > 0)); do
  case "$1" in
    --collection-dir)
      COLLECTION_DIR="${2:-}"
      shift 2
      ;;
    --raw-evidence-bucket)
      RAW_EVIDENCE_BUCKET="${2:-}"
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

[[ "$RAW_EVIDENCE_BUCKET" =~ ^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$ ]] || fail "raw_evidence_bucket_invalid"
if [[ "$SIGNING_KEY" =~ ^gcpkms://projects/[^/]+/locations/europe-west1/keyRings/orchestra-reference-evidence/cryptoKeys/dependency-risk-collection-signing/cryptoKeyVersions/[1-9][0-9]*$ ]]; then
  :
else
  fail "cloud_kms_signing_key_version_invalid"
fi
require_digest "$EXPECTED_SIGNING_PUBLIC_KEY_DIGEST" "expected_signing_public_key_digest_invalid"
require_digest "$ACTOR_IDENTITY_DIGEST" "actor_identity_digest_invalid"

for command_name in jq sha256sum awk mktemp date tar gzip cosign gcloud cmp python3 realpath; do
  require_command "$command_name"
done
for contract_file in "$AUTHORITY" "$PUBLISHER_SCRIPT_SOURCE" "$CUSTODY_SCHEMA"; do
  [[ -f "$contract_file" ]] || fail "contract_file_missing:$(basename "$contract_file")"
done

RESTRICTED_ROOT="$(realpath -m "$ROOT/restricted")"
COLLECTION_DIR="$(realpath -m "$COLLECTION_DIR")"
[[ "$COLLECTION_DIR" == "$RESTRICTED_ROOT/"* && -d "$COLLECTION_DIR" ]] || fail "collection_dir_invalid"
COLLECTION_MANIFEST="$COLLECTION_DIR/$COLLECTION_MANIFEST_NAME"
COLLECTION_PUBLIC_KEY="$COLLECTION_DIR/$COLLECTION_PUBLIC_KEY_NAME"
[[ -f "$COLLECTION_MANIFEST" && -f "$COLLECTION_PUBLIC_KEY" ]] || fail "collection_contract_missing"

python3 "$ROOT/scripts/verify_dependency_risk_collection.py" --manifest "$COLLECTION_MANIFEST" >/dev/null

PROFILE_ID="$(jq -er '.profileId' "$COLLECTION_MANIFEST")"
EVIDENCE_ID="$(jq -er '.evidenceId' "$COLLECTION_MANIFEST")"
[[ "$PROFILE_ID" == "orchestra-ocp-4.20-amd64-v1" ]] || fail "collection_profile_invalid"
[[ "$EVIDENCE_ID" =~ ^orchestra-dependency-risk-evidence-[a-z0-9][a-z0-9.-]+$ ]] || fail "collection_evidence_id_invalid"
[[ "$(jq -er '.targetClass' "$COLLECTION_MANIFEST")" == "vendor-reference-lab" ]] || fail "collection_target_class_invalid"
[[ "$(jq -er '.executionMode' "$COLLECTION_MANIFEST")" == "live" ]] || fail "collection_execution_mode_invalid"

AUTHORITY_DIGEST="$(canonical_digest "$AUTHORITY")"
TOPOLOGY_DIGEST="$(jq -er '.bindings.topologyDigest' "$AUTHORITY")"
DEPENDENCY_ADMISSION_DIGEST="$(jq -er '.bindings.dependencyAdmissionDigest' "$AUTHORITY")"
RELEASE_SET_DIGEST="$(jq -er '.bindings.releaseSetDigest' "$AUTHORITY")"
SOURCE_VERIFICATION_DIGEST="$(jq -er '.bindings.sourceVerificationDigest' "$AUTHORITY")"
RISK_POLICY_DIGEST="$(jq -er '.bindings.riskPolicyDigest' "$AUTHORITY")"
PREFLIGHT_AUTHORITY_DIGEST="$(jq -er '.bindings.preflightAuthorityDigest' "$AUTHORITY")"
COLLECTOR_SCRIPT_DIGEST="$(jq -er '.bindings.collectorScriptDigest' "$AUTHORITY")"
PUBLISHER_SCRIPT_DIGEST="$(raw_digest "$PUBLISHER_SCRIPT_SOURCE")"
CUSTODY_SCHEMA_DIGEST="$(raw_digest "$CUSTODY_SCHEMA")"
[[ "$(jq -er '.bindings.publisherScriptDigest' "$AUTHORITY")" == "$PUBLISHER_SCRIPT_DIGEST" ]] || fail "publisher_script_binding_invalid"
[[ "$(jq -er '.bindings.rawCustodySchemaDigest' "$AUTHORITY")" == "$CUSTODY_SCHEMA_DIGEST" ]] || fail "custody_schema_binding_invalid"

[[ "$(jq -er '.bindings.topologyDigest' "$COLLECTION_MANIFEST")" == "$TOPOLOGY_DIGEST" ]] || fail "collection_topology_binding_invalid"
[[ "$(jq -er '.bindings.dependencyAdmissionDigest' "$COLLECTION_MANIFEST")" == "$DEPENDENCY_ADMISSION_DIGEST" ]] || fail "collection_admission_binding_invalid"
[[ "$(jq -er '.bindings.releaseSetDigest' "$COLLECTION_MANIFEST")" == "$RELEASE_SET_DIGEST" ]] || fail "collection_release_set_binding_invalid"
[[ "$(jq -er '.bindings.sourceVerificationDigest' "$COLLECTION_MANIFEST")" == "$SOURCE_VERIFICATION_DIGEST" ]] || fail "collection_source_binding_invalid"
[[ "$(jq -er '.bindings.riskPolicyDigest' "$COLLECTION_MANIFEST")" == "$RISK_POLICY_DIGEST" ]] || fail "collection_risk_policy_binding_invalid"
[[ "$(jq -er '.collection.collectorScriptDigest' "$COLLECTION_MANIFEST")" == "$COLLECTOR_SCRIPT_DIGEST" ]] || fail "collection_script_binding_invalid"

TEMP_DIR="$(mktemp -d "$RESTRICTED_ROOT/.dependency-risk-publish.XXXXXX")"
chmod 0700 "$TEMP_DIR"
cleanup() {
  rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

KMS_PUBLIC_KEY="$TEMP_DIR/kms-signing-public-key.pem"
cosign public-key --key "$SIGNING_KEY" >"$KMS_PUBLIC_KEY"
chmod 0600 "$KMS_PUBLIC_KEY"
SIGNING_PUBLIC_KEY_DIGEST="$(raw_digest "$KMS_PUBLIC_KEY")"
[[ "$SIGNING_PUBLIC_KEY_DIGEST" == "$EXPECTED_SIGNING_PUBLIC_KEY_DIGEST" ]] || fail "signing_public_key_digest_mismatch"
[[ "$(raw_digest "$COLLECTION_PUBLIC_KEY")" == "$SIGNING_PUBLIC_KEY_DIGEST" ]] || fail "collection_public_key_digest_mismatch"
[[ "$(jq -er '.collection.signingPublicKeyDigest' "$COLLECTION_MANIFEST")" == "$SIGNING_PUBLIC_KEY_DIGEST" ]] || fail "collection_public_key_binding_invalid"
cmp -s "$KMS_PUBLIC_KEY" "$COLLECTION_PUBLIC_KEY" || fail "collection_public_key_bytes_invalid"

COLLECTION_MANIFEST_DIGEST="$(raw_digest "$COLLECTION_MANIFEST")"
COLLECTION_ATTESTATION_DIGEST="$(jq -er '.collection.collectionAttestationDigest' "$COLLECTION_MANIFEST")"
COLLECTION_SIGNATURE_BUNDLE_DIGEST="$(jq -er '.collection.collectionSignatureBundleDigest' "$COLLECTION_MANIFEST")"
COLLECTION_BASENAME="$(basename "$COLLECTION_DIR")"
RAW_ARCHIVE_NAME="dependency-risk-raw-collection.tar.gz"
RAW_ARCHIVE="$TEMP_DIR/$RAW_ARCHIVE_NAME"
tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
  -C "$(dirname "$COLLECTION_DIR")" -cf - "$COLLECTION_BASENAME" \
  | gzip -n >"$RAW_ARCHIVE"
chmod 0600 "$RAW_ARCHIVE"
RAW_ARCHIVE_DIGEST="$(raw_digest "$RAW_ARCHIVE")"

PREFIX="dependency-risk/v1/$PROFILE_ID/$EVIDENCE_ID"
CUSTODY_STATEMENT_NAME="dependency-risk-raw-custody-statement.json"
CUSTODY_SIGNATURE_NAME="dependency-risk-raw-custody-signature.sigstore.json"
CUSTODY_PUBLIC_KEY_NAME="dependency-risk-raw-custody-public-key.pem"
CUSTODY_STATEMENT="$TEMP_DIR/$CUSTODY_STATEMENT_NAME"
CUSTODY_SIGNATURE="$TEMP_DIR/$CUSTODY_SIGNATURE_NAME"
PUBLISHED_AT="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

jq -nS \
  --arg profileId "$PROFILE_ID" \
  --arg evidenceId "$EVIDENCE_ID" \
  --arg topologyDigest "$TOPOLOGY_DIGEST" \
  --arg dependencyAdmissionDigest "$DEPENDENCY_ADMISSION_DIGEST" \
  --arg releaseSetDigest "$RELEASE_SET_DIGEST" \
  --arg sourceVerificationDigest "$SOURCE_VERIFICATION_DIGEST" \
  --arg riskPolicyDigest "$RISK_POLICY_DIGEST" \
  --arg preflightAuthorityDigest "$PREFLIGHT_AUTHORITY_DIGEST" \
  --arg collectionExecutionAuthorityDigest "$AUTHORITY_DIGEST" \
  --arg collectorScriptDigest "$COLLECTOR_SCRIPT_DIGEST" \
  --arg publisherScriptDigest "$PUBLISHER_SCRIPT_DIGEST" \
  --arg rawCustodySchemaDigest "$CUSTODY_SCHEMA_DIGEST" \
  --arg manifestDigest "$COLLECTION_MANIFEST_DIGEST" \
  --arg collectionAttestationDigest "$COLLECTION_ATTESTATION_DIGEST" \
  --arg collectionSignatureBundleDigest "$COLLECTION_SIGNATURE_BUNDLE_DIGEST" \
  --arg rawArchiveObject "$RAW_ARCHIVE_NAME" \
  --arg rawArchiveDigest "$RAW_ARCHIVE_DIGEST" \
  --arg bucket "$RAW_EVIDENCE_BUCKET" \
  --arg prefix "$PREFIX" \
  --arg signingPublicKeyObject "$CUSTODY_PUBLIC_KEY_NAME" \
  --arg custodyStatementObject "$CUSTODY_STATEMENT_NAME" \
  --arg custodySignatureBundleObject "$CUSTODY_SIGNATURE_NAME" \
  --arg actorIdentityDigest "$ACTOR_IDENTITY_DIGEST" \
  --arg signingPublicKeyDigest "$SIGNING_PUBLIC_KEY_DIGEST" \
  --arg publishedAt "$PUBLISHED_AT" \
  '{schemaVersion:1,kind:"orchestra.dependency-risk.raw-custody-statement.v1",profileId:$profileId,targetClass:"vendor-reference-lab",executionMode:"live",evidenceId:$evidenceId,bindings:{topologyDigest:$topologyDigest,dependencyAdmissionDigest:$dependencyAdmissionDigest,releaseSetDigest:$releaseSetDigest,sourceVerificationDigest:$sourceVerificationDigest,riskPolicyDigest:$riskPolicyDigest,preflightAuthorityDigest:$preflightAuthorityDigest,collectionExecutionAuthorityDigest:$collectionExecutionAuthorityDigest,collectorScriptDigest:$collectorScriptDigest,publisherScriptDigest:$publisherScriptDigest,rawCustodySchemaDigest:$rawCustodySchemaDigest},collection:{manifestFile:"dependency-risk-scan-manifest.json",manifestDigest:$manifestDigest,collectionAttestationDigest:$collectionAttestationDigest,collectionSignatureBundleDigest:$collectionSignatureBundleDigest,rawArchiveObject:$rawArchiveObject,rawArchiveDigest:$rawArchiveDigest},storage:{bucket:$bucket,prefix:$prefix,signingPublicKeyObject:$signingPublicKeyObject,custodyStatementObject:$custodyStatementObject,custodySignatureBundleObject:$custodySignatureBundleObject,createOnlyGenerationPrecondition:0,objectGenerationRecorded:false,independentCustodyVerificationRequired:true},publisher:{executionClass:"signed-certification-runner",scriptDigest:$publisherScriptDigest,actorIdentityDigest:$actorIdentityDigest,signingPublicKeyDigest:$signingPublicKeyDigest,publishedAt:$publishedAt},claims:{rawCollectionUploaded:true,rawArtifactsRestricted:true,custodyVerified:false,sourceAdmissionAuthorized:false,mirrorAuthorization:false,activationAuthorized:false,campaignEvidence:false,referenceProfileVerified:false}}' \
  >"$CUSTODY_STATEMENT"
chmod 0600 "$CUSTODY_STATEMENT"

python3 "$ROOT/scripts/validate_dependency_risk_collection_custody.py" \
  --statement "$CUSTODY_STATEMENT" >/dev/null
CUSTODY_STATEMENT_DIGEST="$(raw_digest "$CUSTODY_STATEMENT")"
cosign sign-blob \
  --yes \
  --key "$SIGNING_KEY" \
  --bundle "$CUSTODY_SIGNATURE" \
  "$CUSTODY_STATEMENT" >/dev/null
chmod 0600 "$CUSTODY_SIGNATURE"
CUSTODY_SIGNATURE_DIGEST="$(raw_digest "$CUSTODY_SIGNATURE")"

upload_create_only() {
  local source="$1"
  local object_name="$2"
  gcloud storage cp \
    --if-generation-match=0 \
    --quiet \
    "$source" \
    "gs://$RAW_EVIDENCE_BUCKET/$PREFIX/$object_name" >/dev/null
}

upload_create_only "$RAW_ARCHIVE" "$RAW_ARCHIVE_NAME"
upload_create_only "$KMS_PUBLIC_KEY" "$CUSTODY_PUBLIC_KEY_NAME"
upload_create_only "$CUSTODY_STATEMENT" "$CUSTODY_STATEMENT_NAME"
# This detached signature is the completion marker and must remain last.
upload_create_only "$CUSTODY_SIGNATURE" "$CUSTODY_SIGNATURE_NAME"

printf 'dependency_risk_raw_custody_published evidenceId=%s prefix=%s archive=%s statement=%s signature=%s objectGenerationRecorded=false custodyVerified=false sourceAdmission=false mirrorAuthorization=false activation=false campaignEvidence=false referenceProfileVerified=false\n' \
  "$EVIDENCE_ID" "$PREFIX" "$RAW_ARCHIVE_DIGEST" "$CUSTODY_STATEMENT_DIGEST" "$CUSTODY_SIGNATURE_DIGEST"
