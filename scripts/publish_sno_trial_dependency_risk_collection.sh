#!/usr/bin/env bash
set -Eeuo pipefail

umask 077
export LC_ALL=C
export TZ=UTC

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CUSTODY_POLICY="$ROOT/config/sno-trial-dependency-risk-custody-policy.lock.json"
RISK_POLICY="$ROOT/config/sno-trial-dependency-risk-policy.lock.json"
PUBLISHER="$ROOT/scripts/publish_sno_trial_dependency_risk_collection.sh"
RAW_CUSTODY_SCHEMA="$ROOT/schemas/sno-trial-dependency-risk-raw-custody-statement-v1.schema.json"

COLLECTION_DIR=""
RAW_EVIDENCE_BUCKET=""
SIGNING_KEY=""
EXPECTED_SIGNING_PUBLIC_KEY_DIGEST=""
ACTOR_IDENTITY_DIGEST=""

usage() {
  cat <<'EOF'
Usage: publish_sno_trial_dependency_risk_collection.sh \
  --collection-dir restricted/sno-dependency-risk-collection-<run-id> \
  --raw-evidence-bucket <exact-bucket-name> \
  --signing-key gcpkms://projects/.../cryptoKeyVersions/... \
  --expected-signing-public-key-digest sha256:<digest> \
  --actor-identity-digest sha256:<digest>

Verify and package one SNO dependency-risk collection, then create four
non-overwritable objects under the existing dependency-risk managed folder.
The detached custody signature is uploaded last. This operation does not
record object generations or grant source, mirror, activation, deployment,
campaign, or reference-profile authority.
EOF
}

fail() {
  printf 'sno_dependency_risk_raw_custody_failed code=%s\n' "$1" >&2
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

[[ "$RAW_EVIDENCE_BUCKET" =~ ^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$ ]] \
  || fail "raw_evidence_bucket_invalid"
if [[ "$SIGNING_KEY" =~ ^gcpkms://projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/locations/europe-west1/keyRings/orchestra-reference-evidence/cryptoKeys/dependency-risk-collection-signing/cryptoKeyVersions/[1-9][0-9]*$ ]]; then
  :
else
  fail "cloud_kms_signing_key_version_invalid"
fi
require_digest "$EXPECTED_SIGNING_PUBLIC_KEY_DIGEST" \
  "expected_signing_public_key_digest_invalid"
require_digest "$ACTOR_IDENTITY_DIGEST" "actor_identity_digest_invalid"

for command_name in jq sha256sum awk mktemp date tar gzip cosign gcloud cmp python3 realpath; do
  require_command "$command_name"
done
for contract_file in "$CUSTODY_POLICY" "$RISK_POLICY" "$PUBLISHER" "$RAW_CUSTODY_SCHEMA"; do
  [[ -f "$contract_file" ]] \
    || fail "contract_file_missing:$(basename "$contract_file")"
done

RESTRICTED_ROOT="$(realpath -m "$ROOT/restricted")"
COLLECTION_DIR="$(realpath -m "$COLLECTION_DIR")"
[[ "$COLLECTION_DIR" == "$RESTRICTED_ROOT/"* && -d "$COLLECTION_DIR" ]] \
  || fail "collection_dir_invalid"

MANIFEST="$COLLECTION_DIR/collection-manifest.json"
RISK_EVIDENCE="$COLLECTION_DIR/risk-evidence.json"
COLLECTION_STATEMENT="$COLLECTION_DIR/collection-statement.json"
COLLECTION_SIGNATURE="$COLLECTION_DIR/collection-statement.sigstore.json"
COLLECTION_PUBLIC_KEY="$COLLECTION_DIR/collection-signing-public-key.pem"
for collection_file in \
  "$MANIFEST" "$RISK_EVIDENCE" "$COLLECTION_STATEMENT" \
  "$COLLECTION_SIGNATURE" "$COLLECTION_PUBLIC_KEY"; do
  [[ -f "$collection_file" ]] \
    || fail "collection_contract_missing:$(basename "$collection_file")"
done

python3 "$ROOT/scripts/sno_trial_dependency_risk_custody.py" \
  validate-policy >/dev/null
python3 "$ROOT/scripts/sno_trial_dependency_risk.py" \
  validate-evidence --report "$RISK_EVIDENCE" >/dev/null

PROFILE_ID="$(jq -er '.profileId' "$RISK_EVIDENCE")"
EVIDENCE_ID="$(jq -er '.evidenceId' "$RISK_EVIDENCE")"
[[ "$PROFILE_ID" == "orchestra-ocp-sno-trial-amd64-v1" ]] \
  || fail "collection_profile_invalid"
[[ "$EVIDENCE_ID" =~ ^orchestra-sno-trial-dependency-risk-evidence-[a-z0-9][a-z0-9.-]+$ ]] \
  || fail "collection_evidence_id_invalid"
[[ "$(jq -er '.targetClass' "$RISK_EVIDENCE")" == "engineering-trial" ]] \
  || fail "collection_target_class_invalid"
[[ "$(jq -er '.executionMode' "$RISK_EVIDENCE")" == "live" ]] \
  || fail "collection_execution_mode_invalid"
[[ "$(jq -er '.evidenceId' "$MANIFEST")" == "$EVIDENCE_ID" ]] \
  || fail "collection_manifest_identity_invalid"
[[ "$(jq -er '.evidenceId' "$COLLECTION_STATEMENT")" == "$EVIDENCE_ID" ]] \
  || fail "collection_statement_identity_invalid"

PUBLISHER_DIGEST="$(raw_digest "$PUBLISHER")"
RAW_CUSTODY_SCHEMA_DIGEST="$(raw_digest "$RAW_CUSTODY_SCHEMA")"
[[ "$(jq -er '.bindings.publisherScriptDigest' "$CUSTODY_POLICY")" == "$PUBLISHER_DIGEST" ]] \
  || fail "publisher_script_binding_invalid"
[[ "$(jq -er '.bindings.rawCustodySchemaDigest' "$CUSTODY_POLICY")" == "$RAW_CUSTODY_SCHEMA_DIGEST" ]] \
  || fail "raw_custody_schema_binding_invalid"

TEMP_DIR="$(mktemp -d "$RESTRICTED_ROOT/.sno-dependency-risk-publish.XXXXXX")"
chmod 0700 "$TEMP_DIR"
cleanup() {
  rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

KMS_PUBLIC_KEY="$TEMP_DIR/kms-signing-public-key.pem"
cosign public-key --key "$SIGNING_KEY" >"$KMS_PUBLIC_KEY"
chmod 0600 "$KMS_PUBLIC_KEY"
SIGNING_PUBLIC_KEY_DIGEST="$(raw_digest "$KMS_PUBLIC_KEY")"
[[ "$SIGNING_PUBLIC_KEY_DIGEST" == "$EXPECTED_SIGNING_PUBLIC_KEY_DIGEST" ]] \
  || fail "signing_public_key_digest_mismatch"
[[ "$(raw_digest "$COLLECTION_PUBLIC_KEY")" == "$SIGNING_PUBLIC_KEY_DIGEST" ]] \
  || fail "collection_public_key_digest_mismatch"
cmp -s "$KMS_PUBLIC_KEY" "$COLLECTION_PUBLIC_KEY" \
  || fail "collection_public_key_bytes_invalid"
cosign verify-blob \
  --key "$KMS_PUBLIC_KEY" \
  --bundle "$COLLECTION_SIGNATURE" \
  "$COLLECTION_STATEMENT" >/dev/null

COLLECTION_STATEMENT_DIGEST="$(raw_digest "$COLLECTION_STATEMENT")"
COLLECTION_SIGNATURE_DIGEST="$(raw_digest "$COLLECTION_SIGNATURE")"
[[ "$(jq -er '.collection.collectionStatementDigest' "$RISK_EVIDENCE")" == "$COLLECTION_STATEMENT_DIGEST" ]] \
  || fail "risk_evidence_collection_statement_binding_invalid"
[[ "$(jq -er '.collection.collectionSignatureBundleDigest' "$RISK_EVIDENCE")" == "$COLLECTION_SIGNATURE_DIGEST" ]] \
  || fail "risk_evidence_collection_signature_binding_invalid"
[[ "$(jq -er '.collector.signingPublicKeyDigest' "$COLLECTION_STATEMENT")" == "$SIGNING_PUBLIC_KEY_DIGEST" ]] \
  || fail "collection_statement_public_key_binding_invalid"

MANIFEST_DIGEST="$(raw_digest "$MANIFEST")"
RISK_EVIDENCE_DIGEST="$(raw_digest "$RISK_EVIDENCE")"
COLLECTION_BASENAME="$(basename "$COLLECTION_DIR")"
RAW_ARCHIVE_NAME="sno-dependency-risk-raw-collection.tar.gz"
RAW_ARCHIVE="$TEMP_DIR/$RAW_ARCHIVE_NAME"
tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
  -C "$(dirname "$COLLECTION_DIR")" -cf - "$COLLECTION_BASENAME" \
  | gzip -n >"$RAW_ARCHIVE"
chmod 0600 "$RAW_ARCHIVE"
RAW_ARCHIVE_DIGEST="$(raw_digest "$RAW_ARCHIVE")"

PREFIX="dependency-risk/sno-trial/v1/$PROFILE_ID/$EVIDENCE_ID"
CUSTODY_PUBLIC_KEY_NAME="sno-dependency-risk-raw-custody-public-key.pem"
CUSTODY_STATEMENT_NAME="sno-dependency-risk-raw-custody-statement.json"
CUSTODY_SIGNATURE_NAME="sno-dependency-risk-raw-custody-signature.sigstore.json"
CUSTODY_STATEMENT="$TEMP_DIR/$CUSTODY_STATEMENT_NAME"
CUSTODY_SIGNATURE="$TEMP_DIR/$CUSTODY_SIGNATURE_NAME"
PUBLISHED_AT="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

jq -nS \
  --arg profileId "$PROFILE_ID" \
  --arg evidenceId "$EVIDENCE_ID" \
  --arg artifactSetDigest "$(jq -er '.bindings.artifactSetDigest' "$CUSTODY_POLICY")" \
  --arg releaseSetDigest "$(jq -er '.bindings.releaseSetDigest' "$CUSTODY_POLICY")" \
  --arg riskPolicyDigest "$(jq -er '.bindings.riskPolicyDigest' "$CUSTODY_POLICY")" \
  --arg collectionAuthorityDigest "$(jq -er '.bindings.collectionAuthorityDigest' "$CUSTODY_POLICY")" \
  --arg collectorScriptDigest "$(jq -er '.collectionPolicy.collectorScriptDigest' "$RISK_POLICY")" \
  --arg publisherScriptDigest "$PUBLISHER_DIGEST" \
  --arg rawCustodySchemaDigest "$RAW_CUSTODY_SCHEMA_DIGEST" \
  --arg manifestDigest "$MANIFEST_DIGEST" \
  --arg riskEvidenceDigest "$RISK_EVIDENCE_DIGEST" \
  --arg collectionStatementDigest "$COLLECTION_STATEMENT_DIGEST" \
  --arg collectionSignatureBundleDigest "$COLLECTION_SIGNATURE_DIGEST" \
  --arg rawArchiveDigest "$RAW_ARCHIVE_DIGEST" \
  --arg bucket "$RAW_EVIDENCE_BUCKET" \
  --arg prefix "$PREFIX" \
  --arg actorIdentityDigest "$ACTOR_IDENTITY_DIGEST" \
  --arg signingPublicKeyDigest "$SIGNING_PUBLIC_KEY_DIGEST" \
  --arg publishedAt "$PUBLISHED_AT" \
  '{
    schemaVersion:1,
    kind:"orchestra.openshift.sno-trial-dependency-risk.raw-custody-statement.v1",
    profileId:$profileId,
    targetClass:"engineering-trial",
    executionMode:"live",
    evidenceId:$evidenceId,
    bindings:{
      artifactSetDigest:$artifactSetDigest,
      releaseSetDigest:$releaseSetDigest,
      riskPolicyDigest:$riskPolicyDigest,
      collectionAuthorityDigest:$collectionAuthorityDigest,
      collectorScriptDigest:$collectorScriptDigest,
      publisherScriptDigest:$publisherScriptDigest,
      rawCustodySchemaDigest:$rawCustodySchemaDigest
    },
    collection:{
      manifestFile:"collection-manifest.json",
      manifestDigest:$manifestDigest,
      riskEvidenceFile:"risk-evidence.json",
      riskEvidenceDigest:$riskEvidenceDigest,
      collectionStatementDigest:$collectionStatementDigest,
      collectionSignatureBundleDigest:$collectionSignatureBundleDigest,
      rawArchiveObject:"sno-dependency-risk-raw-collection.tar.gz",
      rawArchiveDigest:$rawArchiveDigest
    },
    storage:{
      bucket:$bucket,
      prefix:$prefix,
      signingPublicKeyObject:"sno-dependency-risk-raw-custody-public-key.pem",
      custodyStatementObject:"sno-dependency-risk-raw-custody-statement.json",
      custodySignatureBundleObject:"sno-dependency-risk-raw-custody-signature.sigstore.json",
      createOnlyGenerationPrecondition:0,
      objectGenerationRecorded:false,
      independentCustodyVerificationRequired:true
    },
    publisher:{
      executionClass:"signed-certification-runner",
      scriptDigest:$publisherScriptDigest,
      actorIdentityDigest:$actorIdentityDigest,
      signingPublicKeyDigest:$signingPublicKeyDigest,
      publishedAt:$publishedAt
    },
    claims:{
      rawCollectionUploaded:true,
      rawArtifactsRestricted:true,
      custodyVerified:false,
      sourceAdmissionAuthorized:false,
      mirrorAuthorization:false,
      activationAuthorized:false,
      deploymentAuthorized:false,
      campaignEvidence:false,
      referenceProfileVerified:false
    }
  }' >"$CUSTODY_STATEMENT"
chmod 0600 "$CUSTODY_STATEMENT"

python3 "$ROOT/scripts/sno_trial_dependency_risk_custody.py" \
  validate-statement --statement "$CUSTODY_STATEMENT" >/dev/null
cosign sign-blob \
  --yes \
  --key "$SIGNING_KEY" \
  --bundle "$CUSTODY_SIGNATURE" \
  "$CUSTODY_STATEMENT" >/dev/null
chmod 0600 "$CUSTODY_SIGNATURE"

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

printf 'sno_dependency_risk_raw_custody_published evidenceId=%s prefix=%s archive=%s statement=%s signature=%s objectGenerationRecorded=false custodyVerified=false sourceAdmission=false mirrorAuthorization=false activation=false deployment=false campaignEvidence=false referenceProfileVerified=false\n' \
  "$EVIDENCE_ID" "$PREFIX" "$RAW_ARCHIVE_DIGEST" \
  "$(raw_digest "$CUSTODY_STATEMENT")" "$(raw_digest "$CUSTODY_SIGNATURE")"
