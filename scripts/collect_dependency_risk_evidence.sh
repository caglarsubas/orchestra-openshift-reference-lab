#!/usr/bin/env bash
set -Eeuo pipefail

umask 077
export LC_ALL=C
export TZ=UTC

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB_LOCK="$ROOT/config/lab.lock.json"
ADMISSION="$ROOT/config/dependency-admission.lock.json"
SOURCE_VERIFICATION="$ROOT/config/dependency-source-verification.lock.json"
RISK_POLICY="$ROOT/config/dependency-risk-policy.lock.json"
RELEASE_SET="$ROOT/config/cross-plane-release-set.lock.json"
COLLECTOR_SCRIPT_SOURCE="$ROOT/scripts/collect_dependency_risk_evidence.sh"
TOOLCHAIN_LOCK="${ORCHESTRA_RUNNER_TOOLCHAIN_LOCK:-/opt/orchestra/certification/toolchain-lock.json}"

OUTPUT_DIR=""
EVIDENCE_ID=""
ACTOR_IDENTITY_DIGEST=""
PLATFORM_RELEASE_DIR=""
SIGNING_KEY=""
EXPECTED_SIGNING_PUBLIC_KEY_DIGEST=""
PREFLIGHT_ONLY=false

usage() {
  cat <<'EOF'
Usage: collect_dependency_risk_evidence.sh \
  --output-dir restricted/<new-directory> \
  --evidence-id orchestra-dependency-risk-evidence-<id> \
  --actor-identity-digest sha256:<digest> \
  --platform-release-dir restricted/platform-release \
  --signing-key gcpkms://projects/.../cryptoKeyVersions/... \
  --expected-signing-public-key-digest sha256:<digest> \
  [--preflight-only]

Run this command only inside the exact certification-runner image pinned by
config/cross-plane-release-set.lock.json. Output is published atomically and
never authorizes source admission, mirroring, activation, or campaign evidence.
Preflight mode validates every launch prerequisite, including an ephemeral KMS
sign-and-verify challenge, but downloads no scanner database and publishes no
collection artifact.
EOF
}

fail() {
  printf 'dependency_risk_collection_failed code=%s\n' "$1" >&2
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

copy_restricted_artifact() {
  local source="$1"
  local destination="$2"
  [[ -f "$source" ]] || fail "release_artifact_missing:$(basename "$source")"
  install -m 0600 "$source" "$destination"
}

while (($# > 0)); do
  case "$1" in
    --output-dir)
      OUTPUT_DIR="${2:-}"
      shift 2
      ;;
    --evidence-id)
      EVIDENCE_ID="${2:-}"
      shift 2
      ;;
    --actor-identity-digest)
      ACTOR_IDENTITY_DIGEST="${2:-}"
      shift 2
      ;;
    --platform-release-dir)
      PLATFORM_RELEASE_DIR="${2:-}"
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
    --preflight-only)
      PREFLIGHT_ONLY=true
      shift
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

[[ -n "$OUTPUT_DIR" ]] || fail "output_dir_required"
[[ -n "$EVIDENCE_ID" ]] || fail "evidence_id_required"
[[ "$EVIDENCE_ID" =~ ^orchestra-dependency-risk-evidence-[a-z0-9][a-z0-9.-]+$ ]] || fail "evidence_id_invalid"
require_digest "$ACTOR_IDENTITY_DIGEST" "actor_identity_digest_invalid"
if [[ "$SIGNING_KEY" =~ ^gcpkms://projects/([^/]+)/locations/([^/]+)/keyRings/([^/]+)/cryptoKeys/([^/]+)/cryptoKeyVersions/([0-9]+)$ ]]; then
  KMS_PROJECT="${BASH_REMATCH[1]}"
  KMS_LOCATION="${BASH_REMATCH[2]}"
  KMS_KEYRING="${BASH_REMATCH[3]}"
  KMS_KEY="${BASH_REMATCH[4]}"
  KMS_VERSION="${BASH_REMATCH[5]}"
else
  fail "cloud_kms_signing_key_version_required"
fi
require_digest "$EXPECTED_SIGNING_PUBLIC_KEY_DIGEST" "expected_signing_public_key_digest_invalid"
require_command realpath
RESTRICTED_ROOT="$(realpath -m "$ROOT/restricted")"
OUTPUT_DIR="$(realpath -m "$OUTPUT_DIR")"
PLATFORM_RELEASE_DIR="$(realpath -m "$PLATFORM_RELEASE_DIR")"
[[ "$OUTPUT_DIR" == "$RESTRICTED_ROOT/"* ]] || fail "output_dir_outside_restricted_storage"
[[ "$PLATFORM_RELEASE_DIR" == "$RESTRICTED_ROOT/"* && -d "$PLATFORM_RELEASE_DIR" ]] || fail "platform_release_dir_invalid"

for command_name in jq sha256sum awk install mktemp date trivy syft cosign gcloud openssl orchestra-certification; do
  require_command "$command_name"
done
for contract_file in "$LAB_LOCK" "$ADMISSION" "$SOURCE_VERIFICATION" "$RISK_POLICY" "$RELEASE_SET" "$COLLECTOR_SCRIPT_SOURCE" "$TOOLCHAIN_LOCK"; do
  [[ -f "$contract_file" ]] || fail "contract_file_missing:$(basename "$contract_file")"
done

[[ ! -e "$OUTPUT_DIR" ]] || fail "output_dir_exists"
OUTPUT_PARENT="$(dirname "$OUTPUT_DIR")"
mkdir -p "$OUTPUT_PARENT"
chmod 0700 "$OUTPUT_PARENT"
TEMP_DIR="$(mktemp -d "$OUTPUT_PARENT/.dependency-risk-collection.XXXXXX")"
chmod 0700 "$TEMP_DIR"
cleanup() {
  rm -rf "$TEMP_DIR"
}
trap cleanup EXIT
cd "$TEMP_DIR"

for policy_variable in \
  TRIVY_CONFIG TRIVY_SEVERITY TRIVY_IGNORE_UNFIXED TRIVY_IGNORE_FILE \
  TRIVY_SCANNERS TRIVY_PLATFORM TRIVY_SKIP_DB_UPDATE \
  TRIVY_SKIP_JAVA_DB_UPDATE TRIVY_OFFLINE_SCAN SYFT_CONFIG SYFT_OUTPUT \
  SYFT_PLATFORM; do
  [[ -z "${!policy_variable:-}" ]] || fail "scanner_policy_environment_forbidden:$policy_variable"
done
[[ ! -e .trivyignore && ! -e trivy.yaml && ! -e .syft.yaml ]] || fail "scanner_policy_file_forbidden"

PROFILE_ID="$(jq -er '.profile.id' "$RELEASE_SET")"
[[ "$PROFILE_ID" == "orchestra-ocp-4.20-amd64-v1" ]] || fail "profile_invalid"
RELEASE_SET_DIGEST="$(canonical_digest "$RELEASE_SET")"
TOPOLOGY_DIGEST="$(canonical_digest "$LAB_LOCK")"
ADMISSION_DIGEST="$(canonical_digest "$ADMISSION")"
SOURCE_VERIFICATION_DIGEST="$(canonical_digest "$SOURCE_VERIFICATION")"
RISK_POLICY_DIGEST="$(canonical_digest "$RISK_POLICY")"
COLLECTOR_SCRIPT_DIGEST="$(raw_digest "$COLLECTOR_SCRIPT_SOURCE")"

[[ "$(jq -er '.bindings.topologyDigest' "$RISK_POLICY")" == "$TOPOLOGY_DIGEST" ]] || fail "risk_policy_topology_binding_invalid"
[[ "$(jq -er '.bindings.dependencyAdmissionDigest' "$RISK_POLICY")" == "$ADMISSION_DIGEST" ]] || fail "risk_policy_admission_binding_invalid"
[[ "$(jq -er '.bindings.sourceVerificationDigest' "$RISK_POLICY")" == "$SOURCE_VERIFICATION_DIGEST" ]] || fail "risk_policy_source_binding_invalid"
[[ "$(jq -er '.bindings.releaseSetDigest' "$RISK_POLICY")" == "$RELEASE_SET_DIGEST" ]] || fail "risk_policy_release_set_binding_invalid"
[[ "$(jq -er '.collectionPolicy.collectorScriptDigest' "$RISK_POLICY")" == "$COLLECTOR_SCRIPT_DIGEST" ]] || fail "risk_policy_collector_script_binding_invalid"
SOURCE_OBSERVED_AT="$(jq -er '.observationWindow.observedAt' "$SOURCE_VERIFICATION")"
SOURCE_VALID_UNTIL="$(jq -er '.observationWindow.validUntil' "$SOURCE_VERIFICATION")"
COLLECTION_CLOCK="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
[[ "$COLLECTION_CLOCK" > "$SOURCE_OBSERVED_AT" || "$COLLECTION_CLOCK" == "$SOURCE_OBSERVED_AT" ]] || fail "source_observation_not_started"
[[ "$COLLECTION_CLOCK" < "$SOURCE_VALID_UNTIL" || "$COLLECTION_CLOCK" == "$SOURCE_VALID_UNTIL" ]] || fail "source_observation_expired"

RUNNER_RELEASE="$(jq -er '.certificationRunner.release' "$RELEASE_SET")"
RUNNER_REVISION="$(jq -er '.certificationRunner.source.revision' "$RELEASE_SET")"
RUNNER_IMAGE="$(jq -er '.certificationRunner.image' "$RELEASE_SET")"
RUNNER_IMAGE_DIGEST="${RUNNER_IMAGE##*@}"
RUNNER_TOOLCHAIN_DIGEST="$(jq -er '.certificationRunner.toolchainDigest' "$RELEASE_SET")"
require_digest "$RUNNER_IMAGE_DIGEST" "runner_image_digest_invalid"
require_digest "$RUNNER_TOOLCHAIN_DIGEST" "runner_toolchain_digest_invalid"

orchestra-certification self-test >/dev/null
[[ "$(raw_digest "$TOOLCHAIN_LOCK")" == "$RUNNER_TOOLCHAIN_DIGEST" ]] || fail "runner_toolchain_digest_mismatch"

RELEASE_MANIFEST_SOURCE="$PLATFORM_RELEASE_DIR/platform-release-manifest.json"
RELEASE_SIGNATURE_SOURCE="$PLATFORM_RELEASE_DIR/platform-release-manifest.sigstore.json"
RELEASE_PROVENANCE_SOURCE="$PLATFORM_RELEASE_DIR/platform-release-manifest.provenance.sigstore.json"
RUNNER_METADATA_SOURCE="$PLATFORM_RELEASE_DIR/release-orchestra-certification-runner-ubi.json"
RELEASE_TOOLCHAIN_SOURCE="$PLATFORM_RELEASE_DIR/certification-runner-toolchain-lock.json"

copy_restricted_artifact "$RELEASE_MANIFEST_SOURCE" "$TEMP_DIR/platform-release-manifest.json"
copy_restricted_artifact "$RELEASE_SIGNATURE_SOURCE" "$TEMP_DIR/platform-release-manifest.sigstore.json"
copy_restricted_artifact "$RELEASE_PROVENANCE_SOURCE" "$TEMP_DIR/platform-release-manifest.provenance.sigstore.json"
copy_restricted_artifact "$RUNNER_METADATA_SOURCE" "$TEMP_DIR/release-orchestra-certification-runner-ubi.json"
copy_restricted_artifact "$RELEASE_TOOLCHAIN_SOURCE" "$TEMP_DIR/certification-runner-toolchain-lock.json"
copy_restricted_artifact "$COLLECTOR_SCRIPT_SOURCE" "$TEMP_DIR/dependency-risk-collector.sh"
[[ "$(raw_digest "$TEMP_DIR/dependency-risk-collector.sh")" == "$COLLECTOR_SCRIPT_DIGEST" ]] || fail "collector_script_changed_during_collection"

[[ "$(raw_digest "$TEMP_DIR/certification-runner-toolchain-lock.json")" == "$RUNNER_TOOLCHAIN_DIGEST" ]] || fail "released_toolchain_digest_mismatch"
[[ "$(jq -er '.release.tag' "$TEMP_DIR/platform-release-manifest.json")" == "$RUNNER_RELEASE" ]] || fail "release_manifest_tag_mismatch"
[[ "$(jq -er '.source.revision' "$TEMP_DIR/platform-release-manifest.json")" == "$RUNNER_REVISION" ]] || fail "release_manifest_revision_mismatch"
[[ "$(jq -er '.source.repository' "$TEMP_DIR/platform-release-manifest.json")" == "caglarsubas/agent-hook-v2" ]] || fail "release_manifest_repository_mismatch"
[[ "$(jq -er '.source.ref' "$TEMP_DIR/platform-release-manifest.json")" == "refs/tags/$RUNNER_RELEASE" ]] || fail "release_manifest_ref_mismatch"
[[ "$(jq -er '.productionProfile.id' "$TEMP_DIR/platform-release-manifest.json")" == "$PROFILE_ID" ]] || fail "release_manifest_profile_mismatch"
[[ "$(jq -er '.productionProfile.digest' "$TEMP_DIR/platform-release-manifest.json")" == "$(jq -er '.profile.digest' "$RELEASE_SET")" ]] || fail "release_manifest_profile_digest_mismatch"
[[ "$(jq -er '.tag' "$TEMP_DIR/release-orchestra-certification-runner-ubi.json")" == "$RUNNER_RELEASE" ]] || fail "runner_metadata_tag_mismatch"
[[ "$(jq -er '.revision' "$TEMP_DIR/release-orchestra-certification-runner-ubi.json")" == "$RUNNER_REVISION" ]] || fail "runner_metadata_revision_mismatch"
[[ "$(jq -er '.role' "$TEMP_DIR/release-orchestra-certification-runner-ubi.json")" == "certification-runner" ]] || fail "runner_metadata_role_mismatch"
[[ "$(jq -er '.flavor' "$TEMP_DIR/release-orchestra-certification-runner-ubi.json")" == "ubi9" ]] || fail "runner_metadata_flavor_mismatch"
RUNNER_METADATA_REF="$(jq -er '.repository + "@" + .digest' "$TEMP_DIR/release-orchestra-certification-runner-ubi.json")"
[[ "$RUNNER_METADATA_REF" == "$RUNNER_IMAGE" ]] || fail "runner_metadata_image_mismatch"
[[ "$(jq -er '.toolchain.digest' "$TEMP_DIR/release-orchestra-certification-runner-ubi.json")" == "$RUNNER_TOOLCHAIN_DIGEST" ]] || fail "runner_metadata_toolchain_mismatch"
[[ "$(jq -er --arg runner "$RUNNER_IMAGE" '[.subjects.images[].ref] | index($runner) != null' "$TEMP_DIR/platform-release-manifest.json")" == "true" ]] || fail "release_manifest_runner_missing"

PUBLISHER_IDENTITY="https://github.com/caglarsubas/agent-hook-v2/.github/workflows/publish-platform-release.yml@refs/tags/$RUNNER_RELEASE"
PUBLISHER_ISSUER="https://token.actions.githubusercontent.com"
cosign verify-blob \
  --timeout 3m \
  --bundle "$TEMP_DIR/platform-release-manifest.sigstore.json" \
  --certificate-identity "$PUBLISHER_IDENTITY" \
  --certificate-oidc-issuer "$PUBLISHER_ISSUER" \
  --certificate-github-workflow-sha "$RUNNER_REVISION" \
  --certificate-github-workflow-ref "refs/tags/$RUNNER_RELEASE" \
  --certificate-github-workflow-repository "caglarsubas/agent-hook-v2" \
  --certificate-github-workflow-trigger push \
  "$TEMP_DIR/platform-release-manifest.json" >/dev/null
cosign verify-blob-attestation \
  --timeout 3m \
  --bundle "$TEMP_DIR/platform-release-manifest.provenance.sigstore.json" \
  --type 'https://slsa.dev/provenance/v1' \
  --certificate-identity "$PUBLISHER_IDENTITY" \
  --certificate-oidc-issuer "$PUBLISHER_ISSUER" \
  --certificate-github-workflow-sha "$RUNNER_REVISION" \
  --certificate-github-workflow-ref "refs/tags/$RUNNER_RELEASE" \
  --certificate-github-workflow-repository "caglarsubas/agent-hook-v2" \
  --certificate-github-workflow-trigger push \
  "$TEMP_DIR/platform-release-manifest.json" >/dev/null
cosign verify "$RUNNER_IMAGE" \
  --timeout 3m \
  --certificate-identity "$PUBLISHER_IDENTITY" \
  --certificate-oidc-issuer "$PUBLISHER_ISSUER" \
  --certificate-github-workflow-sha "$RUNNER_REVISION" \
  --certificate-github-workflow-ref "refs/tags/$RUNNER_RELEASE" \
  --certificate-github-workflow-repository "caglarsubas/agent-hook-v2" \
  --certificate-github-workflow-trigger push >/dev/null
cosign verify-attestation "$RUNNER_IMAGE" \
  --timeout 3m \
  --type cyclonedx \
  --certificate-identity "$PUBLISHER_IDENTITY" \
  --certificate-oidc-issuer "$PUBLISHER_ISSUER" \
  --certificate-github-workflow-sha "$RUNNER_REVISION" \
  --certificate-github-workflow-ref "refs/tags/$RUNNER_RELEASE" \
  --certificate-github-workflow-repository "caglarsubas/agent-hook-v2" \
  --certificate-github-workflow-trigger push >/dev/null

cosign public-key --key "$SIGNING_KEY" >"$TEMP_DIR/collection-signing-public-key.pem"
chmod 0600 "$TEMP_DIR/collection-signing-public-key.pem"
SIGNING_PUBLIC_KEY_DIGEST="$(raw_digest "$TEMP_DIR/collection-signing-public-key.pem")"
[[ "$SIGNING_PUBLIC_KEY_DIGEST" == "$EXPECTED_SIGNING_PUBLIC_KEY_DIGEST" ]] || fail "signing_public_key_digest_mismatch"

EXPECTED_TRIVY_VERSION="$(jq -er '.tools.trivy.version' "$TOOLCHAIN_LOCK")"
EXPECTED_SYFT_VERSION="$(jq -er '.tools.syft.version' "$TOOLCHAIN_LOCK")"
EXPECTED_COSIGN_VERSION="$(jq -er '.tools.cosign.version' "$TOOLCHAIN_LOCK")"
EXPECTED_GCLOUD_VERSION="$(jq -er '.tools.gcloud.version' "$TOOLCHAIN_LOCK")"
TRIVY_VERSION="$(trivy --version | awk '/^Version:/ {print $2; exit}')"
SYFT_VERSION="$(syft version -o json | jq -er '.version')"
COSIGN_VERSION="$(cosign version --json | jq -er '.gitVersion | ltrimstr("v")')"
GCLOUD_VERSION="$(gcloud version --format=json | jq -er '."Google Cloud SDK"')"
[[ "$TRIVY_VERSION" == "$EXPECTED_TRIVY_VERSION" ]] || fail "trivy_version_invalid"
[[ "$SYFT_VERSION" == "$EXPECTED_SYFT_VERSION" ]] || fail "syft_version_invalid"
[[ "$COSIGN_VERSION" == "$EXPECTED_COSIGN_VERSION" ]] || fail "cosign_version_invalid"
[[ "$GCLOUD_VERSION" == "$EXPECTED_GCLOUD_VERSION" ]] || fail "gcloud_version_invalid"

REQUIRED_KMS_ALGORITHM="$(jq -er '.collectionPolicy.preflightKmsAlgorithm' "$RISK_POLICY")"
read -r KMS_ALGORITHM KMS_STATE < <(
  gcloud kms keys versions describe "$KMS_VERSION" \
    --project="$KMS_PROJECT" \
    --location="$KMS_LOCATION" \
    --keyring="$KMS_KEYRING" \
    --key="$KMS_KEY" \
    --format='value(algorithm,state)'
)
[[ "$KMS_ALGORITHM" == "$REQUIRED_KMS_ALGORITHM" ]] || fail "cloud_kms_signing_algorithm_invalid"
[[ "$KMS_STATE" == "ENABLED" ]] || fail "cloud_kms_signing_key_not_enabled"

PREFLIGHT_CHECKED_AT="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
[[ "$PREFLIGHT_CHECKED_AT" > "$SOURCE_OBSERVED_AT" || "$PREFLIGHT_CHECKED_AT" == "$SOURCE_OBSERVED_AT" ]] || fail "source_observation_not_started_during_preflight"
[[ "$PREFLIGHT_CHECKED_AT" < "$SOURCE_VALID_UNTIL" || "$PREFLIGHT_CHECKED_AT" == "$SOURCE_VALID_UNTIL" ]] || fail "source_observation_expired_during_preflight"
jq -nS \
  --arg profileId "$PROFILE_ID" \
  --arg evidenceId "$EVIDENCE_ID" \
  --arg releaseSetDigest "$RELEASE_SET_DIGEST" \
  --arg runnerImageDigest "$RUNNER_IMAGE_DIGEST" \
  --arg runnerToolchainDigest "$RUNNER_TOOLCHAIN_DIGEST" \
  --arg collectorScriptDigest "$COLLECTOR_SCRIPT_DIGEST" \
  --arg actorIdentityDigest "$ACTOR_IDENTITY_DIGEST" \
  --arg signingPublicKeyDigest "$SIGNING_PUBLIC_KEY_DIGEST" \
  --arg checkedAt "$PREFLIGHT_CHECKED_AT" \
  '{schemaVersion:1,kind:"orchestra.dependency-risk.collection-preflight-challenge.v1",profileId:$profileId,evidenceId:$evidenceId,releaseSetDigest:$releaseSetDigest,runnerImageDigest:$runnerImageDigest,runnerToolchainDigest:$runnerToolchainDigest,collectorScriptDigest:$collectorScriptDigest,actorIdentityDigest:$actorIdentityDigest,signingPublicKeyDigest:$signingPublicKeyDigest,checkedAt:$checkedAt,claims:{collectionStarted:false,sourceAdmissionAuthorized:false,mirrorAuthorization:false,activationAuthorized:false,campaignEvidence:false}}' \
  >"$TEMP_DIR/dependency-risk-preflight-challenge.json"
chmod 0600 "$TEMP_DIR/dependency-risk-preflight-challenge.json"
gcloud kms asymmetric-sign \
  --project="$KMS_PROJECT" \
  --location="$KMS_LOCATION" \
  --keyring="$KMS_KEYRING" \
  --key="$KMS_KEY" \
  --version="$KMS_VERSION" \
  --digest-algorithm=sha256 \
  --input-file="$TEMP_DIR/dependency-risk-preflight-challenge.json" \
  --signature-file="$TEMP_DIR/dependency-risk-preflight-challenge.sig" \
  --quiet
chmod 0600 "$TEMP_DIR/dependency-risk-preflight-challenge.sig"
openssl dgst -sha256 \
  -verify "$TEMP_DIR/collection-signing-public-key.pem" \
  -signature "$TEMP_DIR/dependency-risk-preflight-challenge.sig" \
  "$TEMP_DIR/dependency-risk-preflight-challenge.json" >/dev/null \
  || fail "cloud_kms_signing_challenge_verification_failed"
PREFLIGHT_COMPLETED_AT="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
[[ "$PREFLIGHT_COMPLETED_AT" < "$SOURCE_VALID_UNTIL" || "$PREFLIGHT_COMPLETED_AT" == "$SOURCE_VALID_UNTIL" ]] || fail "source_observation_expired_during_preflight"

if [[ "$PREFLIGHT_ONLY" == "true" ]]; then
  printf 'dependency_risk_collection_preflight_ready profile=%s releaseSet=%s runner=%s signingKey=%s collectionStarted=false sourceAdmission=false mirrorAuthorization=false activation=false campaignEvidence=false\n' \
    "$PROFILE_ID" "$RELEASE_SET_DIGEST" "$RUNNER_IMAGE_DIGEST" "$SIGNING_PUBLIC_KEY_DIGEST"
  exit 0
fi
rm -f "$TEMP_DIR/dependency-risk-preflight-challenge.json" "$TEMP_DIR/dependency-risk-preflight-challenge.sig"

STARTED_AT="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
TRIVY_CACHE="$TEMP_DIR/trivy-cache"
mkdir -p "$TRIVY_CACHE"
chmod 0700 "$TRIVY_CACHE"
trivy image --config /dev/null --cache-dir "$TRIVY_CACHE" --no-progress --disable-telemetry --skip-version-check --download-db-only
trivy image --config /dev/null --cache-dir "$TRIVY_CACHE" --no-progress --disable-telemetry --skip-version-check --download-java-db-only
[[ -f "$TRIVY_CACHE/db/trivy.db" ]] || fail "trivy_database_missing"
[[ -f "$TRIVY_CACHE/java-db/trivy-java.db" ]] || fail "trivy_java_database_missing"
TRIVY_DATABASE_DIGEST="$(raw_digest "$TRIVY_CACHE/db/trivy.db")"
TRIVY_JAVA_DATABASE_DIGEST="$(raw_digest "$TRIVY_CACHE/java-db/trivy-java.db")"

SUBJECTS_JSON="$TEMP_DIR/subjects.jsonl"
: >"$SUBJECTS_JSON"
while IFS=$'\t' read -r subject_id source_subject platform_subject; do
  vulnerability_file="$subject_id.trivy.json"
  sbom_file="$subject_id.spdx.json"
  trivy image \
    --config /dev/null \
    --cache-dir "$TRIVY_CACHE" \
    --platform linux/amd64 \
    --image-src remote \
    --scanners vuln \
    --format json \
    --output "$TEMP_DIR/$vulnerability_file" \
    --skip-db-update \
    --skip-java-db-update \
    --offline-scan \
    --disable-telemetry \
    --skip-version-check \
    --no-progress \
    "$platform_subject"
  syft scan \
    --config /dev/null \
    --platform linux/amd64 \
    "registry:$platform_subject" \
    --output "spdx-json=$TEMP_DIR/$sbom_file"
  chmod 0600 "$TEMP_DIR/$vulnerability_file" "$TEMP_DIR/$sbom_file"
  jq -cnS \
    --arg id "$subject_id" \
    --arg sourceSubject "$source_subject" \
    --arg platformSubject "$platform_subject" \
    --arg vulnerabilityReportFile "$vulnerability_file" \
    --arg vulnerabilityReportDigest "$(raw_digest "$TEMP_DIR/$vulnerability_file")" \
    --arg sbomFile "$sbom_file" \
    --arg sbomDigest "$(raw_digest "$TEMP_DIR/$sbom_file")" \
    '{id:$id,sourceSubject:$sourceSubject,platformSubject:$platformSubject,vulnerabilityReportFile:$vulnerabilityReportFile,vulnerabilityReportDigest:$vulnerabilityReportDigest,sbomFile:$sbomFile,sbomDigest:$sbomDigest}' \
    >>"$SUBJECTS_JSON"
done < <(
  jq -r \
    --argjson ids "$(jq -c '.scope.subjectIds' "$RISK_POLICY")" \
    '.images[] | select(.id as $id | $ids | index($id)) | [.id, ((.source.reference | sub(":[^/:]+$"; "")) + "@" + .source.indexDigest), ((.source.reference | sub(":[^/:]+$"; "")) + "@" + .source.platformDigest)] | @tsv' \
    "$ADMISSION" | sort
)

[[ "$(wc -l <"$SUBJECTS_JSON" | tr -d ' ')" == "8" ]] || fail "scan_subject_count_invalid"
COMPLETED_AT="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
[[ "$COMPLETED_AT" < "$SOURCE_VALID_UNTIL" || "$COMPLETED_AT" == "$SOURCE_VALID_UNTIL" ]] || fail "source_observation_expired_during_collection"
STARTED_EPOCH="$(date -u -d "$STARTED_AT" +%s)"
COMPLETED_EPOCH="$(date -u -d "$COMPLETED_AT" +%s)"
((COMPLETED_EPOCH >= STARTED_EPOCH && COMPLETED_EPOCH - STARTED_EPOCH <= 21600)) || fail "collection_duration_invalid"

RELEASE_MANIFEST_DIGEST="$(raw_digest "$TEMP_DIR/platform-release-manifest.json")"
RELEASE_SIGNATURE_DIGEST="$(raw_digest "$TEMP_DIR/platform-release-manifest.sigstore.json")"
RUNNER_PROVENANCE_DIGEST="$(raw_digest "$TEMP_DIR/platform-release-manifest.provenance.sigstore.json")"
RUNNER_METADATA_DIGEST="$(raw_digest "$TEMP_DIR/release-orchestra-certification-runner-ubi.json")"

jq -nS \
  --arg profileId "$PROFILE_ID" \
  --arg evidenceId "$EVIDENCE_ID" \
  --arg topologyDigest "$TOPOLOGY_DIGEST" \
  --arg dependencyAdmissionDigest "$ADMISSION_DIGEST" \
  --arg sourceVerificationDigest "$SOURCE_VERIFICATION_DIGEST" \
  --arg riskPolicyDigest "$RISK_POLICY_DIGEST" \
  --arg releaseSetDigest "$RELEASE_SET_DIGEST" \
  --arg runnerRelease "$RUNNER_RELEASE" \
  --arg runnerRevision "$RUNNER_REVISION" \
  --arg runnerImage "$RUNNER_IMAGE" \
  --arg runnerImageDigest "$RUNNER_IMAGE_DIGEST" \
  --arg runnerToolchainDigest "$RUNNER_TOOLCHAIN_DIGEST" \
  --arg runnerReleaseManifestDigest "$RELEASE_MANIFEST_DIGEST" \
  --arg runnerReleaseManifestSignatureBundleDigest "$RELEASE_SIGNATURE_DIGEST" \
  --arg runnerProvenanceBundleDigest "$RUNNER_PROVENANCE_DIGEST" \
  --arg runnerReleaseMetadataDigest "$RUNNER_METADATA_DIGEST" \
  --arg actorIdentityDigest "$ACTOR_IDENTITY_DIGEST" \
  --arg collectorScriptDigest "$COLLECTOR_SCRIPT_DIGEST" \
  --arg signingPublicKeyDigest "$SIGNING_PUBLIC_KEY_DIGEST" \
  --arg startedAt "$STARTED_AT" \
  --arg completedAt "$COMPLETED_AT" \
  --arg trivyVersion "$TRIVY_VERSION" \
  --arg trivyDatabaseDigest "$TRIVY_DATABASE_DIGEST" \
  --arg trivyJavaDatabaseDigest "$TRIVY_JAVA_DATABASE_DIGEST" \
  --arg syftVersion "$SYFT_VERSION" \
  --slurpfile subjects "$SUBJECTS_JSON" \
  '{schemaVersion:1,kind:"orchestra.dependency-risk.collection-statement.v1",profileId:$profileId,targetClass:"vendor-reference-lab",executionMode:"live",evidenceId:$evidenceId,bindings:{topologyDigest:$topologyDigest,dependencyAdmissionDigest:$dependencyAdmissionDigest,sourceVerificationDigest:$sourceVerificationDigest,riskPolicyDigest:$riskPolicyDigest,releaseSetDigest:$releaseSetDigest},runner:{release:$runnerRelease,revision:$runnerRevision,image:$runnerImage,imageDigest:$runnerImageDigest,toolchainDigest:$runnerToolchainDigest,releaseManifestDigest:$runnerReleaseManifestDigest,releaseManifestSignatureBundleDigest:$runnerReleaseManifestSignatureBundleDigest,provenanceBundleDigest:$runnerProvenanceBundleDigest,releaseMetadataDigest:$runnerReleaseMetadataDigest},collector:{executionClass:"signed-certification-runner",scriptDigest:$collectorScriptDigest,actorIdentityDigest:$actorIdentityDigest,signingPublicKeyDigest:$signingPublicKeyDigest,startedAt:$startedAt,completedAt:$completedAt},scanners:{vulnerability:{name:"trivy",version:$trivyVersion,databaseDigest:$trivyDatabaseDigest,javaDatabaseDigest:$trivyJavaDatabaseDigest},sbom:{name:"syft",version:$syftVersion}},invocationPolicy:{platform:"linux/amd64",imageSource:"remote",vulnerabilityScanners:["vuln"],ignoreFileUsed:false,ignoreUnfixed:false,severityFilter:[],externalConfigUsed:false,databaseUpdatesDuringScan:false,offlineScan:true,sbomSource:"registry",sbomFormat:"spdx-2.3-json"},subjects:$subjects,claims:{rawArtifactsRestricted:true,sourceAdmissionAuthorized:false,mirrorAuthorization:false,activationAuthorized:false,campaignEvidence:false}}' \
  >"$TEMP_DIR/dependency-risk-collection-statement.json"
chmod 0600 "$TEMP_DIR/dependency-risk-collection-statement.json"

COLLECTION_ATTESTATION_DIGEST="$(raw_digest "$TEMP_DIR/dependency-risk-collection-statement.json")"
cosign sign-blob \
  --yes \
  --key "$SIGNING_KEY" \
  --bundle "$TEMP_DIR/dependency-risk-collection-signature.sigstore.json" \
  "$TEMP_DIR/dependency-risk-collection-statement.json" >/dev/null
chmod 0600 "$TEMP_DIR/dependency-risk-collection-signature.sigstore.json"
COLLECTION_SIGNATURE_BUNDLE_DIGEST="$(raw_digest "$TEMP_DIR/dependency-risk-collection-signature.sigstore.json")"

jq -nS \
  --arg profileId "$PROFILE_ID" \
  --arg evidenceId "$EVIDENCE_ID" \
  --arg topologyDigest "$TOPOLOGY_DIGEST" \
  --arg dependencyAdmissionDigest "$ADMISSION_DIGEST" \
  --arg sourceVerificationDigest "$SOURCE_VERIFICATION_DIGEST" \
  --arg riskPolicyDigest "$RISK_POLICY_DIGEST" \
  --arg releaseSetDigest "$RELEASE_SET_DIGEST" \
  --arg runnerRelease "$RUNNER_RELEASE" \
  --arg runnerRevision "$RUNNER_REVISION" \
  --arg runnerImage "$RUNNER_IMAGE" \
  --arg runnerImageDigest "$RUNNER_IMAGE_DIGEST" \
  --arg runnerToolchainDigest "$RUNNER_TOOLCHAIN_DIGEST" \
  --arg runnerReleaseManifestDigest "$RELEASE_MANIFEST_DIGEST" \
  --arg runnerReleaseManifestSignatureBundleDigest "$RELEASE_SIGNATURE_DIGEST" \
  --arg runnerProvenanceBundleDigest "$RUNNER_PROVENANCE_DIGEST" \
  --arg runnerReleaseMetadataDigest "$RUNNER_METADATA_DIGEST" \
  --arg actorIdentityDigest "$ACTOR_IDENTITY_DIGEST" \
  --arg collectorScriptDigest "$COLLECTOR_SCRIPT_DIGEST" \
  --arg signingPublicKeyDigest "$SIGNING_PUBLIC_KEY_DIGEST" \
  --arg startedAt "$STARTED_AT" \
  --arg completedAt "$COMPLETED_AT" \
  --arg collectionAttestationDigest "$COLLECTION_ATTESTATION_DIGEST" \
  --arg collectionSignatureBundleDigest "$COLLECTION_SIGNATURE_BUNDLE_DIGEST" \
  --arg trivyVersion "$TRIVY_VERSION" \
  --arg trivyDatabaseDigest "$TRIVY_DATABASE_DIGEST" \
  --arg trivyJavaDatabaseDigest "$TRIVY_JAVA_DATABASE_DIGEST" \
  --arg syftVersion "$SYFT_VERSION" \
  --slurpfile subjects "$SUBJECTS_JSON" \
  '{schemaVersion:1,profileId:$profileId,targetClass:"vendor-reference-lab",executionMode:"live",evidenceId:$evidenceId,bindings:{topologyDigest:$topologyDigest,dependencyAdmissionDigest:$dependencyAdmissionDigest,sourceVerificationDigest:$sourceVerificationDigest,riskPolicyDigest:$riskPolicyDigest,releaseSetDigest:$releaseSetDigest},collection:{executionClass:"signed-certification-runner",runnerRelease:$runnerRelease,runnerRevision:$runnerRevision,runnerImage:$runnerImage,runnerImageDigest:$runnerImageDigest,runnerToolchainDigest:$runnerToolchainDigest,runnerReleaseManifestFile:"platform-release-manifest.json",runnerReleaseManifestDigest:$runnerReleaseManifestDigest,runnerReleaseManifestSignatureBundleFile:"platform-release-manifest.sigstore.json",runnerReleaseManifestSignatureBundleDigest:$runnerReleaseManifestSignatureBundleDigest,runnerProvenanceBundleFile:"platform-release-manifest.provenance.sigstore.json",runnerProvenanceBundleDigest:$runnerProvenanceBundleDigest,runnerReleaseMetadataFile:"release-orchestra-certification-runner-ubi.json",runnerReleaseMetadataDigest:$runnerReleaseMetadataDigest,runnerToolchainLockFile:"certification-runner-toolchain-lock.json",collectorScriptFile:"dependency-risk-collector.sh",collectorScriptDigest:$collectorScriptDigest,actorIdentityDigest:$actorIdentityDigest,signingPublicKeyFile:"collection-signing-public-key.pem",signingPublicKeyDigest:$signingPublicKeyDigest,startedAt:$startedAt,completedAt:$completedAt,collectionAttestationFile:"dependency-risk-collection-statement.json",collectionAttestationDigest:$collectionAttestationDigest,collectionSignatureBundleFile:"dependency-risk-collection-signature.sigstore.json",collectionSignatureBundleDigest:$collectionSignatureBundleDigest,vulnerabilityScanner:{name:"trivy",version:$trivyVersion,databaseDigest:$trivyDatabaseDigest,javaDatabaseDigest:$trivyJavaDatabaseDigest},sbomScanner:{name:"syft",version:$syftVersion},invocationPolicy:{platform:"linux/amd64",imageSource:"remote",vulnerabilityScanners:["vuln"],ignoreFileUsed:false,ignoreUnfixed:false,severityFilter:[],externalConfigUsed:false,databaseUpdatesDuringScan:false,offlineScan:true,sbomSource:"registry",sbomFormat:"spdx-2.3-json"}},subjects:$subjects}' \
  >"$TEMP_DIR/dependency-risk-scan-manifest.json"
chmod 0600 "$TEMP_DIR/dependency-risk-scan-manifest.json"
rm -rf "$TRIVY_CACHE" "$SUBJECTS_JSON"

mv "$TEMP_DIR" "$OUTPUT_DIR"
trap - EXIT
printf 'dependency_risk_collection_complete output=%s statement=%s signatureBundle=%s sourceAdmission=false mirrorAuthorization=false campaignEvidence=false\n' \
  "$OUTPUT_DIR" "$COLLECTION_ATTESTATION_DIGEST" "$COLLECTION_SIGNATURE_BUNDLE_DIGEST"
