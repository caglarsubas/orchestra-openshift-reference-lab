#!/usr/bin/env bash
set -Eeuo pipefail

umask 077
export LC_ALL=C
export TZ=UTC

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_SET="$ROOT/config/sno-trial-dependency-artifacts.lock.json"
RISK_POLICY="$ROOT/config/sno-trial-dependency-risk-policy.lock.json"
RELEASE_SET="$ROOT/config/cross-plane-release-set.lock.json"
COLLECTOR_SCRIPT="$ROOT/scripts/collect_sno_trial_dependency_risk_evidence.sh"
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
Usage: collect_sno_trial_dependency_risk_evidence.sh \
  --output-dir restricted/<new-directory> \
  --evidence-id orchestra-sno-trial-dependency-risk-evidence-<id> \
  --actor-identity-digest sha256:<digest> \
  --platform-release-dir restricted/platform-release \
  --signing-key gcpkms://projects/.../cryptoKeyVersions/... \
  --expected-signing-public-key-digest sha256:<digest> \
  [--preflight-only]

Run only inside the exact signed certification-runner image. The command
collects raw vulnerability, SPDX, upstream-signature, and model-integrity
evidence into restricted storage; emits a payload-free review report; and
never grants mirroring, activation, deployment, or certification authority.
EOF
}

fail() {
  printf 'sno_dependency_risk_collection_failed code=%s\n' "$1" >&2
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
[[ "$EVIDENCE_ID" =~ ^orchestra-sno-trial-dependency-risk-evidence-[a-z0-9][a-z0-9.-]+$ ]] || fail "evidence_id_invalid"
require_digest "$ACTOR_IDENTITY_DIGEST" "actor_identity_digest_invalid"
require_digest "$EXPECTED_SIGNING_PUBLIC_KEY_DIGEST" "expected_signing_public_key_digest_invalid"
if [[ "$SIGNING_KEY" =~ ^gcpkms://projects/([^/]+)/locations/([^/]+)/keyRings/([^/]+)/cryptoKeys/([^/]+)/cryptoKeyVersions/([0-9]+)$ ]]; then
  KMS_PROJECT="${BASH_REMATCH[1]}"
  KMS_LOCATION="${BASH_REMATCH[2]}"
  KMS_KEYRING="${BASH_REMATCH[3]}"
  KMS_KEY="${BASH_REMATCH[4]}"
  KMS_VERSION="${BASH_REMATCH[5]}"
else
  fail "cloud_kms_signing_key_version_required"
fi

for command_name in jq sha256sum awk install mktemp date curl stat trivy syft cosign gcloud openssl orchestra-certification; do
  require_command "$command_name"
done
for contract_file in "$ARTIFACT_SET" "$RISK_POLICY" "$RELEASE_SET" "$COLLECTOR_SCRIPT" "$TOOLCHAIN_LOCK"; do
  [[ -f "$contract_file" ]] || fail "contract_file_missing:$(basename "$contract_file")"
done

require_command realpath
RESTRICTED_ROOT="$(realpath -m "$ROOT/restricted")"
OUTPUT_DIR="$(realpath -m "$OUTPUT_DIR")"
PLATFORM_RELEASE_DIR="$(realpath -m "$PLATFORM_RELEASE_DIR")"
[[ "$OUTPUT_DIR" == "$RESTRICTED_ROOT/"* ]] || fail "output_dir_outside_restricted_storage"
[[ "$PLATFORM_RELEASE_DIR" == "$RESTRICTED_ROOT/"* && -d "$PLATFORM_RELEASE_DIR" ]] || fail "platform_release_dir_invalid"
[[ ! -e "$OUTPUT_DIR" ]] || fail "output_dir_exists"

OUTPUT_PARENT="$(dirname "$OUTPUT_DIR")"
mkdir -p "$OUTPUT_PARENT"
chmod 0700 "$OUTPUT_PARENT"
TEMP_DIR="$(mktemp -d "$OUTPUT_PARENT/.sno-dependency-risk.XXXXXX")"
chmod 0700 "$TEMP_DIR"
cleanup() {
  rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

for policy_variable in \
  TRIVY_CONFIG TRIVY_SEVERITY TRIVY_IGNORE_UNFIXED TRIVY_IGNORE_FILE \
  TRIVY_SCANNERS TRIVY_PLATFORM TRIVY_SKIP_DB_UPDATE \
  TRIVY_SKIP_JAVA_DB_UPDATE TRIVY_OFFLINE_SCAN SYFT_CONFIG SYFT_OUTPUT \
  SYFT_PLATFORM; do
  [[ -z "${!policy_variable:-}" ]] || fail "scanner_policy_environment_forbidden:$policy_variable"
done

python3 "$ROOT/scripts/sno_trial_dependency_risk.py" validate-policy >/dev/null
ARTIFACT_SET_DIGEST="$(jq -er '.artifactSetDigest' "$ARTIFACT_SET")"
RISK_POLICY_DIGEST="$(canonical_digest "$RISK_POLICY")"
RELEASE_SET_DIGEST="$(canonical_digest "$RELEASE_SET")"
COLLECTOR_SCRIPT_DIGEST="$(raw_digest "$COLLECTOR_SCRIPT")"
[[ "$(jq -er '.bindings.artifactSetDigest' "$RISK_POLICY")" == "$ARTIFACT_SET_DIGEST" ]] || fail "risk_policy_artifact_binding_invalid"
[[ "$(jq -er '.bindings.releaseSetDigest' "$RISK_POLICY")" == "$RELEASE_SET_DIGEST" ]] || fail "risk_policy_release_binding_invalid"
[[ "$(jq -er '.collectionPolicy.collectorScriptDigest' "$RISK_POLICY")" == "$COLLECTOR_SCRIPT_DIGEST" ]] || fail "risk_policy_collector_binding_invalid"

RUNNER_RELEASE="$(jq -er '.certificationRunner.release' "$RELEASE_SET")"
RUNNER_REVISION="$(jq -er '.certificationRunner.source.revision' "$RELEASE_SET")"
RUNNER_IMAGE="$(jq -er '.certificationRunner.image' "$RELEASE_SET")"
RUNNER_IMAGE_DIGEST="${RUNNER_IMAGE##*@}"
RUNNER_TOOLCHAIN_DIGEST="$(jq -er '.certificationRunner.toolchainDigest' "$RELEASE_SET")"
[[ "$(jq -er '.collectionPolicy.runnerImage' "$RISK_POLICY")" == "$RUNNER_IMAGE" ]] || fail "risk_policy_runner_image_invalid"
[[ "$(jq -er '.collectionPolicy.runnerToolchainDigest' "$RISK_POLICY")" == "$RUNNER_TOOLCHAIN_DIGEST" ]] || fail "risk_policy_runner_toolchain_invalid"
[[ "${ORCHESTRA_CERTIFICATION_RUNNER_IMAGE:-}" == "$RUNNER_IMAGE" ]] || fail "runner_execution_identity_missing"
[[ "$(raw_digest "$TOOLCHAIN_LOCK")" == "$RUNNER_TOOLCHAIN_DIGEST" ]] || fail "runner_toolchain_digest_mismatch"
orchestra-certification self-test >/dev/null

RELEASE_MANIFEST="$PLATFORM_RELEASE_DIR/platform-release-manifest.json"
RELEASE_SIGNATURE="$PLATFORM_RELEASE_DIR/platform-release-manifest.sigstore.json"
RELEASE_PROVENANCE="$PLATFORM_RELEASE_DIR/platform-release-manifest.provenance.sigstore.json"
RUNNER_METADATA="$PLATFORM_RELEASE_DIR/release-orchestra-certification-runner-ubi.json"
for release_file in "$RELEASE_MANIFEST" "$RELEASE_SIGNATURE" "$RELEASE_PROVENANCE" "$RUNNER_METADATA"; do
  [[ -f "$release_file" ]] || fail "release_artifact_missing:$(basename "$release_file")"
done
[[ "$(jq -er '.release.tag' "$RELEASE_MANIFEST")" == "$RUNNER_RELEASE" ]] || fail "runner_release_manifest_tag_invalid"
[[ "$(jq -er '.source.revision' "$RELEASE_MANIFEST")" == "$RUNNER_REVISION" ]] || fail "runner_release_manifest_revision_invalid"
[[ "$(jq -er '.repository + "@" + .digest' "$RUNNER_METADATA")" == "$RUNNER_IMAGE" ]] || fail "runner_metadata_image_invalid"

PUBLISHER_IDENTITY="https://github.com/caglarsubas/agent-hook-v2/.github/workflows/publish-platform-release.yml@refs/tags/$RUNNER_RELEASE"
PUBLISHER_ISSUER="https://token.actions.githubusercontent.com"
cosign verify-blob \
  --timeout 3m \
  --bundle "$RELEASE_SIGNATURE" \
  --certificate-identity "$PUBLISHER_IDENTITY" \
  --certificate-oidc-issuer "$PUBLISHER_ISSUER" \
  --certificate-github-workflow-sha "$RUNNER_REVISION" \
  --certificate-github-workflow-ref "refs/tags/$RUNNER_RELEASE" \
  --certificate-github-workflow-repository "caglarsubas/agent-hook-v2" \
  --certificate-github-workflow-trigger push \
  "$RELEASE_MANIFEST" >/dev/null
cosign verify-blob-attestation \
  --timeout 3m \
  --bundle "$RELEASE_PROVENANCE" \
  --type 'https://slsa.dev/provenance/v1' \
  --certificate-identity "$PUBLISHER_IDENTITY" \
  --certificate-oidc-issuer "$PUBLISHER_ISSUER" \
  --certificate-github-workflow-sha "$RUNNER_REVISION" \
  --certificate-github-workflow-ref "refs/tags/$RUNNER_RELEASE" \
  --certificate-github-workflow-repository "caglarsubas/agent-hook-v2" \
  --certificate-github-workflow-trigger push \
  "$RELEASE_MANIFEST" >/dev/null
cosign verify "$RUNNER_IMAGE" \
  --timeout 3m \
  --certificate-identity "$PUBLISHER_IDENTITY" \
  --certificate-oidc-issuer "$PUBLISHER_ISSUER" \
  --certificate-github-workflow-sha "$RUNNER_REVISION" \
  --certificate-github-workflow-ref "refs/tags/$RUNNER_RELEASE" \
  --certificate-github-workflow-repository "caglarsubas/agent-hook-v2" \
  --certificate-github-workflow-trigger push >/dev/null

EXPECTED_TRIVY_VERSION="$(jq -er '.tools.trivy.version' "$TOOLCHAIN_LOCK")"
EXPECTED_SYFT_VERSION="$(jq -er '.tools.syft.version' "$TOOLCHAIN_LOCK")"
EXPECTED_COSIGN_VERSION="$(jq -er '.tools.cosign.version' "$TOOLCHAIN_LOCK")"
TRIVY_VERSION="$(trivy --version | awk '/^Version:/ {print $2; exit}')"
SYFT_VERSION="$(syft version -o json | jq -er '.version')"
COSIGN_VERSION="$(cosign version --json | jq -er '.gitVersion | ltrimstr("v")')"
[[ "$TRIVY_VERSION" == "$EXPECTED_TRIVY_VERSION" ]] || fail "trivy_version_invalid"
[[ "$SYFT_VERSION" == "$EXPECTED_SYFT_VERSION" ]] || fail "syft_version_invalid"
[[ "$COSIGN_VERSION" == "$EXPECTED_COSIGN_VERSION" ]] || fail "cosign_version_invalid"

cosign public-key --key "$SIGNING_KEY" >"$TEMP_DIR/collection-signing-public-key.pem"
SIGNING_PUBLIC_KEY_DIGEST="$(raw_digest "$TEMP_DIR/collection-signing-public-key.pem")"
[[ "$SIGNING_PUBLIC_KEY_DIGEST" == "$EXPECTED_SIGNING_PUBLIC_KEY_DIGEST" ]] || fail "signing_public_key_digest_mismatch"
read -r KMS_ALGORITHM KMS_STATE < <(
  gcloud kms keys versions describe "$KMS_VERSION" \
    --project="$KMS_PROJECT" \
    --location="$KMS_LOCATION" \
    --keyring="$KMS_KEYRING" \
    --key="$KMS_KEY" \
    --format='value(algorithm,state)'
)
[[ "$KMS_ALGORITHM" == "EC_SIGN_P256_SHA256" ]] || fail "cloud_kms_signing_algorithm_invalid"
[[ "$KMS_STATE" == "ENABLED" ]] || fail "cloud_kms_signing_key_not_enabled"

PREFLIGHT_AT="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
jq -nS \
  --arg profileId "orchestra-ocp-sno-trial-amd64-v1" \
  --arg evidenceId "$EVIDENCE_ID" \
  --arg artifactSetDigest "$ARTIFACT_SET_DIGEST" \
  --arg riskPolicyDigest "$RISK_POLICY_DIGEST" \
  --arg releaseSetDigest "$RELEASE_SET_DIGEST" \
  --arg runnerImageDigest "$RUNNER_IMAGE_DIGEST" \
  --arg runnerToolchainDigest "$RUNNER_TOOLCHAIN_DIGEST" \
  --arg collectorScriptDigest "$COLLECTOR_SCRIPT_DIGEST" \
  --arg actorIdentityDigest "$ACTOR_IDENTITY_DIGEST" \
  --arg checkedAt "$PREFLIGHT_AT" \
  '{schemaVersion:1,kind:"orchestra.openshift.sno-trial-dependency-risk-preflight.v1",profileId:$profileId,evidenceId:$evidenceId,bindings:{artifactSetDigest:$artifactSetDigest,riskPolicyDigest:$riskPolicyDigest,releaseSetDigest:$releaseSetDigest},runnerImageDigest:$runnerImageDigest,runnerToolchainDigest:$runnerToolchainDigest,collectorScriptDigest:$collectorScriptDigest,actorIdentityDigest:$actorIdentityDigest,checkedAt:$checkedAt,claims:{collectionStarted:false,sourceAdmissionAuthorized:false,mirrorAuthorization:false,activationAuthorized:false,deploymentAuthorized:false,campaignEvidence:false}}' \
  >"$TEMP_DIR/preflight.json"
gcloud kms asymmetric-sign \
  --project="$KMS_PROJECT" \
  --location="$KMS_LOCATION" \
  --keyring="$KMS_KEYRING" \
  --key="$KMS_KEY" \
  --version="$KMS_VERSION" \
  --digest-algorithm=sha256 \
  --input-file="$TEMP_DIR/preflight.json" \
  --signature-file="$TEMP_DIR/preflight.sig" \
  --quiet
openssl dgst -sha256 \
  -verify "$TEMP_DIR/collection-signing-public-key.pem" \
  -signature "$TEMP_DIR/preflight.sig" \
  "$TEMP_DIR/preflight.json" >/dev/null \
  || fail "cloud_kms_signing_challenge_verification_failed"
if [[ "$PREFLIGHT_ONLY" == "true" ]]; then
  printf 'sno_dependency_risk_preflight_ready evidence=%s collectionStarted=false sourceAdmission=false activation=false deployment=false\n' "$EVIDENCE_ID"
  exit 0
fi
rm -f "$TEMP_DIR/preflight.json" "$TEMP_DIR/preflight.sig"

STARTED_AT="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
TRIVY_CACHE="$TEMP_DIR/trivy-cache"
mkdir -p "$TRIVY_CACHE"
trivy image --config /dev/null --cache-dir "$TRIVY_CACHE" --no-progress --disable-telemetry --skip-version-check --download-db-only
trivy image --config /dev/null --cache-dir "$TRIVY_CACHE" --no-progress --disable-telemetry --skip-version-check --download-java-db-only
TRIVY_DATABASE_DIGEST="$(raw_digest "$TRIVY_CACHE/db/trivy.db")"
TRIVY_JAVA_DATABASE_DIGEST="$(raw_digest "$TRIVY_CACHE/java-db/trivy-java.db")"
TRUSTED_ROOT_FILE="${SIGSTORE_ROOT_FILE:-/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem}"
[[ -f "$TRUSTED_ROOT_FILE" ]] || fail "signature_trusted_root_missing"
TRUSTED_ROOT_DIGEST="$(raw_digest "$TRUSTED_ROOT_FILE")"

SUBJECTS_JSONL="$TEMP_DIR/subjects.jsonl"
: >"$SUBJECTS_JSONL"
while IFS=$'\t' read -r subject_id index_subject platform_subject; do
  raw_signature_file="$subject_id.cosign.raw.txt"
  signature_file="$subject_id.signature.json"
  vulnerability_file="$subject_id.trivy.json"
  sbom_file="$subject_id.spdx.json"
  set +e
  cosign verify "$index_subject" --timeout 3m >"$TEMP_DIR/$raw_signature_file" 2>&1
  cosign_exit=$?
  set -e
  [[ "$cosign_exit" == "1" ]] || fail "upstream_signature_state_changed:$subject_id"
  grep -Eiq 'no signatures found|no matching signatures' "$TEMP_DIR/$raw_signature_file" \
    || fail "upstream_signature_probe_ambiguous:$subject_id"
  jq -nS \
    --arg indexSubject "$index_subject" \
    --arg cosignVersion "$COSIGN_VERSION" \
    --arg rawOutputDigest "$(raw_digest "$TEMP_DIR/$raw_signature_file")" \
    --arg observedAt "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
    '{schemaVersion:1,kind:"orchestra.openshift.sno-trial-upstream-signature-probe.v1",indexSubject:$indexSubject,status:"no-signature-found",cosignVersion:$cosignVersion,cosignExitCode:1,rawOutputDigest:$rawOutputDigest,observedAt:$observedAt}' \
    >"$TEMP_DIR/$signature_file"
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
  jq -nS \
    --arg id "$subject_id" \
    --arg indexSubject "$index_subject" \
    --arg platformSubject "$platform_subject" \
    --arg vulnerabilityReportFile "$vulnerability_file" \
    --arg vulnerabilityReportDigest "$(raw_digest "$TEMP_DIR/$vulnerability_file")" \
    --arg sbomFile "$sbom_file" \
    --arg sbomDigest "$(raw_digest "$TEMP_DIR/$sbom_file")" \
    --arg signatureProbeFile "$signature_file" \
    --arg signatureProbeDigest "$(raw_digest "$TEMP_DIR/$signature_file")" \
    '{id:$id,indexSubject:$indexSubject,platformSubject:$platformSubject,vulnerabilityReportFile:$vulnerabilityReportFile,vulnerabilityReportDigest:$vulnerabilityReportDigest,sbomFile:$sbomFile,sbomDigest:$sbomDigest,signatureProbeFile:$signatureProbeFile,signatureProbeDigest:$signatureProbeDigest}' \
    >>"$SUBJECTS_JSONL"
done < <(
  jq -r \
    '.containers[] | [ .id, ((.sourceReference | sub(":[^/:]+$"; "")) + "@" + .indexDigest), .resolvedReference ] | @tsv' \
    "$ARTIFACT_SET" | sort
)
[[ "$(wc -l <"$SUBJECTS_JSONL" | tr -d ' ')" == "2" ]] || fail "scan_subject_count_invalid"

MODEL_URL="$(jq -er '.models[0].immutableUrl' "$ARTIFACT_SET")"
MODEL_EXPECTED_DIGEST="$(jq -er '.models[0].digest' "$ARTIFACT_SET")"
MODEL_EXPECTED_SIZE="$(jq -er '.models[0].sizeBytes' "$ARTIFACT_SET")"
MODEL_MAX_SIZE="$(jq -er '.models[0].maximumAllowedBytes' "$ARTIFACT_SET")"
MODEL_HEADERS="$TEMP_DIR/model.headers"
curl --fail --silent --show-error --location --head \
  --proto '=https' --tlsv1.2 "$MODEL_URL" >"$MODEL_HEADERS"
MODEL_CONTENT_LENGTH="$(awk 'BEGIN{IGNORECASE=1} /^content-length:/ {gsub("\\r","",$2); value=$2} END{print value}' "$MODEL_HEADERS")"
[[ "$MODEL_CONTENT_LENGTH" =~ ^[0-9]+$ ]] || fail "model_content_length_missing"
((MODEL_CONTENT_LENGTH == MODEL_EXPECTED_SIZE && MODEL_CONTENT_LENGTH <= MODEL_MAX_SIZE)) || fail "model_pre_download_size_invalid"
MODEL_TEMP="$TEMP_DIR/model.download"
curl --fail --silent --show-error --location \
  --proto '=https' --tlsv1.2 \
  --max-filesize "$MODEL_MAX_SIZE" \
  --output "$MODEL_TEMP" \
  "$MODEL_URL"
MODEL_OBSERVED_SIZE="$(stat -c '%s' "$MODEL_TEMP")"
MODEL_OBSERVED_DIGEST="$(raw_digest "$MODEL_TEMP")"
[[ "$MODEL_OBSERVED_SIZE" == "$MODEL_EXPECTED_SIZE" ]] || fail "model_download_size_invalid"
[[ "$MODEL_OBSERVED_DIGEST" == "$MODEL_EXPECTED_DIGEST" ]] || fail "model_download_digest_invalid"
rm -f "$MODEL_TEMP"

COMPLETED_AT="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
STARTED_EPOCH="$(date -u -d "$STARTED_AT" +%s)"
COMPLETED_EPOCH="$(date -u -d "$COMPLETED_AT" +%s)"
((COMPLETED_EPOCH >= STARTED_EPOCH && COMPLETED_EPOCH - STARTED_EPOCH <= 21600)) || fail "collection_duration_invalid"

jq -nS \
  --arg evidenceId "$EVIDENCE_ID" \
  --arg artifactSetDigest "$ARTIFACT_SET_DIGEST" \
  --arg releaseSetDigest "$RELEASE_SET_DIGEST" \
  --arg riskPolicyDigest "$RISK_POLICY_DIGEST" \
  --arg runnerRelease "$RUNNER_RELEASE" \
  --arg runnerRevision "$RUNNER_REVISION" \
  --arg runnerImage "$RUNNER_IMAGE" \
  --arg runnerImageDigest "$RUNNER_IMAGE_DIGEST" \
  --arg runnerToolchainDigest "$RUNNER_TOOLCHAIN_DIGEST" \
  --arg collectorScriptDigest "$COLLECTOR_SCRIPT_DIGEST" \
  --arg actorIdentityDigest "$ACTOR_IDENTITY_DIGEST" \
  --arg signingPublicKeyDigest "$SIGNING_PUBLIC_KEY_DIGEST" \
  --arg startedAt "$STARTED_AT" \
  --arg completedAt "$COMPLETED_AT" \
  --arg trivyDatabaseDigest "$TRIVY_DATABASE_DIGEST" \
  --arg trivyJavaDatabaseDigest "$TRIVY_JAVA_DATABASE_DIGEST" \
  --arg trustedRootDigest "$TRUSTED_ROOT_DIGEST" \
  --arg modelObservedDigest "$MODEL_OBSERVED_DIGEST" \
  --argjson modelObservedSize "$MODEL_OBSERVED_SIZE" \
  --slurpfile subjects "$SUBJECTS_JSONL" \
  '{schemaVersion:1,kind:"orchestra.openshift.sno-trial-dependency-risk-collection-statement.v1",profileId:"orchestra-ocp-sno-trial-amd64-v1",targetClass:"engineering-trial",executionMode:"live",evidenceId:$evidenceId,bindings:{artifactSetDigest:$artifactSetDigest,releaseSetDigest:$releaseSetDigest,riskPolicyDigest:$riskPolicyDigest},runner:{release:$runnerRelease,revision:$runnerRevision,image:$runnerImage,imageDigest:$runnerImageDigest,toolchainDigest:$runnerToolchainDigest},collector:{scriptDigest:$collectorScriptDigest,actorIdentityDigest:$actorIdentityDigest,signingPublicKeyDigest:$signingPublicKeyDigest,startedAt:$startedAt,completedAt:$completedAt},scanners:{vulnerability:{name:"trivy",version:"0.72.0",databaseDigest:$trivyDatabaseDigest,javaDatabaseDigest:$trivyJavaDatabaseDigest},sbom:{name:"syft",version:"1.48.0"},signature:{name:"cosign",version:"3.1.1",trustedRootDigest:$trustedRootDigest}},subjects:$subjects,modelArtifact:{observedDigest:$modelObservedDigest,observedSizeBytes:$modelObservedSize},claims:{rawArtifactsRestricted:true,sourceAdmissionAuthorized:false,mirrorAuthorization:false,activationAuthorized:false,deploymentAuthorized:false,campaignEvidence:false,referenceProfileVerified:false}}' \
  >"$TEMP_DIR/collection-statement.json"
cosign sign-blob \
  --yes \
  --key "$SIGNING_KEY" \
  --bundle "$TEMP_DIR/collection-statement.sigstore.json" \
  "$TEMP_DIR/collection-statement.json" >/dev/null
cosign verify-blob \
  --key "$TEMP_DIR/collection-signing-public-key.pem" \
  --bundle "$TEMP_DIR/collection-statement.sigstore.json" \
  "$TEMP_DIR/collection-statement.json" >/dev/null
COLLECTION_STATEMENT_DIGEST="$(raw_digest "$TEMP_DIR/collection-statement.json")"
COLLECTION_SIGNATURE_DIGEST="$(raw_digest "$TEMP_DIR/collection-statement.sigstore.json")"

jq -nS \
  --arg evidenceId "$EVIDENCE_ID" \
  --arg artifactSetDigest "$ARTIFACT_SET_DIGEST" \
  --arg releaseSetDigest "$RELEASE_SET_DIGEST" \
  --arg riskPolicyDigest "$RISK_POLICY_DIGEST" \
  --arg runnerRelease "$RUNNER_RELEASE" \
  --arg runnerRevision "$RUNNER_REVISION" \
  --arg runnerImage "$RUNNER_IMAGE" \
  --arg runnerImageDigest "$RUNNER_IMAGE_DIGEST" \
  --arg runnerToolchainDigest "$RUNNER_TOOLCHAIN_DIGEST" \
  --arg actorIdentityDigest "$ACTOR_IDENTITY_DIGEST" \
  --arg startedAt "$STARTED_AT" \
  --arg completedAt "$COMPLETED_AT" \
  --arg collectionStatementDigest "$COLLECTION_STATEMENT_DIGEST" \
  --arg collectionSignatureBundleDigest "$COLLECTION_SIGNATURE_DIGEST" \
  --arg trivyDatabaseDigest "$TRIVY_DATABASE_DIGEST" \
  --arg trivyJavaDatabaseDigest "$TRIVY_JAVA_DATABASE_DIGEST" \
  --arg trustedRootDigest "$TRUSTED_ROOT_DIGEST" \
  --arg modelId "$(jq -er '.models[0].id' "$ARTIFACT_SET")" \
  --arg modelUrl "$MODEL_URL" \
  --arg modelRevision "$(jq -er '.models[0].revision' "$ARTIFACT_SET")" \
  --arg modelExpectedDigest "$MODEL_EXPECTED_DIGEST" \
  --arg modelObservedDigest "$MODEL_OBSERVED_DIGEST" \
  --argjson modelExpectedSize "$MODEL_EXPECTED_SIZE" \
  --argjson modelObservedSize "$MODEL_OBSERVED_SIZE" \
  --arg modelLicense "$(jq -er '.models[0].license' "$ARTIFACT_SET")" \
  --slurpfile subjects "$SUBJECTS_JSONL" \
  '{schemaVersion:1,kind:"orchestra.openshift.sno-trial-dependency-risk-collection-manifest.v1",evidenceId:$evidenceId,profileId:"orchestra-ocp-sno-trial-amd64-v1",targetClass:"engineering-trial",executionMode:"live",bindings:{artifactSetDigest:$artifactSetDigest,releaseSetDigest:$releaseSetDigest,riskPolicyDigest:$riskPolicyDigest},collection:{executionClass:"signed-certification-runner",runnerRelease:$runnerRelease,runnerRevision:$runnerRevision,runnerImage:$runnerImage,runnerImageDigest:$runnerImageDigest,runnerToolchainDigest:$runnerToolchainDigest,actorIdentityDigest:$actorIdentityDigest,startedAt:$startedAt,completedAt:$completedAt,collectionStatementDigest:$collectionStatementDigest,collectionSignatureBundleDigest:$collectionSignatureBundleDigest,vulnerabilityScanner:{name:"trivy",version:"0.72.0",databaseDigest:$trivyDatabaseDigest,javaDatabaseDigest:$trivyJavaDatabaseDigest},sbomScanner:{name:"syft",version:"1.48.0"},signatureProbe:{name:"cosign",version:"3.1.1",trustedRootDigest:$trustedRootDigest,offlineVerification:false},rawArtifactsRestricted:true},subjects:$subjects,modelArtifact:{id:$modelId,immutableUrl:$modelUrl,revision:$modelRevision,expectedDigest:$modelExpectedDigest,observedDigest:$modelObservedDigest,expectedSizeBytes:$modelExpectedSize,observedSizeBytes:$modelObservedSize,declaredLicense:$modelLicense,bytesVerified:true,contentLengthVerified:true,licenseReview:{state:"required",reviewerIdentityDigest:null,reviewDigest:null}}}' \
  >"$TEMP_DIR/collection-manifest.json"
python3 "$ROOT/scripts/build_sno_trial_dependency_risk_evidence.py" \
  --manifest "$TEMP_DIR/collection-manifest.json" \
  --output "$TEMP_DIR/risk-evidence.json"
python3 "$ROOT/scripts/sno_trial_dependency_risk.py" validate-evidence \
  --report "$TEMP_DIR/risk-evidence.json" >/dev/null

rm -rf "$TRIVY_CACHE" "$SUBJECTS_JSONL"
chmod 0600 "$TEMP_DIR"/*
mv "$TEMP_DIR" "$OUTPUT_DIR"
trap - EXIT
printf 'sno_dependency_risk_collection_complete output=%s evidence=%s statement=%s sourceAdmission=false activation=false deployment=false\n' \
  "$OUTPUT_DIR" "$(canonical_digest "$OUTPUT_DIR/risk-evidence.json")" "$COLLECTION_STATEMENT_DIGEST"
