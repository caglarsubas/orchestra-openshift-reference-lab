#!/usr/bin/env bash
set -Eeuo pipefail

umask 077
export LC_ALL=C
export TZ=UTC

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNNER_LOCK="$ROOT/config/production-model-custody-runner.lock.json"
CANDIDATE="$ROOT/config/production-model-artifact-candidate.lock.json"

RUNNER_ROOT=""
REGISTRATION_TOKEN_FILE=""
CHAT_MODEL=""
EMBEDDING_MODEL=""
RUNNER_NAME=""

fail() {
  printf 'production_model_custody_runner_failed code=%s\n' "$1" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: run_ephemeral_production_model_custody_runner.sh \
  --runner-root <new-empty-private-directory> \
  --registration-token-file <0600-short-lived-token-file> \
  --chat-model <operator-obtained-chat.gguf> \
  --embedding-model <operator-obtained-embedding.gguf> \
  --runner-name <unique-runner-name>

Download and verify the locked official GitHub Actions Linux/x64 runner,
prestage the two exact operator-obtained models in the one permitted ignored
workspace inbox, register one ephemeral no-update repository runner, execute
one job, and remove the complete runner root on exit.

Run as a dedicated non-root user on a disposable Linux/AMD64 host. This script
does not download models and does not grant custody, licence, admission,
deployment, campaign, or certification authority.
EOF
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required_command_missing:$1"
}

file_digest() {
  printf 'sha256:%s' "$(sha256sum "$1" | awk '{print $1}')"
}

verify_model() {
  local path="$1"
  local service_id="$2"
  [[ -f "$path" && ! -L "$path" ]] || fail "model_regular_file_required:$service_id"
  local expected_size
  local expected_digest
  expected_size="$(jq -er --arg service "$service_id" \
    '.models[] | select(.serviceId == $service) | .sizeBytes' "$CANDIDATE")"
  expected_digest="$(jq -er --arg service "$service_id" \
    '.models[] | select(.serviceId == $service) | .digest' "$CANDIDATE")"
  [[ "$(stat -c '%s' "$path")" == "$expected_size" ]] || fail "model_size_invalid:$service_id"
  [[ "$(file_digest "$path")" == "$expected_digest" ]] || fail "model_digest_invalid:$service_id"
}

while (($# > 0)); do
  case "$1" in
    --runner-root)
      RUNNER_ROOT="${2:-}"
      shift 2
      ;;
    --registration-token-file)
      REGISTRATION_TOKEN_FILE="${2:-}"
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
    --runner-name)
      RUNNER_NAME="${2:-}"
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

[[ "$(uname -s)" == "Linux" ]] || fail "linux_required"
[[ "$(uname -m)" == "x86_64" ]] || fail "x86_64_required"
[[ "$EUID" -ne 0 ]] || fail "root_forbidden"
[[ -n "$RUNNER_ROOT" && "$RUNNER_ROOT" == /* ]] || fail "runner_root_absolute_required"
[[ ! -e "$RUNNER_ROOT" ]] || fail "runner_root_must_not_exist"
[[ "$RUNNER_NAME" =~ ^orchestra-model-custody-[a-z0-9][a-z0-9.-]{5,63}$ ]] || fail "runner_name_invalid"
[[ -f "$REGISTRATION_TOKEN_FILE" && ! -L "$REGISTRATION_TOKEN_FILE" ]] || fail "registration_token_file_invalid"
[[ "$(stat -c '%a' "$REGISTRATION_TOKEN_FILE")" == "600" ]] || fail "registration_token_mode_invalid"
for command_name in curl jq sha256sum awk tar stat uname cp rm; do
  require_command "$command_name"
done
verify_model "$CHAT_MODEL" "model-backend"
verify_model "$EMBEDDING_MODEL" "embedding-model"

RUNNER_URL="$(jq -er '.archive.url' "$RUNNER_LOCK")"
RUNNER_FILENAME="$(jq -er '.archive.filename' "$RUNNER_LOCK")"
RUNNER_DIGEST="$(jq -er '.archive.digest' "$RUNNER_LOCK")"
REPOSITORY="$(jq -er '.registration.repository' "$RUNNER_LOCK")"
WORK_DIRECTORY="$(jq -er '.workspace.workDirectory' "$RUNNER_LOCK")"
INBOX_RELATIVE="$(jq -er '.workspace.privateInbox' "$RUNNER_LOCK")"
[[ "$RUNNER_URL" == "https://github.com/actions/runner/releases/download/v2.336.0/actions-runner-linux-x64-2.336.0.tar.gz" ]] || fail "runner_url_invalid"
[[ "$RUNNER_FILENAME" == "actions-runner-linux-x64-2.336.0.tar.gz" ]] || fail "runner_filename_invalid"
[[ "$RUNNER_DIGEST" =~ ^sha256:[a-f0-9]{64}$ ]] || fail "runner_digest_invalid"
[[ "$REPOSITORY" == "caglarsubas/orchestra-openshift-reference-lab" ]] || fail "repository_invalid"
[[ "$WORK_DIRECTORY" == "_work" ]] || fail "work_directory_invalid"

mkdir -m 0700 "$RUNNER_ROOT"
cleanup() {
  rm -rf "$RUNNER_ROOT"
  rm -f "$REGISTRATION_TOKEN_FILE"
}
trap cleanup EXIT

ARCHIVE="$RUNNER_ROOT/$RUNNER_FILENAME"
curl \
  --fail \
  --location \
  --proto '=https' \
  --tlsv1.2 \
  --retry 3 \
  --retry-all-errors \
  --output "$ARCHIVE" \
  "$RUNNER_URL"
chmod 0600 "$ARCHIVE"
[[ "$(file_digest "$ARCHIVE")" == "$RUNNER_DIGEST" ]] || fail "runner_archive_digest_invalid"
tar -xzf "$ARCHIVE" -C "$RUNNER_ROOT"
rm -f "$ARCHIVE"

INBOX="$RUNNER_ROOT/$INBOX_RELATIVE"
mkdir -p "$INBOX"
chmod 0700 "$INBOX"
CHAT_FILENAME="$(jq -er '.models[] | select(.serviceId == "model-backend") | .filename' "$CANDIDATE")"
EMBEDDING_FILENAME="$(jq -er '.models[] | select(.serviceId == "embedding-model") | .filename' "$CANDIDATE")"
cp --reflink=auto --no-preserve=mode,ownership,timestamps \
  "$CHAT_MODEL" "$INBOX/$CHAT_FILENAME"
cp --reflink=auto --no-preserve=mode,ownership,timestamps \
  "$EMBEDDING_MODEL" "$INBOX/$EMBEDDING_FILENAME"
chmod 0600 "$INBOX/$CHAT_FILENAME" "$INBOX/$EMBEDDING_FILENAME"
verify_model "$INBOX/$CHAT_FILENAME" "model-backend"
verify_model "$INBOX/$EMBEDDING_FILENAME" "embedding-model"

REGISTRATION_TOKEN="$(tr -d '\r\n' <"$REGISTRATION_TOKEN_FILE")"
[[ "$REGISTRATION_TOKEN" =~ ^[A-Za-z0-9._-]{20,4096}$ ]] || fail "registration_token_invalid"
rm -f "$REGISTRATION_TOKEN_FILE"

cd "$RUNNER_ROOT"
./config.sh \
  --unattended \
  --ephemeral \
  --disableupdate \
  --url "https://github.com/$REPOSITORY" \
  --token "$REGISTRATION_TOKEN" \
  --name "$RUNNER_NAME" \
  --labels "orchestra-model-custody-upload" \
  --work "$WORK_DIRECTORY"
unset REGISTRATION_TOKEN

printf 'production_model_custody_ephemeral_runner_registered name=%s ephemeral=true updateDisabled=true modelDownloadPerformed=false artifactCustodyVerified=false admissionAuthorized=false\n' \
  "$RUNNER_NAME"
./run.sh
