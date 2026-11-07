#!/usr/bin/env bash
# inject.sh KIND RUN_ID STEP [SECONDS] [--dry-run]
#
# ⚠️ Fault injection on the OVLM lab host (never on Felcloud resources): waits until run RUN_ID reaches STEP,
# then acts on the OVLM Compose stack over SSH. STEP is a workflow step key (B4, B7, W1, W3, W5 ...) or a run
# state (for a gate wait). It polls the API every 0.5 s through the operator's SSH tunnel.
#   STEP: a step code (B4, B7, W1, W3, W5, G2 = waiting at the cutover gate ...) or the step key itself.
#   worker-kill   docker compose kill -s KILL worker      (LAB-01 a-e, LAB-08)
#   worker-term   docker compose kill -s TERM worker      (LAB-08)
#   db-stop       stop PostgreSQL for SECONDS (default 30), then start it   (LAB-07)
#   worker-start  docker compose up -d worker             (the Compose file has no restart policy: start it again)
# Settings from the environment: OVLM_URL (default http://127.0.0.1:8000, the tunnel), OVLM_TOKEN_FILE,
# OVLM_LAB_HOST_SSH (user@host), OVLM_LAB_SSH_KEY_FILE (optional), optional OVLM_LAB_SSH_OPTS. Timestamps go to $OVLM_LAB_WORKDIR/inject-RUN_ID.log.
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() { print_usage "${BASH_SOURCE[0]}"; exit "${1:-0}"; }
parse_common "$@"
set -- "${REST[@]:-}"
[[ "${1:-}" == -h || "${1:-}" == --help ]] && usage 0
kind="${1:-}"; run="${2:-}"; step="${3:-}"; secs="${4:-30}"
[[ "$kind" =~ ^(worker-kill|worker-term|db-stop|worker-start)$ ]] || usage 2
[[ "$secs" =~ ^[0-9]+$ ]] || usage 2
if [[ "$kind" != worker-start ]]; then
  [[ "$run" =~ ^[A-Za-z0-9-]+$ && "$step" =~ ^[A-Za-z0-9_-]+$ ]] || usage 2
fi
: "${OVLM_URL:=http://127.0.0.1:8000}"
mkdir_work; logf="$OVLM_LAB_WORKDIR/inject-${run:-none}.log"

# Step codes (as in renewal-workflow.md and the UI) -> step keys (what GET /runs/{id} reports in current_step).
# Keys are accepted as they are (lab bug U: the docs say B4/W1 but the API only ever shows the key).
step_key_of() {
  case "$1" in
    B1) echo preflight ;; B2) echo claim_resources ;; B3) echo create_green ;; B4) echo wait_green_active ;;
    B5) echo wait_green_ssh ;; B6) echo prepare_automation ;; B7) echo configure_green ;;
    B8) echo verify_cutover_preconditions ;; B9) echo verify_green_ready ;; G2) echo await_cutover ;;
    W1) echo quiesce_old ;; W2) echo stop_old ;; W3) echo detach_volume ;; W4) echo snapshot_volume ;;
    W5) echo attach_volume_green ;; W6) echo data_attach_green ;; W7) echo start_service_green ;;
    W8) echo healthcheck_green ;; W9) echo move_fip ;; W10) echo verify_external ;;
    R1) echo retain_old ;; R2) echo await_retention ;; X1) echo retire_old ;;
    S1) echo unlock_old ;; S2) echo quiesce_green ;; S3) echo stop_green ;; S4) echo detach_from_green ;;
    S5) echo attach_to_old ;; S6) echo boot_old ;; S7) echo recover_old_service ;; S8) echo move_fip_to_old ;;
    S9) echo verify_external_old ;; S10) echo lock_green ;;
    *) echo "$1" ;;
  esac
}
if [[ -n "$step" ]]; then step="$(step_key_of "$step")"; fi

remote() {  # remote 'command run in ~/ovlm on the lab host'
  need_var OVLM_LAB_HOST_SSH
  # lab bug V: honour OVLM_LAB_SSH_KEY_FILE like the other scripts; -n so ssh never reads this script's stdin
  local key=()
  [[ -z "${OVLM_LAB_SSH_KEY_FILE:-}" ]] || key=(-i "$OVLM_LAB_SSH_KEY_FILE")
  # shellcheck disable=SC2086
  ssh -n -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$OVLM_LAB_WORKDIR/known_hosts" \
    "${key[@]}" ${OVLM_LAB_SSH_OPTS:-} "$OVLM_LAB_HOST_SSH" "cd ovlm && $1"
}
stamp() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)" "$*" | tee -a "$logf" >&2; }
current() {
  curl -fsS --max-time 5 ${OVLM_TOKEN_FILE:+-K <(printf 'header = "Authorization: Bearer %s"\n' "$(<"$OVLM_TOKEN_FILE")")} "$OVLM_URL/api/v1/runs/$run" 2>/dev/null \
    | jq -r '[(.state // ""), (.current_step | if type == "object" then (.key // .step_key // .name // "") else (. // "") end)] | .[]' 2>/dev/null || true
}

if ((DRY_RUN)); then
  case "$kind" in
    worker-kill) echo "+ poll GET \$OVLM_URL/api/v1/runs/$run every 0.5s until state or current_step == $step; then: ssh \$OVLM_LAB_HOST_SSH 'cd ovlm && docker compose kill -s KILL worker'" >&9 ;;
    worker-term) echo "+ (same wait); then: docker compose kill -s TERM worker" >&9 ;;
    db-stop) echo "+ (same wait); then: docker compose stop postgres; sleep $secs; docker compose start postgres" >&9 ;;
    worker-start) echo "+ ssh \$OVLM_LAB_HOST_SSH 'cd ovlm && docker compose up -d worker'" >&9 ;;
  esac
  exit 0
fi
need_cmd ssh curl jq
if [[ "$kind" == worker-start ]]; then stamp "⚠️ starting worker"; remote 'docker compose up -d worker'; stamp "worker started"; exit 0; fi

stamp "waiting for run $run to reach '$step'"
deadline=$((SECONDS + ${OVLM_INJECT_TIMEOUT:-3600}))
until current | grep -qxF -- "$step"; do
  ((SECONDS < deadline)) || die "run never reached '$step' within the timeout; nothing was injected"
  sleep 0.5
done
stamp "reached '$step': injecting $kind"
case "$kind" in
  worker-kill) remote 'docker compose kill -s KILL worker' ;;
  worker-term) remote 'docker compose kill -s TERM worker' ;;
  db-stop) remote 'docker compose stop postgres'; stamp "postgres stopped for ${secs}s"; sleep "$secs"; remote 'docker compose start postgres' ;;
esac
stamp "injected $kind"
[[ "$kind" == db-stop ]] || stamp "the worker stays down until: inject.sh worker-start (Compose has no restart policy)"
