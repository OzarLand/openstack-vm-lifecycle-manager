#!/usr/bin/env bash
# inject.sh KIND RUN_ID STEP [SECONDS] [--dry-run]
#
# ⚠️ Fault injection on the OVLM lab host (never on Felcloud resources): waits until run RUN_ID reaches STEP,
# then acts on the OVLM Compose stack over SSH. STEP is a workflow step key (B4, B7, W1, W3, W5 ...) or a run
# state (for a gate wait). It polls the API every 0.5 s through the operator's SSH tunnel.
#   worker-kill   docker compose kill -s KILL worker      (LAB-01 a-e, LAB-08)
#   worker-term   docker compose kill -s TERM worker      (LAB-08)
#   db-stop       stop PostgreSQL for SECONDS (default 30), then start it   (LAB-07)
#   worker-start  docker compose up -d worker             (the Compose file has no restart policy: start it again)
# Settings from the environment: OVLM_URL (default http://127.0.0.1:8000, the tunnel), OVLM_TOKEN_FILE,
# OVLM_LAB_HOST_SSH (user@host), optional OVLM_LAB_SSH_OPTS. Timestamps go to $OVLM_LAB_WORKDIR/inject-RUN_ID.log.
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

remote() {  # remote 'command run in ~/ovlm on the lab host'
  need_var OVLM_LAB_HOST_SSH
  # shellcheck disable=SC2086
  ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$OVLM_LAB_WORKDIR/known_hosts" ${OVLM_LAB_SSH_OPTS:-} "$OVLM_LAB_HOST_SSH" "cd ovlm && $1"
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
