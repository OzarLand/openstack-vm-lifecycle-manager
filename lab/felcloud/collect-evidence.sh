#!/usr/bin/env bash
# collect-evidence.sh SCENARIO PHASE [--run-id ID] [--dry-run]
#
# READ-ONLY on the cloud and on OVLM. Collects one evidence bundle for a scenario, REDACTED before it touches disk:
# no IPs (v4/v6), MACs, hostnames, URLs, tokens, key material, fingerprints or secret-named JSON fields.
#   SCENARIO  e.g. ACC-01, LAB-05 (letters, digits, dash)
#   PHASE     before | during | after   (one OpenStack inventory file per phase)
# Writes $OVLM_LAB_WORKDIR/evidence/<date>/<SCENARIO>/ :
#   openstack/<PHASE>.json   ovlm-* servers, volumes, the set-aside floating IP's holder (a name, never the address)
#   ovlm/run.json, steps.json, audit.json   if --run-id and OVLM_URL (+ OVLM_TOKEN_FILE) are set (SSH tunnel to the API)
#   lab-host/compose-ps.txt, worker.log, api.log   if OVLM_LAB_HOST_SSH (user@host, from the environment) is set
#   ENV.md, collection.log, SHA256SUMS
# A canary scan runs over the finished bundle; on any hit the bundle is deleted and the script fails.
# The bundle is still a draft: a human reviews it before anything is called "lab validated" (testing-strategy 7.3).
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() { print_usage "${BASH_SOURCE[0]}"; exit "${1:-0}"; }
parse_common "$@"
set -- "${REST[@]:-}"
scenario="${1:-}"; phase="${2:-}"; shift 2 || usage 2
run_id=""
while (($#)); do
  case "$1" in
    --run-id) [[ $# -ge 2 ]] || usage 2; run_id="$2"; shift ;;
    "") ;;
    *) usage 2 ;;
  esac
  shift
done
[[ "$scenario" =~ ^[A-Za-z0-9-]+$ ]] || usage 2
[[ "$phase" =~ ^(before|during|after)$ ]] || usage 2
[[ -z "$run_id" || "$run_id" =~ ^[A-Za-z0-9-]+$ ]] || die "run id must be [A-Za-z0-9-]+"

dir="$OVLM_LAB_WORKDIR/evidence/$(date -u +%Y-%m-%d)/$scenario"
if ((DRY_RUN)); then
  _show openstack server list --long -f json; echo "+ for each ovlm-* server: openstack server show <id> -f json   (addresses dropped)" >&9
  _show openstack volume list --long -f json; _show openstack floating ip list --floating-ip-address '<set-aside-fip>' -f json
  _show openstack versions show -f json
  [[ -z "$run_id" ]] || echo "+ curl \$OVLM_URL/api/v1/runs/$run_id (+ /steps, /audit?run=$run_id), token from \$OVLM_TOKEN_FILE" >&9
  echo "+ ssh \$OVLM_LAB_HOST_SSH 'cd ovlm && docker compose ps; docker compose logs --no-color --since 3h worker api'   # if set" >&9
  echo "+ every file: redact | write to $dir/...; canary scan; SHA256SUMS" >&9
  exit 0
fi
need_cmd openstack jq perl sha256sum
mkdir -p "$dir/openstack" "$dir/ovlm" "$dir/lab-host"; chmod -R go-rwx "$dir"
incomplete=0
note() { printf '%s %s\n' "$(date -u +%H:%M:%SZ)" "$*" >>"$dir/collection.log"; }
save() { redact >"$dir/$1"; }   # save RELATIVE_PATH < raw-stdin

# ---- OpenStack: ovlm-* only, addresses dropped by construction, then redacted
servers="$(openstack server list --long -f json | jq -c '[.[] | select((.Name // "") | test("^ovlm-")) | .ID]')"
vols="$(openstack volume list --long -f json | jq -c '[.[] | select((.Name // "") | test("^ovlm-"))]')"
srv_json="[]"
for id in $(jq -r '.[]' <<<"$servers"); do
  one="$(openstack server show "$id" -f json | jq -c '{name, status, locked: (.locked // false), locked_reason: (.locked_reason // null),
        tags: (.tags // []), flavor: ((.flavor // "") | if type == "object" then (.original_name // .name // "") else . end),
        volumes_attached: [(.volumes_attached // [])[] | (if type == "object" then .id else . end)], fault: (.fault.message? // null),
        launched_at: (.["OS-SRV-USG:launched_at"] // null)}')"
  srv_json="$(jq -c --argjson o "$one" '. + [$o]' <<<"$srv_json")"
done
holder="null"
if [[ -n "${OVLM_LAB_FIP:-}" ]]; then
  port="$(openstack floating ip list --floating-ip-address "$OVLM_LAB_FIP" -f json | jq -r '.[0].Port // ""')"
  if [[ -n "$port" ]]; then
    owner="$(openstack port show "$port" -f value -c device_id)"
    holder="$(openstack server show "$owner" -f value -c name 2>/dev/null | jq -R . || echo null)"
  fi
fi
versions="$(openstack versions show -f json 2>/dev/null | jq -c '[.[] | select((.["Service Type"] // .Service // "") | IN("compute","volumev3","block-storage","network","image")) | {service: (.["Service Type"] // .Service), version: (.Version // null), max_microversion: (.["Max Microversion"] // null)}]' 2>/dev/null || echo '[]')"
jq -n --arg scenario "$scenario" --arg phase "$phase" --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --argjson servers "$srv_json" --argjson volumes "$vols" --argjson holder "$holder" --argjson versions "$versions" '
  {schema: "ovlm.lab-openstack/1", scenario: $scenario, phase: $phase, taken_at: $at, servers: $servers,
   volumes: ($volumes | map({name: .Name, status: .Status, size: .Size, type: .Type, attached_to: (.["Attached to"] // [])})),
   set_aside_floating_ip_held_by: $holder, api_versions: $versions}' | save "openstack/$phase.json"
note "openstack/$phase.json written"

# ---- OVLM API through the operator's SSH tunnel (token from a file, never on a command line)
if [[ -n "$run_id" && -n "${OVLM_URL:-}" ]]; then
  fetch() {  # fetch PATH OUTFILE
    local code
    code="$(curl -sS -o "$dir/.raw" -w '%{http_code}' --max-time 30 ${OVLM_TOKEN_FILE:+-K <(printf 'header = "Authorization: Bearer %s"\n' "$(<"$OVLM_TOKEN_FILE")")} "$OVLM_URL$1" || echo 000)"
    if [[ "$code" == 200 ]]; then save "$2" <"$dir/.raw"; note "$1 ok"; else incomplete=1; note "$1 FAILED (HTTP $code)"; fi
    rm -f "$dir/.raw"
  }
  fetch "/api/v1/runs/$run_id" ovlm/run.json
  fetch "/api/v1/runs/$run_id/steps" ovlm/steps.json
  fetch "/api/v1/audit?run=$run_id" ovlm/audit.json
elif [[ -n "$run_id" ]]; then incomplete=1; note "no OVLM_URL set: run, steps and audit NOT collected"; fi

# ---- lab host logs (the ssh destination comes from the environment, never from this repository)
if [[ -n "${OVLM_LAB_HOST_SSH:-}" ]]; then
  # shellcheck disable=SC2086  # OVLM_LAB_SSH_OPTS is a list of options by design
  rssh() { ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$OVLM_LAB_WORKDIR/known_hosts" ${OVLM_LAB_SSH_OPTS:-} "$OVLM_LAB_HOST_SSH" "$@"; }
  rssh 'cd ovlm && docker compose ps' 2>>"$dir/collection.log" | save lab-host/compose-ps.txt || { incomplete=1; note "compose ps FAILED"; }
  rssh 'cd ovlm && docker compose logs --no-color --since 3h worker' 2>>"$dir/collection.log" | save lab-host/worker.log || { incomplete=1; note "worker log FAILED"; }
  rssh 'cd ovlm && docker compose logs --no-color --since 3h api' 2>>"$dir/collection.log" | save lab-host/api.log || { incomplete=1; note "api log FAILED"; }
  commit="$(rssh 'cat ovlm-commit.txt' 2>/dev/null || echo unknown)"
else commit="unknown (OVLM_LAB_HOST_SSH not set)"; fi
printf '# Lab environment\n\n- cloud: Felcloud (ADR-0007), project ozar-lab, resources ovlm-* only\n- OVLM commit: %s\n- collected: %s\n- virt: real KVM (not nested)\n- scenario: %s, phase: %s\n' \
  "$commit" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$scenario" "$phase" | save ENV.md

# ---- canary: nothing sensitive may survive; literal values the operator configured are searched too
bad=0
ssh_host_part="${OVLM_LAB_HOST_SSH:-}"; ssh_host_part="${ssh_host_part#*@}"
while IFS= read -r -d '' f; do
  canary_clean <"$f" || { warn "canary pattern in $(basename "$f")"; bad=1; }
  for v in "${OVLM_LAB_FIP:-}" "${OVLM_LAB_ADMIN_CIDR:-}" "${OVLM_LAB_HOST_SSH:-}" "$ssh_host_part"; do
    [[ -n "$v" ]] || continue
    if grep -qF -- "$v" "$f"; then warn "a configured sensitive value survived in $(basename "$f")"; bad=1; fi
  done
  if [[ -n "${OVLM_TOKEN_FILE:-}" && -r "$OVLM_TOKEN_FILE" ]] && grep -qF -- "$(<"$OVLM_TOKEN_FILE")" "$f"; then warn "token survived in $(basename "$f")"; bad=1; fi
done < <(find "$dir" -type f ! -name SHA256SUMS -print0)
if ((bad)); then rm -rf "$dir"; die "canary check failed: the bundle was deleted. Nothing was kept."; fi
sums="$(cd "$dir" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum)"
printf '%s\n' "$sums" >"$dir/SHA256SUMS"
log "evidence bundle (redacted, canary clean): $dir"
if ((incomplete)); then warn "bundle is INCOMPLETE, see collection.log"; exit 3; fi
