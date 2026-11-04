#!/usr/bin/env bash
# destroy-lab.sh [--dry-run] [--yes] [--keep-host] [--keep-credentials]
#
# 🛑 DESTRUCTIVE, own resources only. Deletes every ovlm-* resource of the lab and nothing else:
#   servers, volume snapshots/backups, volumes (including ovlm-acc-data: lab data, gone for good), images,
#   leftover ports, security groups, keypairs, application credentials.
# - The set-aside floating IP is never deleted: it is only disassociated from ovlm-* servers.
# - Every delete first re-reads the object and refuses it unless its name matches ^ovlm-[a-z0-9-]+$.
# - A resource that looks like OVLM's (tag ovlm-lab or ovlm:managed) but is not named ovlm-* stops the run
#   (exit 4) and is never deleted: ask the maintainer.
# - Needs --yes and the typed confirmation DESTROY-OVLM-LAB. At the end it lists the project again and fails
#   (exit 1) if any ovlm-* resource is still there. --keep-host keeps ovlm-lab-host (and then ovlm-lab-key and
#   ovlm-lab-sg, which it uses); --keep-credentials keeps the ovlm-* application credentials.
# Take snapshots before and after (snapshot.sh) and run diff-snapshots.sh: that is the proof that nothing else moved.
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() { print_usage "${BASH_SOURCE[0]}"; exit "${1:-0}"; }
parse_common "$@"
keep_host=0; keep_cred=0
for a in "${REST[@]:-}"; do
  case "$a" in
    --keep-host) keep_host=1 ;;
    --keep-credentials) keep_cred=1 ;;
    -h|--help) usage 0 ;;
    "") ;;
    *) usage 2 ;;
  esac
done
((DRY_RUN)) || need_cmd openstack jq
export OS_COMPUTE_API_VERSION="${OS_COMPUTE_API_VERSION:-2.85}"

# list_ovlm TYPE: prints "<id>\t<name>" for every ovlm-* object of that type (keypairs: name\tname).
list_ovlm() {
  local type="$1" out
  # shellcheck disable=SC2086  # TYPE is several words on purpose
  if ((DRY_RUN)); then _show openstack $type list -f json; return 0; fi
  # shellcheck disable=SC2086
  out="$(openstack $type list -f json)" || die "cannot list '$type'; refusing to continue blind"
  jq -r '.[] | select((.Name // "") | test("^ovlm-")) | [(.ID // .Name), .Name] | @tsv' <<<"$out"
}

show_name() {  # show_name TYPE ID -> current name (empty if gone)
  local type="$1" id="$2"
  # shellcheck disable=SC2086
  openstack $type show "$id" -f value -c name 2>/dev/null || true
}

guarded_delete() {  # guarded_delete TYPE ID [extra delete args]
  local type="$1" id="$2"; shift 2
  if ((DRY_RUN)); then
    # shellcheck disable=SC2086
    _show openstack $type delete "$@" "$id"; return 0
  fi
  local name; name="$(show_name "$type" "$id")"
  [[ -n "$name" ]] || { log "$type $id already gone"; return 0; }
  ovlm_name_ok "$name" || die "REFUSING to delete $type $id: name is not ovlm-* (exit 3)"
  log "🛑 DELETE $type $name"
  # shellcheck disable=SC2086
  openstack $type delete "$@" "$id"
}

# 0. stop on look-alikes: tagged for the lab but not named ovlm-*
if ! ((DRY_RUN)); then
  stray="$(openstack server list --long -f json | jq -r '.[]
    | select((.Name | test("^ovlm-") | not)
             and ((.Tags // []) | if type == "array" then . else [.] end | any(. == "ovlm-lab" or . == "ovlm:managed")))
    | .ID')"
  if [[ -n "$stray" ]]; then
    warn "servers tagged for OVLM but NOT named ovlm-* (never deleted by this script):"; echo "$stray" >&2
    echo "Stop: tell the maintainer. A renewal profile must name green servers ovlm-*." >&2; exit 4
  fi
else
  _show openstack server list --long -f json   # real run: stop (exit 4) if a server is tagged ovlm-lab or ovlm:managed but not named ovlm-*
fi

# 1. plan
declare -A plan
for t in server "volume snapshot" "volume backup" volume image port "security group" keypair; do
  plan[$t]="$(list_ovlm "$t")"
done
((keep_cred)) || plan["application credential"]="$(list_ovlm "application credential")"
if ! ((DRY_RUN)); then
  log "plan (names only):"
  for t in "${!plan[@]}"; do
    while IFS=$'\t' read -r _ n; do
      [[ -n "$n" ]] || continue
      if ((keep_host)) && [[ "$n" == "$N_HOST" || "$n" == "$N_KEY" || "$n" == "$N_SG_HOST" ]]; then continue; fi
      echo "  $t: $n"
    done <<<"${plan[$t]}"
  done | sort >&2
fi
confirm_typed "DESTROY-OVLM-LAB"

keep() { ((keep_host)) && [[ "$1" == "$N_HOST" || "$1" == "$N_KEY" || "$1" == "$N_SG_HOST" ]]; }

# 2. floating IPs: disassociate from ovlm-* servers, never delete
if ! ((DRY_RUN)); then
  ovlm_server_ids="$(jq -R . <<<"$(cut -f1 <<<"${plan[server]}")" | jq -s 'map(select(length>0))')"
  while IFS=$'\t' read -r fid port; do
    [[ -n "$port" ]] || continue
    owner="$(openstack port show "$port" -f value -c device_id)"
    if jq -e --arg o "$owner" 'index($o) != null' <<<"$ovlm_server_ids" >/dev/null; then
      log "🛑 disassociate floating IP $fid from an ovlm-* server (the address stays allocated)"
      openstack floating ip unset --port "$fid"
    fi
  done < <(openstack floating ip list -f json | jq -r '.[] | select(.Port != null) | [.ID, .Port] | @tsv')
else
  _show openstack floating ip unset --port "<fip-id of an ovlm-* server>"
fi

# 3. delete in dependency order
delete_type() {  # delete_type TYPE [extra args]
  local t="$1"; shift
  if ((DRY_RUN)); then guarded_delete "$t" "<id>" "$@"; return; fi
  local id name
  while IFS=$'\t' read -r id name; do
    [[ -n "$id" ]] || continue
    keep "$name" && { log "keeping $name"; continue; }
    guarded_delete "$t" "$id" "$@"
  done <<<"${plan[$t]:-}"
}
delete_type server --wait
if ! ((DRY_RUN)); then
  # a volume may take a moment to leave in-use after its server is gone
  while IFS=$'\t' read -r id name; do
    [[ -n "$id" ]] || continue
    for _ in $(seq 1 24); do [[ "$(openstack volume show "$id" -f value -c status 2>/dev/null)" != in-use ]] && break; sleep 5; done
    [[ "$(openstack volume show "$id" -f value -c status 2>/dev/null || echo gone)" != in-use ]] || die "volume $name is still in-use (attached to something that is not an ovlm-* server?): stop and ask the maintainer"
  done <<<"${plan[volume]:-}"
fi
delete_type "volume snapshot"
delete_type "volume backup"
delete_type volume
delete_type image
delete_type port
# security groups: the target group references the host group, so try twice (second pass after the first deletions)
for _pass in 1 2; do
  if ((DRY_RUN)); then guarded_delete "security group" "<id>"; break; fi
  while IFS=$'\t' read -r id name; do
    [[ -n "$id" ]] || continue
    keep "$name" && continue
    [[ -n "$(show_name "security group" "$id")" ]] || continue
    guarded_delete "security group" "$id" || warn "security group $name still referenced; will retry"
  done <<<"${plan["security group"]:-}"
done
if ! ((DRY_RUN)); then
  while IFS=$'\t' read -r id name; do [[ -n "$id" ]] || continue; keep "$name" && continue
    log "🛑 DELETE keypair $name"; assert_ovlm "$name"; openstack keypair delete "$name"; done <<<"${plan[keypair]:-}"
  ((keep_cred)) || while IFS=$'\t' read -r id name; do [[ -n "$id" ]] || continue
    assert_ovlm "$name"; log "🛑 DELETE application credential $name"; openstack application credential delete "$id"; done <<<"${plan["application credential"]:-}"
else
  _show openstack keypair delete "<name>"; ((keep_cred)) || _show openstack application credential delete "<id>"
fi

# 4. prove nothing ovlm-* is left
if ((DRY_RUN)); then echo "+ verify: re-list server, volume, volume snapshot, volume backup, image, port, security group, keypair, application credential; fail if any ovlm-* remains" >&9; exit 0; fi
left=0
for t in server "volume snapshot" "volume backup" volume image port "security group" keypair; do
  rest="$(list_ovlm "$t")"
  while IFS=$'\t' read -r _ n; do [[ -n "${n:-}" ]] || continue; keep "$n" && continue; warn "LEFT: $t $n"; left=1; done <<<"$rest"
done
if ! ((keep_cred)); then
  rest="$(list_ovlm "application credential")"
  while IFS=$'\t' read -r _ n; do [[ -n "${n:-}" ]] || continue; warn "LEFT: application credential $n"; left=1; done <<<"$rest"
fi
((left == 0)) || die "ovlm-* resources are still present (see above); do not report the cleanup as complete"
log "clean: 0 ovlm-* resources left$( ((keep_host)) && echo ' (host kept on request)')"
log "now: snapshot.sh after-destroy && diff-snapshots.sh <before-snapshot> after-destroy"
