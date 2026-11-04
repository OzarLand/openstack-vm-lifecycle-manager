#!/usr/bin/env bash
# snapshot.sh LABEL [--dry-run]
#
# READ-ONLY. Writes a full inventory of the current project (every resource, not only ovlm-*) to
#   $OVLM_LAB_WORKDIR/snapshots/LABEL.json   (mode 0600; contains addresses, never commit it)
# Take one before and one after every lab run, then prove nothing outside ovlm-* changed:
#   diff-snapshots.sh before after            (ADR-0007 guard)
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() { print_usage "${BASH_SOURCE[0]}"; exit "${1:-0}"; }
parse_common "$@"
[[ ${#REST[@]} -eq 1 && "${REST[0]}" != -* ]] || usage 2
label="${REST[0]}"
[[ "$label" =~ ^[A-Za-z0-9._-]+$ ]] || die "label must match [A-Za-z0-9._-]+"

# TYPE | list command | show command | required(1)/optional(0)
COLLECTORS=(
  "server|server list|server show|1"
  "volume|volume list|volume show|1"
  "volume snapshot|volume snapshot list|volume snapshot show|0"
  "volume backup|volume backup list|volume backup show|0"
  "floating ip|floating ip list|floating ip show|1"
  "port|port list|port show|1"
  "network|network list|network show|1"
  "subnet|subnet list|subnet show|1"
  "router|router list|router show|1"
  "security group|security group list|security group show|1"
  "keypair|keypair list|keypair show|1"
  "image|image list --private|image show|0"
  "server group|server group list|server group show|0"
)

mkdir_work
out_dir="$OVLM_LAB_WORKDIR/snapshots"; mkdir -p "$out_dir"
out="$out_dir/$label.json"
[[ ! -e "$out" ]] || die "snapshot '$label' already exists ($out); pick a new label"

if ((DRY_RUN)); then
  for c in "${COLLECTORS[@]}"; do
    IFS='|' read -r type list show req <<<"$c"
    # shellcheck disable=SC2086
    os_ro $list -f json || true
    echo "+ for each id: openstack $show <id> -f json"
  done
  echo "+ assemble $out with jq"
  exit 0
fi

need_cmd openstack jq
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
unavailable=()

for c in "${COLLECTORS[@]}"; do
  IFS='|' read -r type list show req <<<"$c"
  key="${type// /_}"
  # shellcheck disable=SC2086
  if ! ids_json="$(openstack $list -f json 2>"$tmp/err")"; then
    if [[ "$req" == 1 ]]; then die "cannot list '$type' (required): $(head -c 300 "$tmp/err")"; fi
    warn "optional '$type' unavailable; recorded as unavailable"
    unavailable+=("$type"); echo '[]' >"$tmp/$key.json"; continue
  fi
  # keypairs are addressed by name, everything else by ID
  if [[ "$type" == keypair ]]; then ids="$(jq -r '.[].Name' <<<"$ids_json")"; else ids="$(jq -r '.[].ID' <<<"$ids_json")"; fi
  : >"$tmp/$key.ndjson"
  while IFS= read -r id; do
    [[ -n "$id" ]] || continue
    # shellcheck disable=SC2086
    if item="$(openstack $show "$id" -f json 2>/dev/null)"; then
      printf '%s\n' "$item" >>"$tmp/$key.ndjson"
    else
      warn "'$type' $id vanished between list and show; skipped"
    fi
  done <<<"$ids"
  # top-level keys lower-cased with underscores so jq can address them uniformly
  jq -s 'map(with_entries(.key |= (ascii_downcase | gsub("[ -]"; "_"))))' "$tmp/$key.ndjson" >"$tmp/$key.json"
  log "$type: $(jq length "$tmp/$key.json")"
done

args=()
for c in "${COLLECTORS[@]}"; do
  IFS='|' read -r type _ <<<"$c"; key="${type// /_}"
  args+=(--slurpfile "$key" "$tmp/$key.json")
done
unavail_json="$(printf '%s\n' "${unavailable[@]:-}" | jq -R . | jq -s 'map(select(length>0))')"
jq -n --arg label "$label" --arg cloud "$OS_CLOUD" --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --argjson unavailable "$unavail_json" "${args[@]}" '
  {schema: "ovlm.lab-snapshot/1", label: $label, cloud: $cloud, taken_at: $at, unavailable: $unavailable,
   resources: ($ARGS.named | del(.label, .cloud, .at, .unavailable) | map_values(.[0]))}' >"$out"
chmod 600 "$out"
log "snapshot written: $out"
