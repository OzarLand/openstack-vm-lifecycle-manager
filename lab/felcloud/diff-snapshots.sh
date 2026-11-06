#!/usr/bin/env bash
# diff-snapshots.sh BEFORE AFTER [--allow-fip ADDRESS]... [--ignore-field NAME]...
#
# READ-ONLY, local (no cloud call). Compares two snapshots taken by snapshot.sh and proves that no resource
# outside the lab's own set changed: this is the ADR-0007 guard.
#   own = name starts with "ovlm-"; ports of ovlm-* servers; snapshots/backups of ovlm-* volumes;
#         the set-aside floating IP $OVLM_LAB_FIP (always) and any --allow-fip address, whose association and
#         OVLM ownership tag (ovlm:managed) are expected to change.
# Everything else that was added, removed or changed is a VIOLATION: exit 1, and the lab run is not valid.
# --ignore-field NAME drops a noisy field (for example a server's power state while another team works in the
#   project); every ignored field is printed, so a reviewer can see what was excused.
# Output never prints field values (they can hold addresses), only type, id, name and the changed field names.
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() { print_usage "${BASH_SOURCE[0]}"; exit "${1:-0}"; }
allow=(); ignore=(); files=()
while (($#)); do
  case "$1" in
    --allow-fip) [[ $# -ge 2 ]] || usage 2; allow+=("$2"); shift ;;
    --ignore-field) [[ $# -ge 2 ]] || usage 2; ignore+=("$2"); shift ;;
    --dry-run) echo "+ (read-only local comparison; nothing to preview)"; exit 0 ;;
    -h|--help) usage 0 ;;
    -*) usage 2 ;;
    *) files+=("$1") ;;
  esac
  shift
done
[[ ${#files[@]} -eq 2 ]] || usage 2
need_cmd jq
resolve() { if [[ -f "$1" ]]; then echo "$1"; else echo "$OVLM_LAB_WORKDIR/snapshots/$1.json"; fi; }
before="$(resolve "${files[0]}")"; after="$(resolve "${files[1]}")"
[[ -f "$before" && -f "$after" ]] || die "snapshot file not found"
for f in "$before" "$after"; do
  [[ "$(jq -r .schema "$f")" == "ovlm.lab-snapshot/1" ]] || die "$f is not an ovlm.lab-snapshot/1 file"
done
[[ "$(jq -r .cloud "$before")" == "$(jq -r .cloud "$after")" ]] || die "snapshots come from different clouds"
# The set-aside service floating IP is always part of the lab's own set (OVLM moves it and tags it ovlm:managed at
# B2); extra --allow-fip addresses are added to it, never replace it (lab bug P: passing --allow-fip for other
# addresses used to drop it and report OVLM's own ownership tag as a violation).
if [[ -n "${OVLM_LAB_FIP:-}" ]]; then allow+=("$OVLM_LAB_FIP"); fi

allow_json="$(printf '%s\n' "${allow[@]:-}" | jq -R . | jq -s 'map(select(length>0))')"
ignore_json="$(printf '%s\n' "${ignore[@]:-}" | jq -R . | jq -s 'map(select(length>0))')"
report="$(dirname "$after")/diff-$(basename "$before" .json)-$(basename "$after" .json).json"

jq -n --slurpfile b "$before" --slurpfile a "$after" --argjson allow "$allow_json" --argjson ignore "$ignore_json" '
  def norm: with_entries(select(.key | IN("updated","updated_at","progress","revision_number","launched_at","terminated_at") | not))
            | del(.[$ignore[]]);
  def nm: (.name // "") | tostring;
  def own_name: nm | startswith("ovlm-");
  ($b[0].resources) as $B | ($a[0].resources) as $A
  | ([($B.server // [])[], ($A.server // [])[]] | map(select(own_name) | .id) | unique) as $os
  | ([($B.volume // [])[], ($A.volume // [])[]] | map(select(own_name) | .id) | unique) as $ov
  | def owned($t): own_name
      or ($t == "port" and ((.device_id // "") as $d | $os | index($d) != null))
      or ($t == "floating_ip" and ((.floating_ip_address // "") as $x | $allow | index($x) != null))
      or ($t | IN("volume_snapshot","volume_backup")) and ((.volume_id // "") as $v | $ov | index($v) != null);
    def idof($t): if $t == "keypair" then .name else .id end;
    ([($B | keys[]), ($A | keys[])] | unique) as $types
  | [ $types[] as $t
      | (($B[$t] // []) | map({key: (idof($t) | tostring), value: .}) | from_entries) as $bm
      | (($A[$t] // []) | map({key: (idof($t) | tostring), value: .}) | from_entries) as $am
      | ([$bm | keys[], ($am | keys[])] | unique[]) as $id
      | ($bm[$id]) as $x | ($am[$id]) as $y
      | if $x == null then {type: $t, id: $id, rec: $y, change: "added", fields: []}
        elif $y == null then {type: $t, id: $id, rec: $x, change: "removed", fields: []}
        else ($x | norm) as $nx | ($y | norm) as $ny
             | if $nx == $ny then empty
               else {type: $t, id: $id, rec: $y, change: "changed",
                     fields: ([($nx | keys[]), ($ny | keys[])] | unique | map(select($nx[.] != $ny[.])))} end
        end
      | . as $c | {type, id, name: ($c.rec | nm), change, fields, own: ($c.rec | owned($t))}
    ] as $all
  | {schema: "ovlm.lab-diff/1", before: $b[0].label, after: $a[0].label, cloud: $a[0].cloud,
     allowed_floating_ips: ($allow | length), ignored_fields: $ignore,
     unavailable_before: $b[0].unavailable, unavailable_after: $a[0].unavailable,
     own_changes: ($all | map(select(.own))),
     violations: ($all | map(select(.own | not)))}' >"$report"
chmod 600 "$report"

own_n="$(jq '.own_changes | length' "$report")"; viol_n="$(jq '.violations | length' "$report")"
log "before=$(jq -r .before "$report") after=$(jq -r .after "$report"): own (ovlm-*) changes: $own_n, violations: $viol_n"
if [[ "$(jq -r '.ignored_fields | length' "$report")" != 0 ]]; then
  warn "ignored fields (excused by the operator): $(jq -r '.ignored_fields | join(", ")' "$report")"
fi
if [[ "$(jq -r '(.unavailable_before + .unavailable_after) | unique | length' "$report")" != 0 ]]; then
  warn "resource types not covered by the snapshots: $(jq -r '(.unavailable_before + .unavailable_after) | unique | join(", ")' "$report")"
fi
if ((viol_n > 0)); then
  jq -r '.violations[] | "VIOLATION \(.change)\t\(.type)\t\(.id)\t\(.name)\t\(.fields | join(","))"' "$report" >&2
  die "non-ovlm resources changed; this lab run is NOT valid (report: $report). Stop and tell the maintainer."
fi
log "PASS: no resource outside ovlm-* changed (report: $report)"
