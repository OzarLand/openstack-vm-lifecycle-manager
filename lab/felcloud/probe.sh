#!/usr/bin/env bash
# probe.sh --url URL [--interval SECONDS] [--duration SECONDS] [--out FILE.csv]
#
# READ-ONLY (HTTP GET). The external downtime probe: asks URL every interval (default 1 s) for the whole duration
# (default: until Ctrl-C) and writes a CSV `utc_time,epoch_ms,http_code,latency_ms` (no URL, no body, no address).
# At the end prints the failure streaks and the longest outage. Run it from ozar-dev, through the floating IP,
# before the cutover starts, and stop it after the run ends. Compare with the downtime OVLM measured.
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() { print_usage "${BASH_SOURCE[0]}"; exit "${1:-0}"; }
parse_common "$@"
url=""; interval=1; duration=0; out=""
set -- "${REST[@]:-}"
while (($#)); do
  case "$1" in
    --url) url="${2:-}"; shift ;;
    --interval) interval="${2:-}"; shift ;;
    --duration) duration="${2:-}"; shift ;;
    --out) out="${2:-}"; shift ;;
    -h|--help) usage 0 ;;
    "") ;;
    *) usage 2 ;;
  esac
  shift
done
[[ "$url" =~ ^https?:// ]] || usage 2
[[ "$interval" =~ ^[0-9]+(\.[0-9]+)?$ && "$duration" =~ ^[0-9]+$ ]] || usage 2
mkdir_work; mkdir -p "$OVLM_LAB_WORKDIR/probes"
[[ -n "$out" ]] || out="$OVLM_LAB_WORKDIR/probes/probe-$(date -u +%Y%m%dT%H%M%SZ).csv"
if ((DRY_RUN)); then echo "+ every ${interval}s for ${duration}s (0 = until Ctrl-C): curl -s -o /dev/null -w '%{http_code}' --max-time 2 <url>  -> $out" >&9; exit 0; fi
need_cmd curl awk
echo "utc_time,epoch_ms,http_code,latency_ms" >"$out"
summary() {
  awk -F, 'NR>1 { ok = ($3 == 200); t = $2
      if (!ok && !down) { down = 1; start = t; n++ }
      if (ok && down) { d = t - start; total += d; if (d > max) max = d; down = 0 }
      last = t }
    END { if (down) { d = last - start; total += d; if (d > max) max = d; open = 1 }
          printf "probes=%d failure_streaks=%d longest_outage_s=%.1f total_outage_s=%.1f%s\n", NR-1, n, max/1000, total/1000, open ? " (still down at the end)" : "" }' "$out"
}
trap 'summary; log "csv: $out"; exit 0' INT TERM
start=$SECONDS
while :; do
  now_ms="$(date -u +%s%3N)"
  res="$(curl -s -o /dev/null -w '%{http_code} %{time_total}' --max-time 2 "$url" 2>/dev/null || true)"
  code="${res%% *}"; lat="$(awk -v t="${res##* }" 'BEGIN{printf "%d", t*1000}')"
  printf '%s,%s,%s,%s\n' "$(date -u +%H:%M:%S)" "$now_ms" "${code:-000}" "$lat" >>"$out"
  ((duration == 0 || SECONDS - start < duration)) || break
  sleep "$interval"
done
summary; log "csv: $out"
