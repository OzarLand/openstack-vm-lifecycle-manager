#!/usr/bin/env bash
# Shared helpers for the OVLM Felcloud lab kit. Source it; do not run it.
# Rules enforced here: every resource this kit creates or deletes is named ovlm-*; --dry-run prints
# the commands and runs nothing; secrets and addresses are never written to this repository.
# shellcheck shell=bash

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export LAB_DIR

# Optional operator-local settings (git-ignored). Real addresses and paths live only there or in the environment.
if [[ -f "${OVLM_LAB_ENV_FILE:-$LAB_DIR/lab.env}" ]]; then
  # shellcheck disable=SC1090
  source "${OVLM_LAB_ENV_FILE:-$LAB_DIR/lab.env}"
fi

: "${OS_CLOUD:=ozar-lab}"
export OS_CLOUD
: "${OVLM_LAB_WORKDIR:=$HOME/.ovlm-lab}"
: "${OVLM_LAB_TARGET_FLAVOR:=G0.basic.1c1g}"
: "${OVLM_LAB_IMAGE:=Ubuntu 24.04 LTS - Noble Numbat}"   # the exact Glance name; override in lab.env if yours differs
: "${OVLM_LAB_VOLUME_TYPE:=NVMe}"
: "${OVLM_LAB_DATA_SIZE_GB:=2}"
: "${OVLM_LAB_TAG:=ovlm-lab}"
# Egress proxy (optional). The project network may have no direct Internet: then the lab host (and blue, for apt)
# reach the world only through an operator-provided HTTPS-only proxy (CONNECT 443; plain HTTP refused).
#   OVLM_LAB_HTTPS_PROXY   http://host:port of that proxy (no credentials in the URL). Empty = direct Internet.
#   OVLM_LAB_NO_PROXY      extra no-proxy entries (comma separated): the project subnet CIDR and guest addresses.
#   OVLM_LAB_APT_MIRROR    https URL of the Ubuntu archive that apt uses on the VMs behind the proxy.
: "${OVLM_LAB_HTTPS_PROXY:=}"
: "${OVLM_LAB_NO_PROXY:=}"
: "${OVLM_LAB_APT_MIRROR:=https://archive.ubuntu.com/ubuntu}"
: "${OVLM_LAB_APT_SECURITY_MIRROR:=https://security.ubuntu.com/ubuntu}"
export OVLM_LAB_TARGET_FLAVOR   # read by redact() so the flavor name is not mistaken for a hostname

# Names. The prefix is the contract of ADR-0007; nothing else is ever created or deleted.
N_HOST="ovlm-lab-host"
N_KEY="ovlm-lab-key"            # operator public key, for the lab host
N_TARGET_KEY="ovlm-lab-target-key"  # key generated on the lab host, for the targets
N_SG_HOST="ovlm-lab-sg"
N_SG_TARGET="ovlm-acc-sg"          # blue
N_SG_GREEN="ovlm-acc-sg-green"     # what the renewal profile gives to green (separate so a fault can hit green only)
N_BLUE="ovlm-acc-blue"
N_DATA="ovlm-acc-data"
N_CRED_READ="ovlm-inventory"
N_CRED_WRITE="ovlm-renewal"
export N_HOST N_KEY N_TARGET_KEY N_SG_HOST N_SG_TARGET N_SG_GREEN N_BLUE N_DATA N_CRED_READ N_CRED_WRITE

DRY_RUN=0
ASSUME_YES=0

# print_usage FILE: the leading comment block of a script, without the shebang.
print_usage() { awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$1"; }

log()  { printf '[%s] %s\n' "$(date -u +%H:%M:%SZ)" "$*" >&2; }
warn() { printf '[%s] WARNING: %s\n' "$(date -u +%H:%M:%SZ)" "$*" >&2; }
die()  { printf '[%s] ERROR: %s\n' "$(date -u +%H:%M:%SZ)" "$*" >&2; exit 1; }

need_cmd() { local c; for c in "$@"; do command -v "$c" >/dev/null 2>&1 || die "missing command: $c"; done; }
# Tools every script needs on the operator machine, checked in --dry-run too so the operator learns before a real run.
need_jq() { need_cmd jq; }
need_var() { local v; for v in "$@"; do [[ -n "${!v:-}" ]] || die "missing setting: $v (see lab.env.example)"; done; }

# Parse the flags every script shares; leaves the rest in the array REST.
parse_common() {
  REST=()
  while (($#)); do
    case "$1" in
      --dry-run) DRY_RUN=1 ;;
      --yes) ASSUME_YES=1 ;;
      *) REST+=("$1") ;;
    esac
    shift
  done
}

# ovlm_name_ok NAME: the only names this kit accepts.
ovlm_name_ok() { [[ "$1" =~ ^ovlm-[a-z0-9][a-z0-9-]*$ ]]; }
assert_ovlm() { ovlm_name_ok "$1" || die "refusing: '$1' is not an ovlm-* name (ADR-0007)"; }

# Proxy settings go into cloud-init user-data and shell scripts: accept only plain values, never credentials.
# Sets NO_PROXY_FULL (loopback + the operator's entries) for use by the VMs.
validate_proxy_settings() {
  NO_PROXY_FULL="localhost,127.0.0.1,::1${OVLM_LAB_NO_PROXY:+,$OVLM_LAB_NO_PROXY}"
  export NO_PROXY_FULL
  [[ -z "$OVLM_LAB_HTTPS_PROXY" ]] && return 0
  [[ "$OVLM_LAB_HTTPS_PROXY" =~ ^https?://[A-Za-z0-9._-]+(:[0-9]{1,5})?/?$ ]] \
    || die "OVLM_LAB_HTTPS_PROXY must look like http://host:port, with no user name or password in it"
  [[ "$OVLM_LAB_NO_PROXY" =~ ^[A-Za-z0-9._:/,-]*$ ]] || die "OVLM_LAB_NO_PROXY may hold only host names, addresses and CIDRs separated by commas"
  [[ "$OVLM_LAB_APT_MIRROR" =~ ^https://[A-Za-z0-9._/-]+$ && "$OVLM_LAB_APT_SECURITY_MIRROR" =~ ^https://[A-Za-z0-9._/-]+$ ]] \
    || die "OVLM_LAB_APT_MIRROR and OVLM_LAB_APT_SECURITY_MIRROR must be https:// URLs (the proxy refuses plain HTTP)"
}

umask 077
mkdir_work() { mkdir -p "$OVLM_LAB_WORKDIR"; chmod 700 "$OVLM_LAB_WORKDIR"; }

# Command runners. In --dry-run nothing runs, every command is printed on stdout.
#   os_ro  ...  read-only openstack call (prints its output; in dry-run prints the command, returns 1)
#   os_mut ...  state-changing openstack call (marked WRITE in the log)
#   sh_ro / sh_mut  same for non-openstack commands (ssh, git ...)
exec 9>&1  # dry-run output goes to the original stdout even when a caller redirects a command's output
_show() { { printf '+ '; printf '%q ' "$@"; printf '\n'; } >&9; }
os_ro()  { if ((DRY_RUN)); then _show openstack "$@"; return 1; fi; openstack "$@"; }
os_mut() {
  if ((DRY_RUN)); then _show openstack "$@"; return 0; fi
  log "⚠️  WRITE: openstack ${*:1:3} ..."
  openstack "$@"
}
sh_ro()  { if ((DRY_RUN)); then _show "$@"; return 1; fi; "$@"; }
sh_mut() { if ((DRY_RUN)); then _show "$@"; return 0; fi; log "⚠️  WRITE: $1 ..."; "$@"; }

# exists TYPE NAME: 0 if present. In dry-run reports "absent" so the whole plan is printed.
# shellcheck disable=SC2086  # TYPE may be several words ("security group")
exists() { os_ro $1 show "$2" -f value -c id >/dev/null 2>&1; }

# wait_until DESC TIMEOUT_SECONDS CMD...: poll every 5 s. Dry-run only prints.
wait_until() {
  local desc="$1" timeout="$2"; shift 2
  if ((DRY_RUN)); then printf '+ wait up to %ss until: %s\n' "$timeout" "$desc" >&9; return 0; fi
  local start=$SECONDS
  until "$@" >/dev/null 2>&1; do
    ((SECONDS - start < timeout)) || die "timeout after ${timeout}s waiting for: $desc"
    sleep 5
  done
  log "ok: $desc ($((SECONDS - start))s)"
}

# Typed confirmation for destructive steps. --yes alone is not enough.
confirm_typed() {
  local expect="$1"
  ((DRY_RUN)) && { printf '+ (would require typing: %s)\n' "$expect" >&9; return 0; }
  ((ASSUME_YES)) || die "destructive step: re-run with --yes and type the confirmation"
  local got; read -r -p "Type exactly '$expect' to continue: " got
  [[ "$got" == "$expect" ]] || die "confirmation mismatch; nothing was changed"
}

# Redaction used by collect-evidence.sh: no IPs, hostnames or secrets leave the lab.
redact() {
  perl -0777 -pe '
    my @store;
    my $protect = sub { my ($v) = @_; push @store, $v; return "\x01" . $#store . "\x01"; };
    if (length $ENV{OVLM_LAB_TARGET_FLAVOR}) { s/\Q$ENV{OVLM_LAB_TARGET_FLAVOR}\E/$protect->($&)/ge; }
    s/\b(?:ovlm|sqlalchemy|uvicorn|asyncio|alembic|ansible|openstack|psycopg|starlette|fastapi)(?:\.[A-Za-z_][A-Za-z0-9_-]*)+/$protect->($&)/ge;
    s/-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----/<private-key>/gs;
    s/\bssh-(?:ed25519|rsa|dss)\s+[A-Za-z0-9+\/=]{20,}(?:\s+\S+)?/<ssh-public-key>/g;
    s/\becdsa-sha2-\S+\s+[A-Za-z0-9+\/=]{20,}(?:\s+\S+)?/<ssh-public-key>/g;
    s/\bSHA256:[A-Za-z0-9+\/=]{20,}/<fingerprint>/g;
    s/\bgAAAA[A-Za-z0-9_\-=]{20,}/<token>/g;
    s/\b(?:Bearer|Basic)\s+[A-Za-z0-9._\-+\/=]{8,}/$1 <token>/gi;
    s/("[^"\n]*(?:password|passwd|secret|token|passphrase|private_?key|user_?data|credential_?secret)[^"\n]*"\s*:\s*)"(?:[^"\\]|\\.)*"/$1"<redacted>"/gi;
    s/\b((?:password|passwd|secret|token|passphrase)\s*[=:]\s*)\S+/$1<redacted>/gi;
    s/\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b/<mac>/gi;
    s/\b(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?\b/<ip>/g;
    s/(?<![0-9A-Za-z:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?:\/\d{1,3})?(?![0-9A-Za-z:])/<ip6>/gi;
    s/\bhttps?:\/\/[^\s"\x27<>]+/<url>/g;
    s/\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+(?!(?:json|jsonl|yml|yaml|md|log|csv|txt|sh|py|env|toml|service|lock|html|sql|tar|gz)\b)[A-Za-z]{2,}\b/<host>/g;
    s/\x01(\d+)\x01/$store[$1]/g;
  '
}

# Patterns that must never survive redaction (canary check). Reads stdin, prints nothing, returns 1 on a hit.
canary_clean() {
  perl -0777 -ne '
    exit 1 if /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
    exit 1 if /BEGIN [A-Z ]*PRIVATE KEY/;
    exit 1 if /\bgAAAA[A-Za-z0-9_\-=]{20,}/;
    exit 1 if /\bssh-(?:ed25519|rsa)\s+AAAA/;
    exit 0;'
}
