#!/usr/bin/env bash
# create-lab.sh STAGE [options] [--dry-run]
#
# Creates the OVLM lab on Felcloud, one idempotent stage at a time. Every resource is named ovlm-*; a stage
# that finds its resource already present reports it and changes nothing. --dry-run prints every command and
# runs none. Settings: lab.env (see lab.env.example) or the environment.
#
# STAGES (run in this order; `all` = preflight base host host-setup workload fip):
#   preflight        read-only: settings, flavor, image, network, volume type, quotas, the set-aside floating IP
#   base       ⚠️    keypair ovlm-lab-key, security groups ovlm-lab-sg, ovlm-acc-sg (blue) and ovlm-acc-sg-green (+ rules)
#   host       ⚠️    server ovlm-lab-host (Ubuntu 24.04, cloud-init installs Docker + Compose; with
#                    OVLM_LAB_HTTPS_PROXY set: apt over HTTPS and Docker daemon/builds through that proxy), waits until ready
#   host-setup ⚠️    on the host: clone OVLM at OVLM_LAB_REF (detached), make secrets, compose up, smoke test
#   workload   ⚠️    keypair ovlm-lab-target-key, volume ovlm-acc-data (explicit type), server ovlm-acc-blue, attach
#   configure  ⚠️    on the host: FIRST-TIME FORMAT + mount of the data volume (needs --confirm FORMAT-<volume id>,
#                    printed by `configure` without it), THEN Ansible configure, start_service, marker. The order
#                    matters: configure makes an unmounted /srv/data immutable. Safe to repeat: a mounted volume is
#                    not formatted again; a half-done first attempt is detected and the reset is printed
#   fip        ⚠️    associate the set-aside floating IP (OVLM_LAB_FIP) with ovlm-acc-blue; refuses if it is in use
#   credentials ⚠️   application credentials ovlm-inventory (reader) and ovlm-renewal (member); secrets go to
#                    $OVLM_LAB_WORKDIR/credentials/ (0600), never to the terminal
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() { print_usage "${BASH_SOURCE[0]}"; exit "${1:-0}"; }
parse_common "$@"
set -- "${REST[@]:-}"
stage="${1:-}"; [[ -n "$stage" && "$stage" != -* ]] || usage 2
shift || true
confirm_format=""
while (($#)); do
  case "$1" in
    --confirm) [[ $# -ge 2 ]] || usage 2; confirm_format="$2"; shift ;;
    -h|--help) usage 0 ;;
    "") ;;
    *) usage 2 ;;
  esac
  shift
done

# nova microversion: tags at create need >= 2.52, delete_on_termination handling >= 2.85 (EXP-01: max 2.100)
export OS_COMPUTE_API_VERSION="${OS_COMPUTE_API_VERSION:-2.85}"
case "$stage" in preflight|base|host|host-setup|workload|configure|fip|credentials|all) ;; *) usage 2 ;; esac
need_jq   # jq is needed on the operator machine in every mode, dry-run included
((DRY_RUN)) || need_cmd openstack ssh
validate_proxy_settings
mkdir_work
SSH_KNOWN="$OVLM_LAB_WORKDIR/known_hosts"

# ---------------------------------------------------------------- helpers
server_ip() {  # fixed IPv4 of a server (the lab network is shared with ozar-dev, Q8)
  os_ro server show "$1" -f json | jq -r '
    .addresses | if type == "object" then (to_entries[0].value | if type == "array" then .[0] else . end)
                 else (capture("=(?<ip>[0-9.]+)").ip) end'
}
lab_ssh() {  # lab_ssh HOST_IP COMMAND...   (trust on first use: a VM we just created, on a private network)
  local ip="$1"; shift
  local opts=(-o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$SSH_KNOWN")
  [[ -z "${OVLM_LAB_SSH_KEY_FILE:-}" ]] || opts+=(-i "$OVLM_LAB_SSH_KEY_FILE")
  # shellcheck disable=SC2029  # the remote command is meant to be built on the client side
  ssh "${opts[@]}" "ubuntu@$ip" "$@"
}
host_ip() { if ((DRY_RUN)); then echo "<lab-host-ip>"; else server_ip "$N_HOST"; fi; }
server_status() { openstack server show "$1" -f value -c status 2>/dev/null; }
volume_status() { openstack volume show "$1" -f value -c status 2>/dev/null; }
is_server_status() { [[ "$(server_status "$1")" == "$2" ]]; }
is_volume_status() { [[ "$(volume_status "$1")" == "$2" ]]; }
volume_settled() { local s; s="$(volume_status "$1")"; [[ "$s" == available || "$s" == in-use ]]; }

# sg_rules GROUP: the rules as JSON. CLI >= 5.8 deprecates --long (the columns are always there); older CLIs need it.
sg_rules() {
  local out
  out="$(openstack security group rule list "$1" -f json 2>/dev/null)" || out=""
  if [[ -z "$out" ]] || ! jq -e 'all(.[]; has("Direction") and has("Port Range"))' <<<"$out" >/dev/null 2>&1; then
    out="$(openstack security group rule list "$1" --long -f json 2>/dev/null)" || die "cannot list the rules of security group $1"
  fi
  printf '%s' "$out"
}

ensure_rule() {  # ensure_rule GROUP tcp PORT cidr:<CIDR>|group:<NAME>
  local grp="$1" proto="$2" port="$3" remote="$4" kind="${4%%:*}" val="${4#*:}" have=0
  if ! ((DRY_RUN)); then
    local rules; rules="$(sg_rules "$grp")"
    if [[ "$kind" == cidr ]]; then
      jq -e --arg p "$proto" --arg r "$port:$port" --arg c "$val" \
        'any(.[]; .Direction=="ingress" and ."IP Protocol"==$p and ."Port Range"==$r and ."IP Range"==$c)' <<<"$rules" >/dev/null && have=1
    else
      gid="$(openstack security group show "$val" -f value -c id)"
      jq -e --arg p "$proto" --arg r "$port:$port" --arg g "$gid" \
        'any(.[]; .Direction=="ingress" and ."IP Protocol"==$p and ."Port Range"==$r and ."Remote Security Group"==$g)' <<<"$rules" >/dev/null && have=1
    fi
  fi
  if ((have)); then log "rule present: $grp $proto/$port from $remote"; return; fi
  if [[ "$kind" == cidr ]]; then os_mut security group rule create "$grp" --ingress --protocol "$proto" --dst-port "$port" --remote-ip "$val"
  else os_mut security group rule create "$grp" --ingress --protocol "$proto" --dst-port "$port" --remote-group "$val"; fi
}

# ---------------------------------------------------------------- stages
# check_image: the configured image must exist; if not, say which images look like it.
check_image() {
  if ((DRY_RUN)); then os_ro image show "$OVLM_LAB_IMAGE" -f value -c id -c status || true; return 0; fi
  openstack image show "$OVLM_LAB_IMAGE" -f value -c id >/dev/null 2>&1 && return 0
  local word hint
  word="${OVLM_LAB_IMAGE%% *}"
  hint="$(openstack image list -f json 2>/dev/null | jq -r --arg w "$word" \
    '[.[] | select((.Name // "") | ascii_downcase | contains($w | ascii_downcase)) | .Name] | unique | map("  - " + .) | join("\n")')" || hint=""
  warn "image '$OVLM_LAB_IMAGE' not found (or not unique)."
  if [[ -n "$hint" ]]; then printf 'Images whose name contains "%s":\n%s\n' "$word" "$hint" >&2
  else echo "No image name contains \"$word\"; list them with: openstack image list" >&2; fi
  die "set OVLM_LAB_IMAGE in lab.env to the exact image name"
}

stage_preflight() {
  log "preflight (read-only)"
  need_var OVLM_LAB_NETWORK OVLM_LAB_HOST_FLAVOR OVLM_LAB_ADMIN_CIDR OVLM_LAB_SSH_PUBKEY_FILE
  ((DRY_RUN)) || [[ -r "$OVLM_LAB_SSH_PUBKEY_FILE" ]] || die "cannot read OVLM_LAB_SSH_PUBKEY_FILE"
  ((DRY_RUN)) || grep -qE '^(ssh-|ecdsa-)' "$OVLM_LAB_SSH_PUBKEY_FILE" || die "OVLM_LAB_SSH_PUBKEY_FILE is not a public key"
  os_ro token issue -f value -c project_id >/dev/null || ((DRY_RUN)) || die "cannot authenticate with cloud '$OS_CLOUD'"
  local f info
  for f in "$OVLM_LAB_HOST_FLAVOR" "$OVLM_LAB_TARGET_FLAVOR"; do
    if ((DRY_RUN)); then os_ro flavor show "$f" -f json || true; continue; fi
    info="$(openstack flavor show "$f" -f json)" || die "flavor '$f' not found"
    log "flavor $f: $(jq -r '"vcpus=\(.vcpus) ram_MiB=\(.ram) disk_GB=\(.disk)"' <<<"$info")"
  done
  check_image
  if [[ -n "$OVLM_LAB_HTTPS_PROXY" ]]; then
    log "egress proxy configured: VMs use $OVLM_LAB_HTTPS_PROXY (HTTPS only; apt over $OVLM_LAB_APT_MIRROR); no-proxy: $NO_PROXY_FULL"
  else warn "OVLM_LAB_HTTPS_PROXY is empty: the VMs must reach the Internet directly (apt, Docker Hub, PyPI, GitHub)"; fi
  os_ro network show "$OVLM_LAB_NETWORK" -f value -c id >/dev/null || ((DRY_RUN)) || die "network '$OVLM_LAB_NETWORK' not found"
  os_ro volume type show "$OVLM_LAB_VOLUME_TYPE" -f value -c name >/dev/null || ((DRY_RUN)) || die "volume type '$OVLM_LAB_VOLUME_TYPE' not found (there is no working default type)"
  os_ro limits show --absolute || true
  if [[ -n "${OVLM_LAB_FIP:-}" ]]; then
    if ! ((DRY_RUN)); then
      local fip; fip="$(openstack floating ip list --floating-ip-address "$OVLM_LAB_FIP" -f json)"
      [[ "$(jq length <<<"$fip")" == 1 ]] || die "the set-aside floating IP is not in this project"
      [[ "$(jq -r '.[0].Port // ""' <<<"$fip")" == "" ]] || die "the set-aside floating IP is associated: it is not free (is it ozar-dev's?). Stop and ask the maintainer."
      log "set-aside floating IP exists and is unassociated"
    else os_ro floating ip list --floating-ip-address "$OVLM_LAB_FIP" -f json || true; fi
  else warn "OVLM_LAB_FIP not set: the fip stage and the diff allowance will not work"; fi
  log "preflight ok"
}

stage_base() {
  need_var OVLM_LAB_ADMIN_CIDR OVLM_LAB_SSH_PUBKEY_FILE
  [[ "$OVLM_LAB_ADMIN_CIDR" =~ ^[0-9a-fA-F:.]+/[0-9]+$ && "$OVLM_LAB_ADMIN_CIDR" != */0 ]] || die "OVLM_LAB_ADMIN_CIDR must be a CIDR and never /0 (the lab opens nothing to the world)"
  assert_ovlm "$N_KEY"; assert_ovlm "$N_SG_HOST"; assert_ovlm "$N_SG_TARGET"; assert_ovlm "$N_SG_GREEN"
  if exists keypair "$N_KEY"; then log "keypair $N_KEY present"; else os_mut keypair create --public-key "$OVLM_LAB_SSH_PUBKEY_FILE" "$N_KEY"; fi
  local g
  for g in "$N_SG_HOST" "$N_SG_TARGET" "$N_SG_GREEN"; do
    if exists "security group" "$g"; then log "security group $g present"; else os_mut security group create "$g" --description "OVLM lab (ADR-0007), safe to delete"; fi
  done
  ensure_rule "$N_SG_HOST" tcp 22 "cidr:$OVLM_LAB_ADMIN_CIDR"
  for g in "$N_SG_TARGET" "$N_SG_GREEN"; do
    ensure_rule "$g" tcp 22 "group:$N_SG_HOST"
    ensure_rule "$g" tcp 8080 "group:$N_SG_HOST"
    ensure_rule "$g" tcp 22 "cidr:$OVLM_LAB_ADMIN_CIDR"
    ensure_rule "$g" tcp 8080 "cidr:$OVLM_LAB_ADMIN_CIDR"
    # A probe through a floating IP on the same router arrives with the prober's own floating IP as its source
    if [[ -n "${OVLM_LAB_PROBE_CIDR:-}" ]]; then ensure_rule "$g" tcp 8080 "cidr:$OVLM_LAB_PROBE_CIDR"; fi
  done
}

# render_init_script ROLE: the first-boot script of a VM (ROLE host: Docker + Compose; target: apt only).
# It holds the proxy URL and nothing secret; the proxy must be reachable without credentials.
render_init_script() {
  local role="$1"
  cat <<INIT
#!/bin/bash
# OVLM lab first-boot script (${role}). Log: /var/log/ovlm-lab-init.log
set -euo pipefail
exec >>/var/log/ovlm-lab-init.log 2>&1
export DEBIAN_FRONTEND=noninteractive
PROXY='${OVLM_LAB_HTTPS_PROXY}'
NOPROXY='${NO_PROXY_FULL}'
MIRROR='${OVLM_LAB_APT_MIRROR%/}'
SECMIRROR='${OVLM_LAB_APT_SECURITY_MIRROR%/}'
ROLE='${role}'
INIT
  cat <<'INIT'
if [ -n "$PROXY" ]; then
  # apt over HTTPS only, through the proxy (it refuses plain HTTP)
  printf 'Acquire::https::Proxy "%s";\n' "$PROXY" > /etc/apt/apt.conf.d/90ovlm-proxy
  for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.sources /etc/apt/sources.list.d/*.list; do
    [ -f "$f" ] || continue
    sed -i -E "s#https?://security\.ubuntu\.com/ubuntu/?#$SECMIRROR/#g; s#https?://([A-Za-z0-9.-]+\.)?archive\.ubuntu\.com/ubuntu/?#$MIRROR/#g" "$f"
  done
  # login shells (git, pip, curl, ansible-galaxy) go through the proxy too
  printf 'HTTPS_PROXY=%s\nhttps_proxy=%s\nNO_PROXY=%s\nno_proxy=%s\n' "$PROXY" "$PROXY" "$NOPROXY" "$NOPROXY" >> /etc/environment
fi
if [ "$ROLE" = host ]; then
  apt-get update -y
  apt-get install -y ca-certificates docker.io docker-compose-v2 git make jq curl python3-venv
  apt-get install -y docker-buildx || true
  if [ -n "$PROXY" ]; then
    # Docker daemon (image pulls) through the proxy; HTTPS only. Builds get the proxy from compose.yaml build args.
    # No client-side "proxies.default": Docker would inject it into every container (the api too), and only the
    # worker may have the proxy (install-guide 5a).
    mkdir -p /etc/systemd/system/docker.service.d
    printf '[Service]\nEnvironment="HTTPS_PROXY=%s" "NO_PROXY=%s"\n' "$PROXY" "$NOPROXY" > /etc/systemd/system/docker.service.d/10-ovlm-proxy.conf
    systemctl daemon-reload
    systemctl restart docker
  fi
  systemctl enable --now docker
  usermod -aG docker ubuntu
  touch /var/lib/ovlm-lab-ready
fi
INIT
}

# write_user_data ROLE: prints the path of the cloud-config file, or nothing when the VM needs none
# (target without a proxy keeps the image defaults).
write_user_data() {
  local role="$1" f
  f="$OVLM_LAB_WORKDIR/lab-$role.user-data"
  if [[ "$role" == target && -z "$OVLM_LAB_HTTPS_PROXY" ]]; then return 0; fi
  if ((DRY_RUN)); then echo "$f"; return; fi
  local b64; b64="$(render_init_script "$role" | base64 -w0)"
  cat >"$f" <<CLOUD
#cloud-config
# OVLM lab VM ($role). No secrets in this file; the script is base64 to keep YAML quoting out of it.
write_files:
  - path: /usr/local/sbin/ovlm-lab-init
    permissions: '0700'
    encoding: b64
    content: $b64
runcmd:
  - [/usr/local/sbin/ovlm-lab-init]
CLOUD
  echo "$f"
}

stage_host() {
  need_var OVLM_LAB_NETWORK OVLM_LAB_HOST_FLAVOR
  assert_ovlm "$N_HOST"
  if exists server "$N_HOST"; then log "server $N_HOST present ($(server_status "$N_HOST"))"
  else
    local ud; ud="$(write_user_data host)"
    os_mut server create "$N_HOST" --flavor "$OVLM_LAB_HOST_FLAVOR" --image "$OVLM_LAB_IMAGE" --network "$OVLM_LAB_NETWORK" \
      --key-name "$N_KEY" --security-group "$N_SG_HOST" --user-data "$ud" --tag "$OVLM_LAB_TAG" --property ovlm=lab --wait
  fi
  wait_until "$N_HOST ACTIVE" 600 is_server_status "$N_HOST" ACTIVE
  # ACTIVE is not ready (EXP-01b): wait for SSH and for cloud-init to finish installing Docker
  if ((DRY_RUN)); then echo "+ wait up to 900s: ssh ubuntu@<lab-host-ip> test -f /var/lib/ovlm-lab-ready" >&9; else
    local ip; ip="$(host_ip)"
    wait_until "$N_HOST ready (cloud-init done)" 900 lab_ssh "$ip" test -f /var/lib/ovlm-lab-ready
    lab_ssh "$ip" 'docker --version && docker compose version'
  fi
}

# project_cidrs: ",<cidr>" for every subnet of the lab network: the worker must reach guests in them directly,
# never through the proxy.
project_cidrs() {
  ((DRY_RUN)) && { printf ',<project-subnet-cidr>'; return; }
  local c out=""
  while read -r c; do [[ "$c" =~ ^[0-9a-fA-F:.]+/[0-9]+$ ]] && out+=",$c"; done < <(openstack subnet list --network "$OVLM_LAB_NETWORK" -f value -c Subnet 2>/dev/null || true)
  [[ -n "$out" ]] || warn "could not read the subnet CIDRs of '$OVLM_LAB_NETWORK'; add them to OVLM_LAB_NO_PROXY"
  printf '%s' "$out"
}

stage_host_setup() {
  need_var OVLM_LAB_REPO_URL OVLM_LAB_REF
  [[ "$OVLM_LAB_REF" != -* && "$OVLM_LAB_REPO_URL" != -* ]] || die "ref and URL must not start with '-'"
  local ip; ip="$(host_ip)"
  log "OVLM at '$OVLM_LAB_REF' on the lab host (compose dev stack, API on the host's loopback only)"
  local noproxy="" proxy="$OVLM_LAB_HTTPS_PROXY"
  if [[ -n "$proxy" ]]; then noproxy="$NO_PROXY_FULL,postgres,api,worker$(project_cidrs)"; fi
  sh_mut lab_ssh "$ip" bash -s -- "$OVLM_LAB_REPO_URL" "$OVLM_LAB_REF" "$proxy" "$noproxy" <<'REMOTE'
set -euo pipefail
url="$1"; ref="$2"; proxy="${3:-}"; noproxy="${4:-}"
if [ -n "$proxy" ]; then
  # git, pip and the docker CLI go through the proxy; the worker gets it from .env (compose.yaml), minus the project
  # subnet and the guests, which it must reach directly (SSH, health probe)
  export HTTPS_PROXY="$proxy" https_proxy="$proxy" NO_PROXY="$noproxy" no_proxy="$noproxy"
fi
[ -d ovlm/.git ] || git clone --no-checkout -- "$url" ovlm
cd ovlm
git fetch --depth 100 origin -- "$ref"
git checkout --detach FETCH_HEAD
git rev-parse HEAD > ~/ovlm-commit.txt
[ -f ~/.ssh/ovlm_target ] || ssh-keygen -q -t ed25519 -N '' -C ovlm-lab-target -f ~/.ssh/ovlm_target
make secrets
if [ -n "$proxy" ]; then
  ( umask 077; printf 'HTTPS_PROXY=%s\nNO_PROXY=%s\n' "$proxy" "$noproxy" > .env )
else
  rm -f .env
fi
docker compose up -d --build --wait
curl -fsS http://127.0.0.1:8000/readyz; echo
echo "OVLM commit: $(cat ~/ovlm-commit.txt)"
REMOTE
  log "next: create the first admin on the host:  docker compose exec api ovlm admin create --username <name> --enrol-link"
  log "      and reach the API with:              ssh -L 8000:127.0.0.1:8000 ubuntu@<lab-host-ip>"
}

stage_workload() {
  need_var OVLM_LAB_NETWORK
  assert_ovlm "$N_TARGET_KEY"; assert_ovlm "$N_DATA"; assert_ovlm "$N_BLUE"
  local ip; ip="$(host_ip)"
  if exists keypair "$N_TARGET_KEY"; then log "keypair $N_TARGET_KEY present"; else
    local pub="$OVLM_LAB_WORKDIR/target.pub"
    if ((DRY_RUN)); then echo "+ ssh ubuntu@<lab-host-ip> cat ~/.ssh/ovlm_target.pub > $pub" >&9; else lab_ssh "$ip" cat .ssh/ovlm_target.pub >"$pub"; fi
    os_mut keypair create --public-key "$pub" "$N_TARGET_KEY"
  fi
  if exists volume "$N_DATA"; then log "volume $N_DATA present ($(volume_status "$N_DATA"))"; else
    os_mut volume create --size "$OVLM_LAB_DATA_SIZE_GB" --type "$OVLM_LAB_VOLUME_TYPE" --property ovlm=lab "$N_DATA"
  fi
  wait_until "$N_DATA settled (available or in-use)" 300 volume_settled "$N_DATA"
  if exists server "$N_BLUE"; then log "server $N_BLUE present ($(server_status "$N_BLUE"))"; else
    local ud args=(); ud="$(write_user_data target)"; [[ -z "$ud" ]] || args=(--user-data "$ud")
    os_mut server create "$N_BLUE" --flavor "$OVLM_LAB_TARGET_FLAVOR" --image "$OVLM_LAB_IMAGE" --network "$OVLM_LAB_NETWORK" \
      --key-name "$N_TARGET_KEY" --security-group "$N_SG_TARGET" --tag "$OVLM_LAB_TAG" --property ovlm=lab "${args[@]}" --wait
  fi
  wait_until "$N_BLUE ACTIVE" 600 is_server_status "$N_BLUE" ACTIVE
  if ! ((DRY_RUN)) && [[ "$(volume_status "$N_DATA")" == in-use ]]; then log "volume $N_DATA already attached"; else
    os_mut server add volume "$N_BLUE" "$N_DATA"
    wait_until "$N_DATA in-use" 120 is_volume_status "$N_DATA" in-use
  fi
  if ((DRY_RUN)); then echo "+ wait up to 600s: ssh (host) ubuntu@<blue-ip> true   # ACTIVE is not ready" >&9; else
    local bip; bip="$(server_ip "$N_BLUE")"
    # a recreated blue may get a fixed IP seen before: forget the old host key (this file holds blue's keys only)
    lab_ssh "$ip" 'mkdir -p ~/lab-work && rm -f ~/lab-work/known_hosts_blue'
    wait_until "$N_BLUE reachable over SSH from the lab host" 600 lab_ssh "$ip" "ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=~/lab-work/known_hosts_blue -i ~/.ssh/ovlm_target ubuntu@$bip true"
  fi
}

stage_configure() {
  local ip bip vol; ip="$(host_ip)"
  if ((DRY_RUN)); then bip="<blue-ip>"; vol="<volume-id>"; confirm_format="FORMAT-$vol"
  else bip="$(server_ip "$N_BLUE")"; vol="$(openstack volume show "$N_DATA" -f value -c id)"; fi
  if [[ -z "$confirm_format" ]]; then
    log "data volume id: $vol"
    log "FIRST-TIME FORMAT is destructive and runs only with the typed confirmation. Re-run:"
    log "  create-lab.sh configure --confirm FORMAT-$vol"
    log "Nothing was changed."
    return 0
  fi
  [[ "$confirm_format" == "FORMAT-$vol" ]] || die "confirmation does not match FORMAT-$vol; nothing changed"
  local proxy="$OVLM_LAB_HTTPS_PROXY" noproxy=""
  [[ -z "$proxy" ]] || noproxy="$NO_PROXY_FULL$(project_cidrs)"
  # ansible-core 2.19.4 is the version OVLM pins; the host has Python 3.12 (ozar-dev has 3.10, too old for it)
  # ORDER: format + mount the volume FIRST. `configure` makes an unmounted /srv/data immutable (nothing may write to
  # the root disk), which would make the later mount fail. A mounted volume is never formatted again.
  sh_mut lab_ssh "$ip" bash -s -- "$bip" "$vol" "$proxy" "$noproxy" <<'REMOTE'
set -euo pipefail
bip="$1"; vol="$2"; proxy="${3:-}"; noproxy="${4:-}"
if [ -n "$proxy" ]; then export HTTPS_PROXY="$proxy" https_proxy="$proxy" NO_PROXY="$noproxy" no_proxy="$noproxy"; fi
cd ~/ovlm/ansible
[ -d ~/ansible-venv ] || python3 -m venv ~/ansible-venv
~/ansible-venv/bin/pip install --quiet 'ansible-core==2.19.4'
export PATH=~/ansible-venv/bin:$PATH
export ANSIBLE_ROLES_PATH="$HOME/ovlm/ansible/roles"
ansible-galaxy collection install -r requirements.yml
work=~/lab-work; known="$work/known_hosts_blue"; res="$work/results"
mkdir -p "$res"; chmod 700 "$work" "$res"   # a dedicated directory: the result role sets 0700 on its parent (never /tmp)
printf '[ovlm_target]\nblue ansible_host=%s ansible_user=ubuntu ansible_ssh_private_key_file=%s/.ssh/ovlm_target ansible_python_interpreter=/usr/bin/python3 ansible_ssh_common_args="-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=%s"\n' "$bip" "$HOME" "$known" > "$work/inventory.ini"
printf '{"ovlm":{"role":"old","data_volume":{"id":"%s","mount_point":"/srv/data","fs_type":"ext4","first_use":false},"vars":{"app_port":8080}}}' "$vol" > "$work/extravars.json"
inv="$work/inventory.ini"; ev="@$work/extravars.json"
# -n: never read stdin, or the first call swallows the rest of this heredoc script and the stage silently does nothing
sshb() { ssh -n -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$known" -i ~/.ssh/ovlm_target "ubuntu@$bip" "$@"; }

# where is blue? mounted = finished earlier; stale = the OLD order left an immutable, unmounted /srv/data; blank = new
if sshb mountpoint -q /srv/data; then state=mounted
elif sshb "sudo lsattr -d /srv/data 2>/dev/null | awk '{print \$1}' | grep -q i"; then state=stale
else state=blank; fi
echo "data volume state on blue: $state"
if [ "$state" = stale ]; then
  cat >&2 <<'MSG'
STOP: /srv/data on blue is immutable and not mounted (left by a run in the old order), and the volume probably
already has a filesystem, which the bootstrap refuses to touch. Nothing was changed now. Reset, then repeat:
  ./destroy-lab.sh --keep-host --keep-credentials        # types DESTROY-OVLM-LAB; also deletes ovlm-acc-data
  ./create-lab.sh base && ./create-lab.sh workload       # new blue and a new, blank volume
  ./create-lab.sh configure --confirm FORMAT-<the NEW volume id printed by `configure`>
MSG
  exit 3
fi
if [ "$state" = blank ]; then
  ansible-playbook -i "$inv" lab/bootstrap_data.yml -e "bootstrap_volume_id=$vol" -e "bootstrap_confirm=FORMAT-$vol"
else
  echo "volume already mounted: not formatting again"
fi
ansible-playbook -i "$inv" playbooks/configure.yml -e "$ev" -e "ovlm_result_path=$res/configure.json"
ansible-playbook -i "$inv" playbooks/start_service.yml -e "$ev" -e "ovlm_result_path=$res/start.json"
ansible-playbook -i "$inv" playbooks/healthcheck.yml -e "$ev" -e "ovlm_result_path=$res/health.json"
# the marker is written once: a repeat of this stage must not replace the value recorded for the survival test
has_marker="$(sshb "curl -fsS http://127.0.0.1:8080/health | python3 -c 'import json,sys; print(\"yes\" if json.load(sys.stdin).get(\"marker_sha256\") else \"no\")'")"
if [ "$has_marker" = no ]; then
  sshb 'for i in 1 2 3 4 5; do curl -fsS http://127.0.0.1:8080/ >/dev/null; done; curl -fsS -X POST http://127.0.0.1:8080/marker; echo'
else
  echo "marker already present: left unchanged"
fi
sshb 'curl -fsS http://127.0.0.1:8080/health; echo'
REMOTE
  log "record the marker SHA-256 and fs_uuid printed above (not in this repository)"
}

stage_fip() {
  need_var OVLM_LAB_FIP
  assert_ovlm "$N_BLUE"
  if ! ((DRY_RUN)); then
    local fip; fip="$(openstack floating ip list --floating-ip-address "$OVLM_LAB_FIP" -f json)"
    [[ "$(jq length <<<"$fip")" == 1 ]] || die "the set-aside floating IP is not in this project"
    local port; port="$(jq -r '.[0].Port // ""' <<<"$fip")"
    if [[ -n "$port" ]]; then
      local owner; owner="$(openstack port show "$port" -f value -c device_id)"
      if [[ "$(openstack server show "$owner" -f value -c name 2>/dev/null)" == "$N_BLUE" ]]; then log "floating IP already on $N_BLUE"; return; fi
      die "the set-aside floating IP is associated with something that is not $N_BLUE; refusing (never touch other resources)"
    fi
  fi
  os_mut server add floating ip "$N_BLUE" "$OVLM_LAB_FIP"
  log "from ozar-dev, probe it:  probe.sh --url http://\$OVLM_LAB_FIP:8080/health --duration 5"
}

stage_credentials() {
  assert_ovlm "$N_CRED_READ"; assert_ovlm "$N_CRED_WRITE"
  local cdir="$OVLM_LAB_WORKDIR/credentials"; mkdir -p "$cdir"; chmod 700 "$cdir"
  local spec n role expires="${OVLM_LAB_CRED_EXPIRES:-$(date -u -d '+14 days' +%Y-%m-%dT%H:%M:%S)}"
  for spec in "$N_CRED_READ:reader" "$N_CRED_WRITE:member"; do
    n="${spec%%:*}"; role="${spec##*:}"
    if exists "application credential" "$n"; then log "application credential $n present (secret cannot be read again; delete and recreate to rotate)"; continue; fi
    if ((DRY_RUN)); then echo "+ openstack application credential create --role $role --expiration $expires --description 'OVLM lab' -f json $n   # secret -> $cdir/$n.json (0600)" >&9; continue; fi
    log "⚠️  WRITE: application credential create $n (role $role); secret goes to $cdir/$n.json"
    if ! openstack application credential create --role "$role" --expiration "$expires" --description "OVLM lab (ADR-0007)" -f json "$n" >"$cdir/$n.json.tmp" 2>"$cdir/err.tmp"; then
      rm -f "$cdir/$n.json.tmp"
      warn "cloud refused ($(head -c 200 "$cdir/err.tmp")). The maintainer must create '$n' (role $role, this project only) and upload it in OVLM. See README 'Credentials'."
      rm -f "$cdir/err.tmp"; continue
    fi
    mv "$cdir/$n.json.tmp" "$cdir/$n.json"; rm -f "$cdir/err.tmp"; chmod 600 "$cdir/$n.json"
  done
  log "upload each secret with PUT /api/v1/projects/<id>/credentials/{read|write} (admin, TOTP), then delete the files"
}

case "$stage" in
  preflight) stage_preflight ;;
  base) stage_base ;;
  host) stage_host ;;
  host-setup) stage_host_setup ;;
  workload) stage_workload ;;
  configure) stage_configure ;;
  fip) stage_fip ;;
  credentials) stage_credentials ;;
  all) stage_preflight; stage_base; stage_host; stage_host_setup; stage_workload; stage_fip ;;
  *) usage 2 ;;
esac
log "stage '$stage' done"
