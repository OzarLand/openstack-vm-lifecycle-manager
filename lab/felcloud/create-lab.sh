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
#   host       ⚠️    server ovlm-lab-host (Ubuntu 24.04, cloud-init installs Docker + Compose), waits until ready
#   host-setup ⚠️    on the host: clone OVLM at OVLM_LAB_REF (detached), make secrets, compose up, smoke test
#   workload   ⚠️    keypair ovlm-lab-target-key, volume ovlm-acc-data (explicit type), server ovlm-acc-blue, attach
#   configure  ⚠️    on the host: Ansible configure on blue, then FIRST-TIME FORMAT of the data volume (needs
#                    --confirm FORMAT-<volume id>, printed by `configure` without it), start_service, marker
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
((DRY_RUN)) || need_cmd openstack jq ssh
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

ensure_rule() {  # ensure_rule GROUP tcp PORT cidr:<CIDR>|group:<NAME>
  local grp="$1" proto="$2" port="$3" remote="$4" kind="${4%%:*}" val="${4#*:}" have=0
  if ! ((DRY_RUN)); then
    local rules; rules="$(openstack security group rule list "$grp" --long -f json)"
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
stage_preflight() {
  log "preflight (read-only)"
  need_var OVLM_LAB_NETWORK OVLM_LAB_HOST_FLAVOR OVLM_LAB_ADMIN_CIDR OVLM_LAB_SSH_PUBKEY_FILE
  ((DRY_RUN)) || [[ -r "$OVLM_LAB_SSH_PUBKEY_FILE" ]] || die "cannot read OVLM_LAB_SSH_PUBKEY_FILE"
  ((DRY_RUN)) || grep -qE '^(ssh-|ecdsa-)' "$OVLM_LAB_SSH_PUBKEY_FILE" || die "OVLM_LAB_SSH_PUBKEY_FILE is not a public key"
  os_ro token issue -f value -c project_id >/dev/null || ((DRY_RUN)) || die "cannot authenticate with cloud '$OS_CLOUD'"
  local f
  for f in "$OVLM_LAB_HOST_FLAVOR" "$OVLM_LAB_TARGET_FLAVOR"; do
    if ! ((DRY_RUN)); then log "flavor $f: $(openstack flavor show "$f" -f value -c vcpus -c ram -c disk | tr '\n' ' ')(vcpus ram_MiB disk_GB)" || die "flavor '$f' not found"; else os_ro flavor show "$f" -f value -c vcpus -c ram -c disk; fi
  done
  os_ro image show "$OVLM_LAB_IMAGE" -f value -c id -c status >/dev/null || ((DRY_RUN)) || die "image '$OVLM_LAB_IMAGE' not found"
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
  done
}

write_user_data() {
  local f="$OVLM_LAB_WORKDIR/lab-host.user-data"
  if ((DRY_RUN)); then echo "$f"; return; fi
  cat >"$f" <<'CLOUD'
#cloud-config
# OVLM lab host: Docker + Compose from the Ubuntu archive. No secrets in this file.
runcmd:
  - [bash, -c, "set -e; export DEBIAN_FRONTEND=noninteractive; apt-get update -y; apt-get install -y docker.io docker-compose-v2 git make jq curl python3-venv; apt-get install -y docker-buildx || true; systemctl enable --now docker; usermod -aG docker ubuntu; touch /var/lib/ovlm-lab-ready"]
CLOUD
  echo "$f"
}

stage_host() {
  need_var OVLM_LAB_NETWORK OVLM_LAB_HOST_FLAVOR
  assert_ovlm "$N_HOST"
  if exists server "$N_HOST"; then log "server $N_HOST present ($(server_status "$N_HOST"))"
  else
    local ud; ud="$(write_user_data)"
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

stage_host_setup() {
  need_var OVLM_LAB_REPO_URL OVLM_LAB_REF
  [[ "$OVLM_LAB_REF" != -* && "$OVLM_LAB_REPO_URL" != -* ]] || die "ref and URL must not start with '-'"
  local ip; ip="$(host_ip)"
  log "OVLM at '$OVLM_LAB_REF' on the lab host (compose dev stack, API on the host's loopback only)"
  sh_mut lab_ssh "$ip" bash -s -- "$OVLM_LAB_REPO_URL" "$OVLM_LAB_REF" <<'REMOTE'
set -euo pipefail
url="$1"; ref="$2"
[ -d ovlm/.git ] || git clone --no-checkout -- "$url" ovlm
cd ovlm
git fetch --depth 100 origin -- "$ref"
git checkout --detach FETCH_HEAD
git rev-parse HEAD > ~/ovlm-commit.txt
[ -f ~/.ssh/ovlm_target ] || ssh-keygen -q -t ed25519 -N '' -C ovlm-lab-target -f ~/.ssh/ovlm_target
make secrets
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
    os_mut server create "$N_BLUE" --flavor "$OVLM_LAB_TARGET_FLAVOR" --image "$OVLM_LAB_IMAGE" --network "$OVLM_LAB_NETWORK" \
      --key-name "$N_TARGET_KEY" --security-group "$N_SG_TARGET" --tag "$OVLM_LAB_TAG" --property ovlm=lab --wait
  fi
  wait_until "$N_BLUE ACTIVE" 600 is_server_status "$N_BLUE" ACTIVE
  if ! ((DRY_RUN)) && [[ "$(volume_status "$N_DATA")" == in-use ]]; then log "volume $N_DATA already attached"; else
    os_mut server add volume "$N_BLUE" "$N_DATA"
    wait_until "$N_DATA in-use" 120 is_volume_status "$N_DATA" in-use
  fi
  if ((DRY_RUN)); then echo "+ wait up to 600s: ssh (host) ubuntu@<blue-ip> true   # ACTIVE is not ready" >&9; else
    local bip; bip="$(server_ip "$N_BLUE")"
    wait_until "$N_BLUE reachable over SSH from the lab host" 600 lab_ssh "$ip" "ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new -i ~/.ssh/ovlm_target ubuntu@$bip true"
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
  # ansible-core 2.19.4 is the version OVLM pins; the host has Python 3.12 (ozar-dev has 3.10, too old for it)
  sh_mut lab_ssh "$ip" bash -s -- "$bip" "$vol" <<'REMOTE'
set -euo pipefail
bip="$1"; vol="$2"
cd ~/ovlm/ansible
[ -d ~/ansible-venv ] || python3 -m venv ~/ansible-venv
~/ansible-venv/bin/pip install --quiet 'ansible-core==2.19.4'
export PATH=~/ansible-venv/bin:$PATH
ansible-galaxy collection install -r requirements.yml
mkdir -p ~/lab-work
printf '[ovlm_target]\nblue ansible_host=%s ansible_user=ubuntu ansible_ssh_private_key_file=%s/.ssh/ovlm_target ansible_ssh_common_args="-o StrictHostKeyChecking=accept-new"\n' "$bip" "$HOME" > ~/lab-work/inventory.ini
printf '{"ovlm":{"role":"old","data_volume":{"id":"%s","mount_point":"/srv/data","fs_type":"ext4","first_use":false},"vars":{"app_port":8080}}}' "$vol" > ~/lab-work/extravars.json
inv=~/lab-work/inventory.ini; ev=@$HOME/lab-work/extravars.json
ansible-playbook -i "$inv" playbooks/configure.yml -e "$ev" -e ovlm_result_path=/tmp/ovlm-configure.json
ansible-playbook -i "$inv" lab/bootstrap_data.yml -e "bootstrap_volume_id=$vol" -e "bootstrap_confirm=FORMAT-$vol"
ansible-playbook -i "$inv" playbooks/start_service.yml -e "$ev" -e ovlm_result_path=/tmp/ovlm-start.json
ansible-playbook -i "$inv" playbooks/healthcheck.yml -e "$ev" -e ovlm_result_path=/tmp/ovlm-health.json
ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -i ~/.ssh/ovlm_target "ubuntu@$bip" \
  'for i in 1 2 3 4 5; do curl -fsS http://127.0.0.1:8080/ >/dev/null; done; curl -fsS -X POST http://127.0.0.1:8080/marker; echo; curl -fsS http://127.0.0.1:8080/health; echo'
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
