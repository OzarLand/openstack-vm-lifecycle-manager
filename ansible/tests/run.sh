#!/usr/bin/env bash
# CI glue for the ovlm-counter reference workload. No cloud needed.
#   tests/run.sh            everything: lint + syntax + decision table + local-container run
#   tests/run.sh lint       lint + syntax checks + static contract lints + decision-table test only
#   tests/run.sh container  only the local-container run
# Needs: ansible-core, ansible-lint, yamllint, python3 (>= 3.9), ssh, ssh-keygen; docker for the container run.
# The container is UNPRIVILEGED: no systemd, no real mount, no block device. The playbooks run with
# ovlm_test_mode=true (service started with start-stop-daemon; mount SIMULATED). data_attach is NOT
# executed against a device here; its decision table is tested with canned blkid output instead.
set -euo pipefail

MODE="${1:-all}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
WORK="${OVLM_CI_WORK:-$HERE/work}"
mkdir -p "$WORK/artifacts"

export ANSIBLE_CONFIG="$HERE/ansible.cfg"
export ANSIBLE_ROLES_PATH="$ROOT/roles"
export ANSIBLE_COLLECTIONS_PATH="${OVLM_CI_COLLECTIONS_PATH:-$WORK/collections}"
export ANSIBLE_LOCAL_TEMP="$WORK/tmp" ANSIBLE_REMOTE_TEMP="/tmp/.ansible-ci"
mkdir -p "$ANSIBLE_LOCAL_TEMP"

say() { printf '\n== %s\n' "$*"; }
die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

ensure_collections() {
  if ansible-galaxy collection list ansible.posix >/dev/null 2>&1 \
     && ansible-galaxy collection list ansible.posix 2>/dev/null | grep -q 'ansible.posix'; then return; fi
  say "install pinned collections from requirements.yml (CI build step; OVLM itself never does this at run time)"
  if ! ansible-galaxy collection install -r "$ROOT/requirements.yml" -p "$ANSIBLE_COLLECTIONS_PATH"; then
    # Fallback for networks that block galaxy.ansible.com: same pinned version, from the upstream git tag.
    ver="$(awk '/ansible.posix/{f=1} f&&/version:/{print $2; exit}' "$ROOT/requirements.yml")"
    say "galaxy unreachable; trying the git tag $ver"
    ansible-galaxy collection install "git+https://github.com/ansible-collections/ansible.posix.git,$ver" -p "$ANSIBLE_COLLECTIONS_PATH"
  fi
}

static_lints() {
  say "static contract lints"
  cd "$ROOT"
  # 1. every phase playbook targets ovlm_target and nothing else
  for f in playbooks/*.yml; do
    grep -Eq '^\s+hosts: ovlm_target\b' "$f" || die "$f: hosts must be ovlm_target"
    grep -Eq '^\s+hosts: (all|localhost)\b' "$f" && die "$f: forbidden hosts pattern"
  done
  # 2. data_attach never formats or wipes (contract 3.3 rule 6)
  if grep -RnE '\b(mkfs[.a-z0-9]*|wipefs|parted|mklabel|dd if=|sgdisk|sfdisk)\b|\bdd +' playbooks/data_attach.yml roles/data_volume; then
    die "data_attach contains a forbidden formatting/wiping string"
  fi
  # 3. formatting exists only in lab/bootstrap_data.yml, and renewal playbooks never reference it
  others="$(grep -RlE '\bmkfs' --include='*.yml' --include='*.py' --include='*.j2' . | grep -v -e '^./lab/bootstrap_data.yml$' -e '^./tests/' || true)"
  [ -z "$others" ] || die "mkfs outside lab/bootstrap_data.yml: $others"
  grep -Rn 'bootstrap_data' playbooks roles && die "renewal code references bootstrap_data" || true
  # 4. quiesce never edits fstab or disables units (contract 3.4)
  if grep -RnE "state: absent|enabled: false|state: (unmounted|absent).*fstab|lineinfile" roles/quiesce playbooks/quiesce.yml; then
    die "quiesce edits fstab or disables a unit"
  fi
  grep -Rq 'state: unmounted' roles/quiesce || die "quiesce must unmount with state: unmounted"
  # 5. no ignore_errors anywhere (contract section 10); failed_when: false on read-only probes is allowed
  grep -Rn 'ignore_errors' playbooks roles lab && die "ignore_errors is forbidden" || true
  # 6. blocking no_log lint stand-in: no secret-like module args in this repo at all
  if grep -RniE --include='*.yml' '(vault|password|token|secret|api_key)\b *[:=]' playbooks roles lab | grep -v 'vault_password: *ovlm-secret' ; then
    die "secret-like argument without no_log (this reference workload handles no secrets)"
  fi
  echo "static lints ok"
}

lint_and_syntax() {
  ensure_collections
  cd "$ROOT"
  say "yamllint"; yamllint -c .yamllint .
  say "ansible-lint (profile production)"; ansible-lint -c .ansible-lint
  say "ansible-playbook --syntax-check"
  for f in playbooks/*.yml lab/bootstrap_data.yml; do
    ansible-playbook --syntax-check -i "$HERE/syntax_inventory.ini" "$f" >/dev/null && echo "syntax ok: $f"
  done
  static_lints
  say "data_attach decision table (canned blkid output)"
  ansible-playbook -i "localhost," "$HERE/decision_table.yml" | tee "$WORK/decision.log" | tail -4
  grep -Eq 'failed=0' "$WORK/decision.log" || die "decision table test failed"
}

CID=""
cleanup() { [ -n "$CID" ] && docker rm -f "$CID" >/dev/null 2>&1 || true; }

container_run() {
  ensure_collections
  command -v docker >/dev/null || die "docker not found"
  trap cleanup EXIT
  say "build and start the unprivileged Ubuntu 24.04 SSH target"
  docker build -q -t ovlm-ci-target "$HERE" >/dev/null
  CID="$(docker run -d --rm -p 127.0.0.1::22 ovlm-ci-target)"
  PORT="$(docker port "$CID" 22/tcp | head -1 | sed 's/.*://')"
  KEY="$WORK/ci_key"; rm -f "$KEY" "$KEY.pub"; ssh-keygen -q -t ed25519 -N '' -f "$KEY"
  docker exec -i "$CID" sh -c 'cat > /home/ovlm/.ssh/authorized_keys && chown ovlm:ovlm /home/ovlm/.ssh/authorized_keys && chmod 600 /home/ovlm/.ssh/authorized_keys' < "$KEY.pub"
  SSHO=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -i "$KEY" -p "$PORT")
  for _ in $(seq 1 30); do ssh "${SSHO[@]}" ovlm@127.0.0.1 true 2>/dev/null && break; sleep 1; done
  ssh "${SSHO[@]}" ovlm@127.0.0.1 true || die "ssh to the target container did not come up"

  INV="$WORK/inventory.ini"
  cat > "$INV" <<INV2
[ovlm_target]
ci-target ansible_host=127.0.0.1 ansible_port=$PORT ansible_user=ovlm ansible_ssh_private_key_file=$KEY ovlm_role=new
INV2

  # ---- helpers ----
  extra() {  # extra OUTFILE [expected_marker]
    python3 -I - "$1" "${2:-}" "${3:-}" <<'PY'
import json, sys
out, expected_marker, fs_uuid = sys.argv[1], sys.argv[2], sys.argv[3]
ovlm = {"workflow_id": "ci", "step": "ci", "attempt": 1, "role": "new", "check_mode": False,
        "service_name": "ovlm-counter",
        "data_volume": {"id": "0f1e2d3c-4b5a-4697-8877-665544332211",
                        "expected_serial": "0f1e2d3c-4b5a-4697-8877-665544332211",
                        "mount_point": "/srv/data", "fs_type": "ext4", "first_use": False},
        "vars": {"app_port": 8080, "service_units": ["ovlm-counter.service"]}}
if expected_marker:
    ovlm["expected_marker_checksum"] = expected_marker
if fs_uuid:
    ovlm["expected_fs_uuid"] = fs_uuid
json.dump({"ovlm": ovlm, "ovlm_test_mode": True}, open(out, "w"))
PY
  }
  # phase NAME RESULT_NAME [extra-file] -> sets RC, RECAP_CHANGED; runs ansible-playbook, never aborts the script
  phase() {
    local name="$1" res="$WORK/artifacts/$2.json" ev="${3:-$WORK/extravars.json}"
    rm -f "$res"
    set +e
    ansible-playbook -i "$INV" "$ROOT/playbooks/$name.yml" -e "@$ev" -e "ovlm_result_path=$res" > "$WORK/artifacts/$2.log" 2>&1
    RC=$?
    set -e
    RECAP_CHANGED="$(grep -E '^ci-target +:' "$WORK/artifacts/$2.log" | sed -E 's/.*changed=([0-9]+).*/\1/')"
    echo "-- $name ($2): exit=$RC changed=${RECAP_CHANGED:-?}"
  }
  expect_rc() { [ "$RC" = "$1" ] || { tail -40 "$WORK/artifacts/last.log" 2>/dev/null; die "$2: expected exit $1, got $RC (see $WORK/artifacts)"; }; }
  guest_py() { ssh "${SSHO[@]}" ovlm@127.0.0.1 "python3 -c \"$1\""; }
  http() {  # http METHOD PATH -> body
    guest_py "import urllib.request as u,sys
r=u.Request('http://127.0.0.1:8080$2',method='$1',data=(b'' if '$1'=='POST' else None))
try: print(u.urlopen(r,timeout=10).read().decode())
except Exception as e: print(getattr(e,'read',lambda:b'')().decode() or e)"
  }
  jget() { python3 -I -c "import json,sys; print(json.loads(sys.stdin.read())['$1'])"; }

  extra "$WORK/extravars.json"

  say "preflight (read-only)"
  phase preflight preflight;       expect_rc 0 preflight;  python3 -I "$HERE/check_result.py" "$WORK/artifacts/preflight.json" preflight ok

  say "configure, twice: the second run must report changed=0"
  phase configure configure1;      expect_rc 0 configure;  python3 -I "$HERE/check_result.py" "$WORK/artifacts/configure1.json" configure ok
  [ "${RECAP_CHANGED:-x}" != "0" ] || die "first configure reported changed=0"
  phase configure configure2;      expect_rc 0 configure2; python3 -I "$HERE/check_result.py" "$WORK/artifacts/configure2.json" configure ok
  [ "$RECAP_CHANGED" = "0" ] || die "second configure not idempotent: changed=$RECAP_CHANGED"

  say "healthcheck before start must be unhealthy (exit 2, retryable)"
  phase healthcheck hc_before;     expect_rc 2 hc_before;  python3 -I "$HERE/check_result.py" "$WORK/artifacts/hc_before.json" healthcheck fail retryable

  say "start_service, twice (idempotent)"
  phase start_service start1;      expect_rc 0 start1;     python3 -I "$HERE/check_result.py" "$WORK/artifacts/start1.json" start_service ok
  phase start_service start2;      expect_rc 0 start2;     python3 -I "$HERE/check_result.py" "$WORK/artifacts/start2.json" start_service ok
  [ "$RECAP_CHANGED" = "0" ] || die "second start_service not idempotent: changed=$RECAP_CHANGED"

  say "healthcheck (read-only, repeated, check mode too)"
  phase healthcheck hc1;           expect_rc 0 hc1;        python3 -I "$HERE/check_result.py" "$WORK/artifacts/hc1.json" healthcheck ok
  [ "$RECAP_CHANGED" = "0" ] || die "healthcheck changed something"
  set +e; ansible-playbook --check --diff -i "$INV" "$ROOT/playbooks/healthcheck.yml" -e "@$WORK/extravars.json" -e "ovlm_result_path=$WORK/artifacts/hc_check.json" >/dev/null 2>&1; RC=$?; set -e
  expect_rc 0 "healthcheck --check"

  say "workload: increment 5 times and write the marker, record counter + marker"
  for _ in 1 2 3 4 5; do http GET / >/dev/null; done
  MARK_BODY="$(http POST /marker)"; MARKER="$(printf '%s' "$MARK_BODY" | jget marker_sha256)"
  HEALTH="$(http GET /health)"; COUNTER_BEFORE="$(printf '%s' "$HEALTH" | jget counter)"; GEN_BEFORE="$(printf '%s' "$HEALTH" | jget generation)"
  echo "marker=$MARKER counter=$COUNTER_BEFORE generation=$GEN_BEFORE"
  [ "$COUNTER_BEFORE" -ge 5 ] || die "counter did not increment"

  say "healthcheck with the expected marker checksum: ok; with a wrong one: unhealthy"
  extra "$WORK/extravars_marker.json" "$MARKER"
  phase healthcheck hc_marker "$WORK/extravars_marker.json"; expect_rc 0 hc_marker; python3 -I "$HERE/check_result.py" "$WORK/artifacts/hc_marker.json" healthcheck ok
  extra "$WORK/extravars_wrong.json" "$(printf '0%.0s' $(seq 1 64))"
  phase healthcheck hc_wrong "$WORK/extravars_wrong.json";  expect_rc 2 hc_wrong;  python3 -I "$HERE/check_result.py" "$WORK/artifacts/hc_wrong.json" healthcheck fail retryable

  say "quiesce, twice: reports the marker checksum, stops the service, idempotent"
  phase quiesce quiesce1;          expect_rc 0 quiesce1;   python3 -I "$HERE/check_result.py" "$WORK/artifacts/quiesce1.json" quiesce ok
  [ "$(jget_file() { python3 -I -c "import json;print(json.load(open('$1'))['facts']['marker_sha256'])"; }; jget_file "$WORK/artifacts/quiesce1.json")" = "$MARKER" ] || die "quiesce marker differs from the recorded one"
  phase quiesce quiesce2;          expect_rc 0 quiesce2;   python3 -I "$HERE/check_result.py" "$WORK/artifacts/quiesce2.json" quiesce ok
  [ "$RECAP_CHANGED" = "0" ] || die "second quiesce not idempotent: changed=$RECAP_CHANGED"
  ssh "${SSHO[@]}" ovlm@127.0.0.1 "grep -c . /etc/fstab >/dev/null; ! grep -q ovlm /etc/fstab" || die "quiesce touched fstab"

  say "healthcheck after quiesce must fail: the service is stopped"
  phase healthcheck hc_after;      expect_rc 2 hc_after;   python3 -I "$HERE/check_result.py" "$WORK/artifacts/hc_after.json" healthcheck fail retryable

  say "restart the service (as on a new VM): the data must have survived"
  phase start_service start3;      expect_rc 0 start3;     python3 -I "$HERE/check_result.py" "$WORK/artifacts/start3.json" start_service ok
  phase healthcheck hc_survive "$WORK/extravars_marker.json"; expect_rc 0 hc_survive; python3 -I "$HERE/check_result.py" "$WORK/artifacts/hc_survive.json" healthcheck ok
  HEALTH="$(http GET /health)"
  [ "$(printf '%s' "$HEALTH" | jget counter)" -ge "$COUNTER_BEFORE" ] || die "counter went backwards"
  [ "$(printf '%s' "$HEALTH" | jget generation)" -gt "$GEN_BEFORE" ] || die "generation did not grow on restart"
  [ "$(printf '%s' "$HEALTH" | jget marker_sha256)" = "$MARKER" ] || die "marker changed across restart"
  echo "container run ok"
}

case "$MODE" in
  lint) lint_and_syntax ;;
  container) container_run ;;
  all) lint_and_syntax; container_run ;;
  *) die "usage: run.sh [all|lint|container]" ;;
esac
say "PASS ($MODE)"
