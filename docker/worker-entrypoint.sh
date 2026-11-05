#!/bin/sh
# Worker launcher (automation-contract.md section 11, "Separate OS user").
#
# The worker must run ansible-runner as `ovlm-ansible` (uid 10002) while staying an unprivileged process itself.
# Started as container root with a minimal capability set (compose: cap_drop ALL, cap_add SETUID SETGID SETPCAP
# KILL), this script drops to uid/gid ovlm (10001) with supplementary group ovlm-ansible (10002, the run directory
# is shared through it) and keeps ONLY CAP_SETUID, CAP_SETGID and CAP_KILL as ambient capabilities: setuid to start
# the child as ovlm-ansible, kill to stop its process tree. No setuid binary, no sudo, no root process remains.
# Started as `ovlm` (no capabilities) it just runs; the runner then cannot switch user and refuses to run.
# `-- COMMAND...` runs COMMAND in the same dropped context instead of `ovlm` (used by `make smoke`).
set -eu
if [ "${1:-}" = "--" ]; then
    shift
else
    set -- ovlm "$@"
fi
if [ "$(id -u)" = 0 ]; then
    # Credential store KEK (security-model.md 5.1): the Docker secret is a 0400 file owned by the host user, so
    # neither ovlm nor ovlm-ansible can read it. Root reads it once (CAP_DAC_READ_SEARCH, dropped below) and a
    # process running as ovlm writes the copy into the 0700 tmpfs /run/ovlm-kek (mode 0600). Never an env value.
    if [ -f /run/secrets/worker_kek ] && [ -d /run/ovlm-kek ] && [ ! -s /run/ovlm-kek/worker_kek ]; then
        setpriv --reuid=10001 --regid=10001 --clear-groups -- \
            sh -c 'umask 077; cat > /run/ovlm-kek/.worker_kek.tmp && mv /run/ovlm-kek/.worker_kek.tmp /run/ovlm-kek/worker_kek' \
            < /run/secrets/worker_kek
    fi
    exec setpriv --reuid=10001 --regid=10001 --groups=10002 \
        --inh-caps=+setuid,+setgid,+kill --ambient-caps=+setuid,+setgid,+kill \
        --bounding-set=-all,+setuid,+setgid,+kill --no-new-privs -- "$@"
fi
exec "$@"
