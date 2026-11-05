# syntax=docker/dockerfile:1
# Two images from one Dockerfile - architecture.md section 4:
#   target `runtime` (default): api and migrate. No ansible, no ansible-runner, no collections.
#   target `worker`: the same code plus the `automation` dependency group and the pinned ansible.posix collection.
# The api must never import automation (import-linter); keeping ansible out of its image makes that physical.
# Base pinned by digest; bump together with the Renovate/Dependabot PR.
ARG PYTHON_IMAGE=python:3.12-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337
# Used only to fetch the pinned collection at build time.
ARG GIT_IMAGE=alpine/git:v2.47.2@sha256:062a01ad7a0eb17cff382bc5e26086b4d710e56dfdfdf001109a49b6d9bd378c

# --- Python environments: hash-checked install of every dependency (and the build backend), then the project itself.
# Optional build secret `pip_ca`: a CA bundle for builds behind a TLS-intercepting proxy
# (docker build --secret id=pip_ca,src=/path/ca.pem). Not needed otherwise.
FROM ${PYTHON_IMAGE} AS venv-api
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
RUN python -m venv /opt/venv
WORKDIR /build
COPY requirements.lock ./
RUN --mount=type=secret,id=pip_ca,required=false \
    if [ -s /run/secrets/pip_ca ]; then export PIP_CERT=/run/secrets/pip_ca; fi; \
    /opt/venv/bin/pip install --require-hashes --no-deps -r requirements.lock
COPY pyproject.toml ./
COPY src ./src
RUN /opt/venv/bin/pip install --no-deps --no-build-isolation .

# requirements-worker.lock = requirements.lock + the `automation` group (ansible-core, ansible-runner, ...).
FROM ${PYTHON_IMAGE} AS venv-worker
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
RUN python -m venv /opt/venv
WORKDIR /build
COPY requirements-worker.lock ./
RUN --mount=type=secret,id=pip_ca,required=false \
    if [ -s /run/secrets/pip_ca ]; then export PIP_CERT=/run/secrets/pip_ca; fi; \
    /opt/venv/bin/pip install --require-hashes --no-deps -r requirements-worker.lock
COPY pyproject.toml ./
COPY src ./src
RUN /opt/venv/bin/pip install --no-deps --no-build-isolation .

# --- Pinned collections, provisioned at build time from a commit (no Galaxy at run time, SEC-R-12).
# The commit is the tag named in ansible/requirements.yml; the build fails if the two ever disagree.
# Fetching needs the build host to reach github.com (and, behind a TLS-intercepting proxy, the `pip_ca` secret).
FROM ${GIT_IMAGE} AS collection-src
ARG ANSIBLE_POSIX_COMMIT=e98d9a0756458be1ac710988498000973889075c
RUN --mount=type=secret,id=pip_ca,required=false \
    set -eu; \
    if [ -s /run/secrets/pip_ca ]; then export GIT_SSL_CAINFO=/run/secrets/pip_ca; fi; \
    git init -q /posix && cd /posix \
 && git fetch -q --depth 1 https://github.com/ansible-collections/ansible.posix.git "${ANSIBLE_POSIX_COMMIT}" \
 && git checkout -q FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "${ANSIBLE_POSIX_COMMIT}" \
 && rm -rf .git

FROM ${PYTHON_IMAGE} AS collections
ARG ANSIBLE_POSIX_VERSION=2.2.2
COPY --from=venv-worker /opt/venv /opt/venv
COPY --from=collection-src /posix /tmp/posix
COPY ansible/requirements.yml /tmp/requirements.yml
RUN set -eu; \
    grep -A1 "name: ansible.posix" /tmp/requirements.yml | grep -q "version: ${ANSIBLE_POSIX_VERSION}$"; \
    /opt/venv/bin/ansible-galaxy collection install /tmp/posix -p /opt/ovlm/collections \
 && grep -q "\"version\": \"${ANSIBLE_POSIX_VERSION}\"" /opt/ovlm/collections/ansible_collections/ansible/posix/MANIFEST.json \
 && find /opt/ovlm/collections -type d -exec chmod 0755 {} + \
 && find /opt/ovlm/collections -type f -exec chmod a+r,go-w {} +

# --- Runtime base: two OS users (security-model.md section 6.5): `ovlm` runs api/worker; `ovlm-ansible` is
# reserved for the ansible-runner children and has no access to ovlm's files. Distinct uids, no login shell.
FROM ${PYTHON_IMAGE} AS base
ARG VERSION=0.0.1
LABEL org.opencontainers.image.title="ovlm" \
      org.opencontainers.image.description="OpenStack VM Lifecycle Manager" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"
RUN groupadd --system --gid 10001 ovlm \
 && groupadd --system --gid 10002 ovlm-ansible \
 && useradd --system --uid 10001 --gid ovlm --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin ovlm \
 && useradd --system --uid 10002 --gid ovlm-ansible --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin ovlm-ansible
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY alembic.ini ./
COPY migrations ./migrations
EXPOSE 8000
# Liveness of the api by default; Compose overrides the check per service.
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2).status == 200 else 1)"]

# --- worker: automation dependencies, pinned collection, and the launcher that gives the worker (uid ovlm) exactly
# CAP_SETUID/SETGID/KILL as ambient capabilities so it can run ansible-runner as `ovlm-ansible` (automation-contract.md 11).
FROM base AS worker
# ssh/ssh-keyscan/ssh-keygen (host-key pinning, ansible's ssh connection) and git (the verified clone) belong to the
# worker image ONLY: the api image gets neither (checked by `make smoke`). Pinned to the Debian release's upstream
# series (bookworm: openssh 9.2, git 2.39), not to the -deb12uN revision: that one disappears from the archive with
# every security update and would break rebuilds. The base image digest above fixes the rest of the OS.
ARG OPENSSH_CLIENT_VERSION=1:9.2p1-*
ARG GIT_VERSION=1:2.39.*
# apt over HTTPS by default: a build behind an HTTPS-only egress proxy (CONNECT 443; plain HTTP refused) works without a
# hand-built base image. The proxy itself comes from the usual HTTPS_PROXY/https_proxy build args (compose.yaml passes
# them from .env); a TLS-intercepting proxy's CA goes in the optional `pip_ca` build secret, as for pip. Set
# `--build-arg APT_URI_SCHEME=http` to get the base image's own http:// sources back.
ARG APT_URI_SCHEME=https
RUN --mount=type=secret,id=pip_ca,required=false \
    set -eu; \
    case "${APT_URI_SCHEME}" in http|https) ;; *) echo "APT_URI_SCHEME must be http or https" >&2; exit 1 ;; esac; \
    for f in /etc/apt/sources.list /etc/apt/sources.list.d/*; do \
      if [ -f "$f" ]; then sed -i -E "s#https?://#${APT_URI_SCHEME}://#g" "$f"; fi; \
    done; \
    apt_opts=""; \
    if [ -s /run/secrets/pip_ca ]; then apt_opts="-o Acquire::https::CaInfo=/run/secrets/pip_ca"; fi; \
    apt-get $apt_opts update \
 && DEBIAN_FRONTEND=noninteractive apt-get $apt_opts install -y --no-install-recommends \
      "openssh-client=${OPENSSH_CLIENT_VERSION}" "git=${GIT_VERSION}" \
 && rm -rf /var/lib/apt/lists/*
COPY --from=venv-worker /opt/venv /opt/venv
COPY --from=collections /opt/ovlm/collections /opt/ovlm/collections
COPY docker/worker-entrypoint.sh /usr/local/bin/ovlm-worker-entrypoint
USER ovlm
ENTRYPOINT ["/usr/local/bin/ovlm-worker-entrypoint"]
CMD ["worker"]

# --- runtime (default target): api, migrate. Last stage on purpose: `docker build .` builds this one.
FROM base AS runtime
COPY --from=venv-api /opt/venv /opt/venv
USER ovlm
ENTRYPOINT ["ovlm"]
CMD ["api"]
