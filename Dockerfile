# syntax=docker/dockerfile:1
# One image, three process roles (api, worker, migrate) - architecture.md section 4.
# Base pinned by digest; bump together with the Renovate/Dependabot PR.
ARG PYTHON_IMAGE=python:3.12-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337

FROM ${PYTHON_IMAGE} AS builder
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
RUN python -m venv /opt/venv
WORKDIR /build
# Hash-checked install of every dependency (and the build backend), then the project itself without deps.
COPY requirements.lock ./
# Optional build secret `pip_ca`: a CA bundle for builds behind a TLS-intercepting proxy
# (docker build --secret id=pip_ca,src=/path/ca.pem). Not needed otherwise.
RUN --mount=type=secret,id=pip_ca,required=false \
    if [ -s /run/secrets/pip_ca ]; then export PIP_CERT=/run/secrets/pip_ca; fi; \
    /opt/venv/bin/pip install --require-hashes --no-deps -r requirements.lock
COPY pyproject.toml ./
COPY src ./src
RUN /opt/venv/bin/pip install --no-deps --no-build-isolation .

FROM ${PYTHON_IMAGE} AS runtime
ARG VERSION=0.0.1
LABEL org.opencontainers.image.title="ovlm" \
      org.opencontainers.image.description="OpenStack VM Lifecycle Manager" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"
# Two OS users (security-model.md section 6.5): `ovlm` runs api/worker; `ovlm-ansible` is reserved for the
# ansible-runner children and has no access to ovlm's files. Distinct uids, no login shell, no home contents.
RUN groupadd --system --gid 10001 ovlm \
 && groupadd --system --gid 10002 ovlm-ansible \
 && useradd --system --uid 10001 --gid ovlm --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin ovlm \
 && useradd --system --uid 10002 --gid ovlm-ansible --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin ovlm-ansible
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
COPY --from=builder /opt/venv /opt/venv
WORKDIR /app
COPY alembic.ini ./
COPY migrations ./migrations
USER ovlm
EXPOSE 8000
# Liveness of the api by default; Compose overrides the check per service.
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2).status == 200 else 1)"]
ENTRYPOINT ["ovlm"]
CMD ["api"]
