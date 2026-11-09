.DEFAULT_GOAL := help
SHELL := /bin/bash
UV ?= uv
SECRETS := db_superuser_password db_owner_password db_api_password db_worker_password
# Tag of the images `make build` produces. A real installation builds a fixed tag (e.g. the commit) and names it in
# .env as OVLM_IMAGE / OVLM_WORKER_IMAGE for compose.prod.yaml.
IMAGE_TAG ?= dev
# The Compose command of the operational targets (backup, restore, upgrade-preflight, smoke). Plain `docker compose`
# reads COMPOSE_FILE from .env: put COMPOSE_FILE=compose.prod.yaml there and every target follows the production file.
# `make <target> COMPOSE_FILE=compose.prod.yaml` works too. The development targets (up, down) always use compose.yaml.
COMPOSE_FILE ?=
COMPOSE := docker compose$(foreach f,$(subst :, ,$(COMPOSE_FILE)), -f $(f))
# compose.override.yaml is still read when present (install-guide.md section 5), as plain `docker compose` would.
DEV_COMPOSE := docker compose -f compose.yaml$(if $(wildcard compose.override.yaml), -f compose.override.yaml)

.PHONY: help install lint format typecheck test test-unit test-integration lock lock-check secrets build up down smoke clean \
	backup restore upgrade-preflight compose-check

help:  ## Show targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-18s %s\n", $$1, $$2}'

install:  ## Create the virtualenv from the hash-locked uv.lock
	$(UV) sync --frozen --group automation

lint:  ## ruff, ruff format check, mypy, import-linter
	$(UV) run --frozen ruff check .
	$(UV) run --frozen ruff format --check .
	$(UV) run --frozen mypy
	$(UV) run --frozen lint-imports

format:  ## Apply ruff fixes and formatting
	$(UV) run --frozen ruff check --fix .
	$(UV) run --frozen ruff format .

test: test-unit test-integration  ## Unit then integration tests (integration needs Docker or OVLM_TEST_DATABASE_URL)

test-unit:
	$(UV) run --frozen --group automation pytest tests/unit

test-integration:  ## Starts a throw-away PostgreSQL container unless OVLM_TEST_DATABASE_URL is set
	$(UV) run --frozen --group automation pytest tests/integration

lock:  ## Re-resolve uv.lock; regenerate requirements.lock (api image) and requirements-worker.lock (worker image: + automation group)
	$(UV) lock
	$(UV) export --frozen --no-dev --group build --no-emit-project --format requirements-txt --no-header -o requirements.lock >/dev/null
	$(UV) export --frozen --no-dev --group build --group automation --no-emit-project --format requirements-txt --no-header -o requirements-worker.lock >/dev/null

lock-check:  ## Fail if the lock files are stale
	$(UV) lock --check
	$(UV) export --frozen --no-dev --group build --no-emit-project --format requirements-txt --no-header -o /tmp/requirements.lock.check >/dev/null
	diff -u requirements.lock /tmp/requirements.lock.check
	$(UV) export --frozen --no-dev --group build --group automation --no-emit-project --format requirements-txt --no-header -o /tmp/requirements-worker.lock.check >/dev/null
	diff -u requirements-worker.lock /tmp/requirements-worker.lock.check

secrets:  ## Create the missing secrets in ./secrets (git-ignored): DB passwords, TOTP key (api), worker key pair (KEK)
	@# Creates only missing files, each with its mode; never rewrites a file or changes an existing file's mode, so
	@# a tightened key (totp_key 0400 owned by 10001, install-guide-real-cloud.md 5.2) stays as the operator set it.
	@set -eu; umask 077; mkdir -p secrets; \
	for s in $(SECRETS); do \
	  if [ ! -e secrets/$$s ]; then \
	    head -c 24 /dev/urandom | base64 | tr -d '/+=\n' > secrets/$$s; chmod 0444 secrets/$$s; echo "created secrets/$$s"; \
	  fi; \
	done; \
	if [ ! -e secrets/worker_kek ]; then \
	  openssl genpkey -algorithm X25519 -out secrets/worker_kek; chmod 0400 secrets/worker_kek; rm -f secrets/worker_kek.pub; \
	  echo "created secrets/worker_kek (worker private key: mounted into the worker only)"; \
	elif [ -n "$$(find secrets/worker_kek -perm /077)" ]; then \
	  echo "WARNING: secrets/worker_kek has group or other permissions; expected 0400 (chmod 0400 secrets/worker_kek)" >&2; \
	fi; \
	if [ ! -e secrets/worker_kek.pub ]; then \
	  openssl pkey -in secrets/worker_kek -pubout -out secrets/worker_kek.pub; chmod 0444 secrets/worker_kek.pub; \
	  echo "created secrets/worker_kek.pub"; \
	fi; \
	if [ ! -e secrets/totp_key ]; then \
	  openssl rand -base64 32 | tr '+/' '-_' > secrets/totp_key; chmod 0444 secrets/totp_key; \
	  echo "created secrets/totp_key (Fernet key encrypting TOTP secrets at rest: api only; 0444 for development)"; \
	fi

build:  ## Build both images: ovlm:$(IMAGE_TAG) (api, migrate) and ovlm-worker:$(IMAGE_TAG) (worker); IMAGE_TAG=dev
	docker build --target runtime -t ovlm:$(IMAGE_TAG) .
	docker build --target worker -t ovlm-worker:$(IMAGE_TAG) .

up: secrets  ## Build and start postgres, migrate, api and worker; wait until healthy
	$(DEV_COMPOSE) up -d --build --wait

down:  ## Stop the development stack (compose.yaml) and delete its volumes; never the compose.prod.yaml project
	$(DEV_COMPOSE) down -v

compose-check:  ## Validate compose.yaml and compose.prod.yaml with `docker compose config` (no daemon needed)
	$(DEV_COMPOSE) config -q
	OVLM_IMAGE=ovlm:check OVLM_WORKER_IMAGE=ovlm-worker:check OVLM_EXTERNAL_URL=https://ovlm.example.org \
	  docker compose -f compose.prod.yaml config -q

smoke:  ## Assertions on a running stack (`make up` first); used by CI
	@set -euo pipefail; \
	echo "== api answers on loopback"; \
	curl -fsS http://127.0.0.1:8000/healthz; echo; \
	curl -fsS http://127.0.0.1:8000/readyz; echo; \
	echo "== anonymous / redirects to the login page, which loads htmx"; \
	test "$$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' http://127.0.0.1:8000/)" = "303 http://127.0.0.1:8000/login"; \
	curl -fsS http://127.0.0.1:8000/login | grep -q htmx; \
	echo "== /metrics is not on the public port"; \
	test "$$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/metrics)" = 404; \
	echo "== metrics on the internal ports (Compose network only)"; \
	$(COMPOSE) exec -T api python -c "import urllib.request as u; assert b'ovlm_build_info' in u.urlopen('http://127.0.0.1:9100/metrics').read()"; \
	$(COMPOSE) exec -T worker python -c "import urllib.request as u; b=u.urlopen('http://127.0.0.1:9100/metrics').read(); assert b'ovlm_worker_heartbeat_age_seconds' in b"; \
	echo "== migrate exited 0"; \
	test "$$(docker inspect -f '{{.State.ExitCode}}' $$($(COMPOSE) ps -a -q migrate))" = 0; \
	echo "== non-root, distinct users"; \
	test "$$($(COMPOSE) exec -T api id -u)" = 10001; \
		$(COMPOSE) run --rm --no-deps --entrypoint id api ovlm-ansible | grep -q 'uid=10002'; \
	echo "== worker image: has ssh, ssh-keyscan, git; ansible --version runs as ovlm-ansible; worker holds only setuid/setgid/kill"; \
	$(COMPOSE) exec -T worker /usr/local/bin/ovlm-worker-entrypoint -- python - < tests/smoke/worker_checks.py; \
	echo "== worker: no process runs as root or holds DAC_READ_SEARCH after start-up; PID 1 is tini as ovlm (CS-6)"; \
	$(COMPOSE) exec -T -u ovlm worker python - < tests/smoke/worker_root_checks.py; \
	echo "== api image: no ansible, ssh or git"; \
	$(COMPOSE) exec -T api python - < tests/smoke/api_checks.py; \
	echo "== secret isolation: api/worker never see the owner secret"; \
	test "$$($(COMPOSE) exec -T api ls /run/secrets | tr '\n' ' ')" = "db_api_password totp_key worker_kek_pub "; \
	test "$$($(COMPOSE) exec -T worker ls /run/secrets | tr '\n' ' ')" = "db_worker_password worker_kek "; \
	echo "== the api has no KEK private key and cannot load one"; \
	! $(COMPOSE) exec -T api test -e /run/ovlm-kek/worker_kek; \
	$(COMPOSE) exec -T api python - < tests/smoke/api_kek_checks.py; \
	echo "== TOTP enrolment has its key (no 503): the api loads the vault exactly as the enrolment route does"; \
	$(COMPOSE) exec -T api python - < tests/smoke/api_totp_checks.py; \
	! $(COMPOSE) exec -T worker test -e /run/secrets/totp_key; \
	echo "== read-only rootfs"; \
	! $(COMPOSE) exec -T api touch /app/x 2>/dev/null; \
	echo "== each service connects as its own DB role"; \
	test "$$($(COMPOSE) exec -T postgres psql -U postgres -d ovlm -Atc "select string_agg(distinct usename, ',' order by usename) from pg_stat_activity where application_name like 'ovlm-%'")" = ovlm_api,ovlm_worker; \
	echo "smoke OK"

BACKUP_DIR ?= backups

backup:  ## Dump the running stack's database to $(BACKUP_DIR)/<UTC time>/ after `ovlm backup check`
	@set -euo pipefail; umask 077; \
	d="$(BACKUP_DIR)/$$(date -u +%Y%m%dT%H%M%SZ)"; mkdir -p "$$d"; \
	echo "== backup check: every sealed secret in use is wrapped to the current KEK; the TOTP key decrypts"; \
	if ! $(COMPOSE) exec -T api ovlm backup check > "$$d/manifest.txt"; then \
	  cat "$$d/manifest.txt"; rm -rf "$$d"; \
	  echo "backup REFUSED: the keys in ./secrets cannot restore this database (see the BLOCK lines)"; exit 2; \
	fi; \
	echo "== pg_dump (custom format: schema, data, grants, triggers, sequences)"; \
	$(COMPOSE) exec -T postgres pg_dump -U postgres -d ovlm -Fc > "$$d/ovlm.dump"; \
	$(COMPOSE) exec -T postgres pg_restore -l < "$$d/ovlm.dump" > /dev/null; \
	echo "== cluster roles (attributes only, no passwords: those come from ./secrets)"; \
	$(COMPOSE) exec -T postgres pg_dumpall -U postgres --roles-only --no-role-passwords > "$$d/roles.sql"; \
	(cd "$$d" && sha256sum manifest.txt ovlm.dump roles.sql > SHA256SUMS); \
	cat "$$d/manifest.txt"; \
	echo "backup OK: $$d (store it encrypted; the KEK and TOTP key of this manifest are kept apart, offline)"

restore:  ## DESTRUCTIVE: replace the database: make restore DUMP=backups/<time> CONFIRM=replace-ovlm-database
	@set -euo pipefail; \
	test -n "$(DUMP)" || { echo "DUMP=$(BACKUP_DIR)/<time> is required"; exit 2; }; \
	test "$(CONFIRM)" = replace-ovlm-database || { echo "CONFIRM=replace-ovlm-database is required: this drops the database ovlm"; exit 2; }; \
	(cd "$(DUMP)" && sha256sum -c --quiet SHA256SUMS); \
	cat "$(DUMP)/manifest.txt"; \
	$(COMPOSE) up -d --wait postgres; \
	$(COMPOSE) stop worker api; \
	$(COMPOSE) exec -T postgres psql -U postgres -d postgres -v ON_ERROR_STOP=1 -c 'DROP DATABASE IF EXISTS ovlm WITH (FORCE)'; \
	$(COMPOSE) exec -T postgres psql -U postgres -d postgres -v ON_ERROR_STOP=1 -v dbname=ovlm < deploy/backup/create-database.sql; \
	$(COMPOSE) exec -T postgres pg_restore -U postgres -d ovlm --exit-on-error --single-transaction < "$(DUMP)/ovlm.dump"; \
	echo "== end every restored browser session (a session revoked after the backup would be live again)"; \
	$(COMPOSE) exec -T postgres psql -U postgres -d ovlm -v ON_ERROR_STOP=1 -c 'DELETE FROM auth_session'; \
	$(COMPOSE) up -d --wait; \
	echo "== the keys in ./secrets open this database"; \
	$(COMPOSE) exec -T api ovlm backup check; \
	$(COMPOSE) exec -T -u ovlm worker ovlm kek status; \
	echo "restore OK: run make smoke and check every non-terminal run (docs/backup-restore-upgrade.md section 3)"

upgrade-preflight:  ## Read-only, new image: refuse an upgrade mid-window or a downgrade (PREFLIGHT_ARGS=--worker-stopped)
	$(COMPOSE) run --rm --no-deps -T api upgrade preflight $(PREFLIGHT_ARGS)

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache build dist
