.DEFAULT_GOAL := help
SHELL := /bin/bash
UV ?= uv
SECRETS := db_superuser_password db_owner_password db_api_password db_worker_password

.PHONY: help install lint format typecheck test test-unit test-integration lock lock-check secrets build up down smoke clean \
	backup restore upgrade-preflight

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

secrets:  ## Generate random development secrets, the TOTP key (api only) and the worker key pair (KEK) in ./secrets (git-ignored)
	@umask 077; mkdir -p secrets; \
	for s in $(SECRETS); do \
	  [ -f secrets/$$s ] || { head -c 24 /dev/urandom | base64 | tr -d '/+=\n' > secrets/$$s; echo "created secrets/$$s"; }; \
	  chmod 0444 secrets/$$s; \
	done; \
	if [ ! -f secrets/worker_kek ]; then \
	  openssl genpkey -algorithm X25519 -out secrets/worker_kek && rm -f secrets/worker_kek.pub && \
	  echo "created secrets/worker_kek (worker private key: mounted into the worker only)"; \
	fi; \
	chmod 0400 secrets/worker_kek; \
	if [ ! -f secrets/worker_kek.pub ]; then \
	  openssl pkey -in secrets/worker_kek -pubout -out secrets/worker_kek.pub && echo "created secrets/worker_kek.pub"; \
	fi; \
	chmod 0444 secrets/worker_kek.pub; \
	if [ ! -f secrets/totp_key ]; then \
	  openssl rand -base64 32 | tr '+/' '-_' > secrets/totp_key && \
	  echo "created secrets/totp_key (Fernet key encrypting TOTP secrets at rest: mounted into the api only)"; \
	fi; \
	chmod 0444 secrets/totp_key

build:  ## Build both images: ovlm:dev (api, migrate) and ovlm-worker:dev (worker: ansible + collections)
	docker build --target runtime -t ovlm:dev .
	docker build --target worker -t ovlm-worker:dev .

up: secrets  ## Build and start postgres, migrate, api and worker; wait until healthy
	docker compose up -d --build --wait

down:  ## Stop the stack and delete its volume
	docker compose down -v

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
	docker compose exec -T api python -c "import urllib.request as u; assert b'ovlm_build_info' in u.urlopen('http://127.0.0.1:9100/metrics').read()"; \
	docker compose exec -T worker python -c "import urllib.request as u; b=u.urlopen('http://127.0.0.1:9100/metrics').read(); assert b'ovlm_worker_heartbeat_age_seconds' in b"; \
	echo "== migrate exited 0"; \
	test "$$(docker inspect -f '{{.State.ExitCode}}' $$(docker compose ps -a -q migrate))" = 0; \
	echo "== non-root, distinct users"; \
	test "$$(docker compose exec -T api id -u)" = 10001; \
		docker compose run --rm --no-deps --entrypoint id api ovlm-ansible | grep -q 'uid=10002'; \
	echo "== worker image: has ssh, ssh-keyscan, git; ansible --version runs as ovlm-ansible; worker holds only setuid/setgid/kill"; \
	docker compose exec -T worker /usr/local/bin/ovlm-worker-entrypoint -- python - < tests/smoke/worker_checks.py; \
	echo "== worker: no process runs as root or holds DAC_READ_SEARCH after start-up; PID 1 is tini as ovlm (CS-6)"; \
	docker compose exec -T -u ovlm worker python - < tests/smoke/worker_root_checks.py; \
	echo "== api image: no ansible, ssh or git"; \
	docker compose exec -T api python - < tests/smoke/api_checks.py; \
	echo "== secret isolation: api/worker never see the owner secret"; \
	test "$$(docker compose exec -T api ls /run/secrets | tr '\n' ' ')" = "db_api_password totp_key worker_kek_pub "; \
	test "$$(docker compose exec -T worker ls /run/secrets | tr '\n' ' ')" = "db_worker_password worker_kek "; \
	echo "== the api has no KEK private key and cannot load one"; \
	! docker compose exec -T api test -e /run/ovlm-kek/worker_kek; \
	docker compose exec -T api python - < tests/smoke/api_kek_checks.py; \
	echo "== TOTP enrolment has its key (no 503): the api loads the vault exactly as the enrolment route does"; \
	docker compose exec -T api python - < tests/smoke/api_totp_checks.py; \
	! docker compose exec -T worker test -e /run/secrets/totp_key; \
	echo "== read-only rootfs"; \
	! docker compose exec -T api touch /app/x 2>/dev/null; \
	echo "== each service connects as its own DB role"; \
	test "$$(docker compose exec -T postgres psql -U postgres -d ovlm -Atc "select string_agg(distinct usename, ',' order by usename) from pg_stat_activity where application_name like 'ovlm-%'")" = ovlm_api,ovlm_worker; \
	echo "smoke OK"

BACKUP_DIR ?= backups

backup:  ## Dump the running stack's database to $(BACKUP_DIR)/<UTC time>/ after `ovlm backup check`
	@set -euo pipefail; umask 077; \
	d="$(BACKUP_DIR)/$$(date -u +%Y%m%dT%H%M%SZ)"; mkdir -p "$$d"; \
	echo "== backup check: every sealed secret in use is wrapped to the current KEK; the TOTP key decrypts"; \
	if ! docker compose exec -T api ovlm backup check > "$$d/manifest.txt"; then \
	  cat "$$d/manifest.txt"; rm -rf "$$d"; \
	  echo "backup REFUSED: the keys in ./secrets cannot restore this database (see the BLOCK lines)"; exit 2; \
	fi; \
	echo "== pg_dump (custom format: schema, data, grants, triggers, sequences)"; \
	docker compose exec -T postgres pg_dump -U postgres -d ovlm -Fc > "$$d/ovlm.dump"; \
	docker compose exec -T postgres pg_restore -l < "$$d/ovlm.dump" > /dev/null; \
	echo "== cluster roles (attributes only, no passwords: those come from ./secrets)"; \
	docker compose exec -T postgres pg_dumpall -U postgres --roles-only --no-role-passwords > "$$d/roles.sql"; \
	(cd "$$d" && sha256sum manifest.txt ovlm.dump roles.sql > SHA256SUMS); \
	cat "$$d/manifest.txt"; \
	echo "backup OK: $$d (store it encrypted; the KEK and TOTP key of this manifest are kept apart, offline)"

restore:  ## DESTRUCTIVE: replace the database: make restore DUMP=backups/<time> CONFIRM=replace-ovlm-database
	@set -euo pipefail; \
	test -n "$(DUMP)" || { echo "DUMP=$(BACKUP_DIR)/<time> is required"; exit 2; }; \
	test "$(CONFIRM)" = replace-ovlm-database || { echo "CONFIRM=replace-ovlm-database is required: this drops the database ovlm"; exit 2; }; \
	(cd "$(DUMP)" && sha256sum -c --quiet SHA256SUMS); \
	cat "$(DUMP)/manifest.txt"; \
	docker compose up -d --wait postgres; \
	docker compose stop worker api; \
	docker compose exec -T postgres psql -U postgres -d postgres -v ON_ERROR_STOP=1 -c 'DROP DATABASE IF EXISTS ovlm WITH (FORCE)'; \
	docker compose exec -T postgres psql -U postgres -d postgres -v ON_ERROR_STOP=1 -v dbname=ovlm < deploy/backup/create-database.sql; \
	docker compose exec -T postgres pg_restore -U postgres -d ovlm --exit-on-error --single-transaction < "$(DUMP)/ovlm.dump"; \
	echo "== end every restored browser session (a session revoked after the backup would be live again)"; \
	docker compose exec -T postgres psql -U postgres -d ovlm -v ON_ERROR_STOP=1 -c 'DELETE FROM auth_session'; \
	docker compose up -d --wait; \
	echo "== the keys in ./secrets open this database"; \
	docker compose exec -T api ovlm backup check; \
	docker compose exec -T -u ovlm worker ovlm kek status; \
	echo "restore OK: run make smoke and check every non-terminal run (docs/backup-restore-upgrade.md section 3)"

upgrade-preflight:  ## Read-only, new image: refuse an upgrade mid-window or a downgrade (PREFLIGHT_ARGS=--worker-stopped)
	docker compose run --rm --no-deps -T api upgrade preflight $(PREFLIGHT_ARGS)

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache build dist
