.DEFAULT_GOAL := help
SHELL := /bin/bash
UV ?= uv
SECRETS := db_superuser_password db_owner_password db_api_password db_worker_password

.PHONY: help install lint format typecheck test test-unit test-integration lock lock-check secrets build up down smoke clean

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

secrets:  ## Generate random development secrets in ./secrets (git-ignored)
	@umask 077; mkdir -p secrets; \
	for s in $(SECRETS); do \
	  [ -f secrets/$$s ] || { head -c 24 /dev/urandom | base64 | tr -d '/+=\n' > secrets/$$s; echo "created secrets/$$s"; }; \
	  chmod 0444 secrets/$$s; \
	done

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
	echo "== api image: no ansible, ssh or git"; \
	docker compose exec -T api python - < tests/smoke/api_checks.py; \
	echo "== secret isolation: api/worker never see the owner secret"; \
	test "$$(docker compose exec -T api ls /run/secrets)" = db_api_password; \
	test "$$(docker compose exec -T worker ls /run/secrets)" = db_worker_password; \
	echo "== read-only rootfs"; \
	! docker compose exec -T api touch /app/x 2>/dev/null; \
	echo "== each service connects as its own DB role"; \
	test "$$(docker compose exec -T postgres psql -U postgres -d ovlm -Atc "select string_agg(distinct usename, ',' order by usename) from pg_stat_activity where application_name like 'ovlm-%'")" = ovlm_api,ovlm_worker; \
	echo "smoke OK"

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache build dist
