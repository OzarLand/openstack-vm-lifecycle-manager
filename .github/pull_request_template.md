## What this changes

<!-- One or two sentences: what and why. Link the issue or discussion, if any (Closes #N). -->

## Area

<!-- Tick all that apply. The bold areas get an independent review (see CONTRIBUTING.md). -->

- [ ] Docs only
- [ ] Tests only
- [ ] Install, Compose, Makefile, CI
- [ ] Inventory, readiness, policies, profiles, UI
- [ ] **Renewal workflow or strategy**
- [ ] **OpenStack write client, allowlist or ownership guard**
- [ ] **Authentication, authorization, TOTP or audit**
- [ ] **Secrets, credentials or the automation runner**
- [ ] Database migration

## What was tested

<!-- Be exact. Say which commands you ran and the result. Say what you did NOT run. -->

- [ ] `make lint`
- [ ] `make test-unit` (also as a **non-root** user if your shell is root)
- [ ] `make test-integration` (PostgreSQL via Docker or `OVLM_TEST_DATABASE_URL`)
- [ ] `make smoke` against `make up` (only if Compose, images or entrypoints changed)
- [ ] Not run, and why:

**Highest status reached** (see the status vocabulary in CONTRIBUTING.md):
Designed / Implemented / Unit tested / Integration tested.
This change has **not** been lab validated unless a stored evidence bundle says so.

## Safety check

- [ ] OVLM still never deletes a data volume or a floating IP, and still checks the write allowlist and ownership guard.
- [ ] No new OpenStack call is a write, or it is added to the allowlist with a test.
- [ ] No secret in code, tests, fixtures, logs, error messages or Compose environment values.
- [ ] Docs commands carry a ⚠️ (state-changing) or 🛑 (destructive) warning where needed.
- [ ] No real hostname, domain, IP or MAC address anywhere in the diff.

## Housekeeping

- [ ] Commits are signed off (`git commit -s`).
- [ ] New behaviour has tests at the level `docs/testing-strategy.md` names.
- [ ] Dependencies, if changed: exact pin, and `make lock` run (all three lock files committed).
- [ ] Docs updated, or not needed:

## Questions for the reviewer

<!-- Anything you are unsure about. Deviations from the design go here. -->
