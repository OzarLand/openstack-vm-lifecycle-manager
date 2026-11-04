[← OVLM home](README.md) · [← OzarLand home](https://github.com/OzarLand/ozarland)

# Contributing to OVLM

OVLM is a **code** project in [OzarLand](https://github.com/OzarLand/ozarland). It follows the
[OzarLand contribution guide](https://github.com/OzarLand/ozarland/blob/main/CONTRIBUTING.md). This page adds what a
code project needs on top: a dev setup, test rules and a stricter review.

> [!WARNING]
> OVLM is **pre-alpha** and **not lab validated**. The interfaces still move. Do not point a development build at a
> production cloud.

## Where to start

| You want to… | Do this |
|---|---|
| Fix a small, well-bounded gap | Pick an entry from [good-first-issues.md](docs/good-first-issues.md), or an issue labelled `good first contribution` |
| Challenge the design | Open an issue on [renewal-workflow.md](docs/renewal-workflow.md) or the [security model](docs/security-model.md) |
| Tell us how your cloud behaves | Use the *Cloud behaviour report* issue form |
| Report a bug | Use the *Bug report* issue form |
| Ask a question | Start a discussion in [OzarLand Discussions](https://github.com/OzarLand/ozarland/discussions) |
| Report a vulnerability or leaked secret | **Do not open a public issue.** Use *Report a vulnerability* in the Security tab of this repository |

If you are unsure where something goes, ask in a discussion. For a change bigger than a few files, open an issue
first, so nobody builds something the design does not allow.

## Rules that are not optional

1. **No secrets, real hostnames, domains, IP or MAC addresses**, in code, tests, fixtures, logs, issues or screenshots.
   Use `example.org` and documentation address ranges. See
   [sensitive data](https://github.com/OzarLand/ozarland/blob/main/docs/conventions/sensitive-data.md).
2. **Flag risky commands** in docs: ⚠️ for state-changing, 🛑 for destructive, with what changes, who is affected,
   and how to undo it. See [risk warnings](https://github.com/OzarLand/ozarland/blob/main/docs/conventions/risk-warnings.md).
3. **Never claim a status that was not reached** (see [status vocabulary](#status-vocabulary)).
4. **Do not weaken a safety rule to make a test pass.** OVLM never deletes a data volume or a floating IP, and
   every OpenStack write passes an allowlist and an ownership guard. A change that loosens this needs a design
   discussion first.
5. Follow the [code of conduct](https://github.com/OzarLand/ozarland/blob/main/CODE_OF_CONDUCT.md).

## Development setup

You need Python 3.12 or later, [uv](https://docs.astral.sh/uv/), GNU Make, and Docker with Compose.
Docker is also what starts a throw-away PostgreSQL for the integration tests.

```bash
git clone https://github.com/OzarLand/openstack-vm-lifecycle-manager.git
cd openstack-vm-lifecycle-manager
make install     # hash-locked virtualenv from uv.lock
make lint        # ruff, ruff format check, mypy, import-linter
make test-unit   # unit tests: no database, no cloud
make test        # unit, then integration tests
```

`make help` lists every target.

### PostgreSQL for the integration tests

`make test-integration` starts a throw-away `postgres` container with Docker. Without Docker, point the tests at a
PostgreSQL you control with a **superuser** URL:

```bash
# ⚠️ State-changing: the tests create and drop roles and databases on this server.
# Use a disposable server, never a shared one.
export OVLM_TEST_DATABASE_URL='postgresql+psycopg://postgres:<password>@127.0.0.1:5432/postgres'
make test-integration
```

There is no silent skip. With neither Docker nor `OVLM_TEST_DATABASE_URL`, the integration tests **error**, so a
green run always means PostgreSQL really ran.

### Run the unit tests as a non-root user

If your shell is root (a container, a cloud sandbox), **also run the unit tests as a normal user**. Running as root
once hid a real production bug: Ansible needs a writable `HOME`, and the worker does not run as root
(PR #7). Create a user, give it read access to the checkout, and run `make test-unit` as that user.

### Run the local stack

```bash
make up       # generates dev secrets in ./secrets (git-ignored), builds, starts, waits until healthy
make smoke    # assertions against the running stack
make down     # ⚠️ stops the stack and deletes its database volume
```

The Compose file is a **development and CI** file, not an installation. For an evaluation install, read the
[install guide](docs/install-guide.md).

## Branches, commits and pull requests

- Work on a branch of your fork. Open a pull request against `main`. One topic per pull request.
- **Sign off every commit** (`git commit -s`) to certify the
  [Developer Certificate of Origin](https://developercertificate.org/). There is no contributor agreement.
- Write the commit message in English, in the imperative, and say *why* when it is not obvious.
- Pull requests are squash-merged. The maintainer merges.
- Before you push, run `make lint` and `make test`. CI runs the same checks plus `make lock-check`.
- New behaviour comes with tests at the level [testing-strategy.md](docs/testing-strategy.md) names.
- If you add a dependency, use `uv add`, pin an exact version, and run `make lock`. Commit `uv.lock`,
  `requirements.lock` and `requirements-worker.lock`.
- Respect the import boundaries `make lint` checks: the `api` never imports `openstack`, `automation` or `worker`.
- Database changes are Alembic migrations, one per module (see [agent-working-rules.md](docs/agent-working-rules.md)).
- Do not put secrets in `compose.yaml` or in environment values. Secrets are files (Docker secrets).

Fill in the pull request template. It asks what was tested and what was **not**.

## Review expectations

Reviews focus on correctness, safety and scope, not on style (ruff decides style).

**Critical areas get an independent review** by a reviewer other than the author, and the pull request says so:

| Area | Why |
|---|---|
| Renewal workflow and strategy steps (`src/ovlm/renewal`, `src/ovlm/workflow`) | A mistake can cause downtime or data loss on a real VM |
| OpenStack write client, allowlist, ownership guard (`src/ovlm/openstack`) | The last barrier before a destructive call |
| Authentication, authorization, TOTP, step-up, audit (`src/ovlm/auth`, `src/ovlm/audit`) | Decides who can approve a destructive step |
| Secrets, credentials, the automation runner (`src/ovlm/secrets`, `src/ovlm/automation`) | Credentials and guest access |

For these areas, expect questions such as: what happens on a crash between two steps? Is the call idempotent?
Which role may do this? Can a secret reach a log? A reviewer may ask for a failure test before approving.

Anyone can review. A comment like "I ran this on a cloud with policy X and it behaved like Y" is a contribution.

## Status vocabulary

Use these words, and only when they are true. The full table is in
[agent-team.md](docs/agent-team.md#status-vocabulary-used-in-every-document).

| Status | Meaning |
|---|---|
| **Designed** | Described in a document, no code |
| **Implemented** | Code exists on a branch |
| **Unit tested** | Tests with OpenStack faked pass in CI |
| **Integration tested** | Tests against real PostgreSQL and a real Ansible run pass in CI |
| **Lab validated** | Run end to end on a real OpenStack cloud, with stored evidence |
| **Production validated** | Confirmed by a human operator, other than the author, on a real platform |

Nothing in OVLM is lab validated yet. In a pull request, say exactly which tests ran and what did not run.
"Not tested" is an acceptable answer. A false "tested" is not.

## Where to ask

- Questions and ideas: [OzarLand Discussions](https://github.com/OzarLand/ozarland/discussions).
- Bugs, cloud behaviour reports and design questions: the issue forms of this repository.
- The way the team works: [agent-working-rules.md](docs/agent-working-rules.md) and
  [agent-team.md](docs/agent-team.md).

By contributing, you agree that your contribution is published under the [Apache License 2.0](LICENSE).
