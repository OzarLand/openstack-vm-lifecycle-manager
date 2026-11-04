# Working rules for implementation agents

| Field | Value |
|---|---|
| Owner | Agent 1 — PM / Engineering Manager |
| Last updated | 2026-11-04 |

Every implementation agent follows these rules. The brief of each task says which files the agent owns.

## Source of truth

- Design: [architecture.md](architecture.md), [data-model.md](data-model.md), [api-design.md](api-design.md),
  [renewal-workflow.md](renewal-workflow.md), [security-model.md](security-model.md), the ADRs.
- Backlog: [roadmap.md](roadmap.md). Tests: [testing-strategy.md](testing-strategy.md).
- If the design is wrong or unclear, **do not silently deviate**: implement the safest reading, and report the
  question in your summary.

## Shared files (to avoid merge conflicts)

| Shared thing | Rule |
|---|---|
| Alembic migrations | One migration per module, `down_revision = "0001"` (the baseline), `branch_labels = ("<module>",)`. Several heads are expected; Agent 1 adds the merge revision. Never edit another module's migration. |
| API routers | Put your routes in `src/ovlm/api/routes_<module>.py` (or `src/ovlm/<module>/api.py`) and add **one** `include_router` line in `src/ovlm/api/app.py`. |
| SQLAlchemy models | In your own module (`src/ovlm/<module>/models.py`), importing the shared `Base` from `ovlm.db`. |
| Dependencies | Add with `uv add` and commit `uv.lock` and `requirements.lock` (`make lock`). Pin exact versions. |
| Import boundaries | Respect the import-linter contracts. The api never imports `openstack`, `automation` or `worker`. |

## Quality bar (before every push)

- `make lint` and `make test` pass. **If your sandbox runs as root, also run the unit tests as a non-root user**: root hid a real production bug once (Ansible needs a writable `HOME`; fixed in PR #7). Integration tests need PostgreSQL: Docker, or `OVLM_TEST_DATABASE_URL`.
- New behaviour comes with tests at the level `testing-strategy.md` names.
- Report honestly: say exactly which tests ran and passed, and what was not run. Never claim a status (unit tested,
  integration tested, lab validated) that was not reached.
- No secrets, real hostnames or addresses in code, tests, fixtures or logs.

## Git

- `git config user.name "Soufian Zaouam"` and
  `git config user.email "18644174+soufian-zaouam@users.noreply.github.com"`.
- Small commits, with sign-off (`git commit -s`).
- **Commit messages never mention Claude or any AI model, and contain no Co-Authored-By or session-link trailers**
  (the maintainer's rule).
- Push only to your own branch (named in your brief). Retry on transient errors. No pull requests.

## Summary at the end of the task (15 lines or fewer)

What exists, which tests pass (with counts), deviations from the design, open questions, and blockers.
