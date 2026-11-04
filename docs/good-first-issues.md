[← OVLM home](../README.md)

# Good first issues

| Field | Value |
|---|---|
| Purpose | Small, well-bounded tasks for a first contribution. Each one is meant to become a GitHub issue labelled `good first contribution`. |
| Last updated | 2026-11-04 |

Every entry below comes from a real gap found by reading the code or running it. None needs an OpenStack cloud or
OpenStack knowledge. Read [CONTRIBUTING.md](../CONTRIBUTING.md) first: set up with `make install`, run `make lint`
and `make test-unit` before you push, and sign off your commits (`git commit -s`).

> [!NOTE]
> OVLM is pre-alpha. If a file named here has moved, search for the function or text quoted in the entry.
> Do not touch the critical areas listed in CONTRIBUTING.md (renewal, OpenStack write client, auth, secrets
> storage) as part of these tasks. Entry 2 changes one small helper in `config/`; it gets a normal review.

| # | Title | Kind | Size |
|---|---|---|---|
| 1 | `make help` hides two targets | Tooling | XS |
| 2 | A secret file that is not valid UTF-8 crashes with a raw traceback | Error message + test | S |
| 3 | `ovlm --help` does not list `admin` and `inventory` | CLI help + test | S |
| 4 | A wrong `--clouds-yaml` path ends in a long traceback | Error message + test | S |
| 5 | A bad `OVLM_HTTP__TRUSTED_PROXIES` value gives an opaque error | Error message + test | S |
| 6 | Add `SECURITY.md` | Docs | XS |
| 7 | Add an index to `docs/` | Docs | S |
| 8 | Document the `ovlm` command line | Docs | S |

---

## 1. `make help` hides two targets

**Why it matters.** `make help` is the first place a new contributor looks. It builds its list from lines that have
a `## description`. `test-unit` and `clean` have none, so they are missing, although `test-unit` is the target
CONTRIBUTING.md tells people to run.

**Files to touch.** `Makefile`.

**Acceptance criteria.**
- `make help` lists `test-unit` and `clean`, each with a one-line description in the same style as the others.
- No other target changes behaviour.

**How to test.**
```bash
make help | grep -E 'test-unit|clean'    # two lines, both with a description
make test-unit                           # still passes
```

---

## 2. A secret file that is not valid UTF-8 crashes with a raw traceback

**Why it matters.** `read_secret_file` is documented to raise `SecretFileError` for a missing, unreadable or empty
file, with a message that never contains the secret. A file with invalid bytes (for example a binary file mounted
by mistake) raises a bare `UnicodeDecodeError` instead, so the process dies with a traceback and no hint about
which setting was wrong. The error text of a decode error can also show raw bytes of the file. Secrets must stay
out of messages.

**Files to touch.**
- `src/ovlm/config/secrets.py` (`read_secret_file`)
- `tests/unit/test_config.py` (next to `test_missing_and_empty_secret_files`)

**Acceptance criteria.**
- A file with invalid UTF-8 raises `SecretFileError`, and the message names the path and says the file is not valid
  UTF-8 text.
- The message contains no bytes from the file.
- Existing behaviour for missing and empty files is unchanged.
- A new unit test covers the invalid-bytes case.

**How to test.**
```bash
make test-unit
uv run --frozen pytest tests/unit/test_config.py -k secret
make lint
```
Try it by hand with `printf '\xff\xfe' > /tmp/bad-secret` and `read_secret_file("/tmp/bad-secret")`.

---

## 3. `ovlm --help` does not list `admin` and `inventory`

**Why it matters.** `main()` in `src/ovlm/cli.py` handles `admin` and `inventory` before it builds the main
parser, so `ovlm --help` and the "invalid choice" error list only `api, worker, migrate`. The first admin is
created with `ovlm admin create`, and a newcomer reading `--help` will not find it.

**Files to touch.**
- `src/ovlm/cli.py` (the parser description or an epilog)
- `tests/unit/` (a small test, for example in `test_inventory_cli.py` or a new `test_cli.py`)

**Acceptance criteria.**
- `ovlm --help` mentions `admin create` and `inventory sync` with one line each, and points to
  `ovlm admin --help` and `ovlm inventory --help`.
- `ovlm admin --help` and `ovlm inventory --help` still work and need no database.
- `api`, `worker` and `migrate` behave as before.
- A unit test checks that `--help` output contains `admin` and `inventory` (use `capsys` and catch `SystemExit`).

**How to test.**
```bash
uv run --frozen ovlm --help
uv run --frozen ovlm admin --help
uv run --frozen ovlm inventory --help
make test-unit && make lint
```

---

## 4. A wrong `--clouds-yaml` path ends in a long traceback

**Why it matters.** `ovlm inventory sync --cloud X --clouds-yaml /wrong/path.yaml` does not tell you the file is
missing. The OpenStack SDK ignores a missing file, so the user sees `Cloud X was not found.` inside a JSON log
line with a full stack trace. The real cause (a typo in the path) is hidden.

**Files to touch.**
- `src/ovlm/inventory/cli.py` (check the path before `connect_read_only`, or in `main`)
- `tests/unit/test_inventory_cli.py`

**Acceptance criteria.**
- If `--clouds-yaml` is given and the file does not exist or is not a regular file, the command prints one clear
  line on stderr (`clouds.yaml not found: <path>`) and exits with a non-zero status, without a traceback.
- The same applies to an unknown `--cloud` name in an existing file: one line, naming the cloud, no stack trace.
- Never print file contents or credentials.
- Without `--clouds-yaml`, behaviour is unchanged.
- Unit tests cover both cases (`tmp_path` for the file).

**How to test.**
```bash
uv run --frozen ovlm inventory sync --cloud demo --clouds-yaml /does/not/exist.yaml --dry-run; echo "exit=$?"
make test-unit && make lint
```

---

## 5. A bad `OVLM_HTTP__TRUSTED_PROXIES` value gives an opaque error

**Why it matters.** Anyone following the [install guide](install-guide.md) sets this variable. A typo produces
`SettingsError: error parsing value for field "http" from source "EnvSettingsSource"`, which does not say which
variable or which value is wrong. The validator in `HttpSettings` already knows the value that failed.

**Files to touch.**
- `src/ovlm/config/settings.py` (`HttpSettings._parse_networks`)
- `tests/unit/test_config.py` or `tests/unit/test_client_address.py`

**Acceptance criteria.**
- For an invalid entry, the error message names `trusted_proxies` and the offending entry
  (`"not-a-network"`), and says an IPv4/IPv6 address or network is expected.
- Valid values (`"10.9.0.0/24, fd00::1"`, a list, an empty list) behave exactly as before.
- A unit test checks the message for an invalid entry.
- The message does not suggest a wide range such as `0.0.0.0/0` as a fix.

**How to test.**
```bash
OVLM_HTTP__TRUSTED_PROXIES=bogus uv run --frozen python -c "from ovlm.config import Settings; Settings()"
make test-unit && make lint
```
Note: the wrapper error comes from the settings library for values given through the environment. If you cannot
improve that wrapper message, make the `ValueError` text good and show where it appears (for example when
constructing `Settings(http={"trusted_proxies": "bogus"})`). Say in the pull request what you found.

---

## 6. Add `SECURITY.md`

**Why it matters.** The repository has no security policy, so the *Security* tab gives no guidance, and the issue
form links to private vulnerability reporting. The [security model](security-model.md) (section 9) already lists a
`SECURITY.md` as a deliverable. OzarLand has its own policy to follow.

**Files to touch.**
- `SECURITY.md` (new, repository root)
- `README.md` (one link in the Contributing section)

**Acceptance criteria.**
- It states what to report privately: a vulnerability in OVLM, a secret or real hostname published by mistake, an
  unsafe procedure. It says **not** to open a public issue.
- It says how: GitHub private vulnerability reporting (*Report a vulnerability* in the Security tab). No e-mail
  address is invented.
- It says that OVLM is pre-alpha and not lab validated, and that no version is supported for production.
- It links to the [OzarLand security policy](https://github.com/OzarLand/ozarland/blob/main/SECURITY.md) and
  sends upstream OpenStack vulnerabilities to <https://security.openstack.org/>.
- English, short sentences, no placeholders left in.

**How to test.** Open the file in the GitHub preview. Check every link by clicking it. Check that the README link
resolves.

---

## 7. Add an index to `docs/`

**Why it matters.** `docs/` holds about twenty documents, ADRs, reviews and experiments, with no table of contents.
The README links the main ones, but a contributor cannot see what exists, who owns it or how far it is checked.

**Files to touch.** `docs/README.md` (new).

**Acceptance criteria.**
- A table of every top-level file in `docs/` and each of the folders `decisions/`, `experiments/` and `reviews/`,
  with one line on what it is for, grouped (product, design, security, testing, process).
- The status of each document, copied from the document itself. Do not invent a status. If a document does not
  state one, write "not stated".
- Every link is relative and resolves (check with the command below).
- No document is edited.

**How to test.**
```bash
cd docs
grep -o '](\([^)#]*\)' README.md | sed 's/](//' | grep -v '^http' | sort -u | while read -r f; do test -e "$f" || echo "BROKEN: $f"; done
```
No `BROKEN` line should print.

---

## 8. Document the `ovlm` command line

**Why it matters.** The commands exist (`api`, `worker`, `migrate`, `admin create`, `inventory sync`), but the only
mention of most of them is in the README and in code docstrings. A reference page saves a newcomer from reading
`cli.py`.

**Files to touch.** `docs/cli.md` (new), plus one link from `README.md`.

**Acceptance criteria.**
- One section per command with: what it does, who runs it and where (inside the api container, from a checkout),
  every flag **copied from `--help`**, and one example.
- State clearly which commands change state (`migrate`, `admin create`, `inventory sync` without `--dry-run`) with
  the ⚠️ marker, and which are read only.
- State that no command takes a secret on the command line.
- No flag is documented that `--help` does not show.
- No real hostnames, addresses or credentials in examples.

**How to test.**
```bash
uv run --frozen ovlm admin create --help
uv run --frozen ovlm inventory sync --help
```
Compare each flag in your page with this output. Ask a reviewer to run one example.

---

## Maintainer notes (for creating the issues)

- Label: `good first contribution`. Entries 1 and 6 are the smallest; start newcomers there.
- Entry 3 and entry 8 touch the same command line. Do both or do 8 after 3, so the page matches `--help`.
- Entries 2, 4 and 5 each add a test. A pull request without one should be sent back.
- None of these claims a new status. After they are merged, no status in the README changes.
