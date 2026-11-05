"""Blocking static lint (contract sections 5, 9; SEC-R-3, SEC-R-35)."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from ovlm.automation import lint as lint_mod
from ovlm.automation.lint import (
    StaticWaivers,
    Waiver,
    check_requirements_pinned,
    lint_repo,
)

ROOT = Path(__file__).parents[3]


def play(tasks: str, *, hosts: str = "ovlm_target", extra: str = "") -> str:
    body = "\n".join("      " + line for line in tasks.strip().splitlines())
    return f"- hosts: {hosts}\n  gather_facts: false\n{extra}  tasks:\n{body}\n"


def repo(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return tmp_path


def rules(tmp_path: Path, files: dict[str, str], **kw: object) -> set[str]:
    return {f.rule for f in lint_repo(repo(tmp_path, files), "playbooks", **kw).blocking}  # type: ignore[arg-type]


def one(phase: str, tasks: str, **kw: str) -> dict[str, str]:
    return {f"playbooks/{phase}.yml": play(tasks, **kw)}


def test_reference_workload_is_clean_without_waivers() -> None:
    # Its check_mode: false tasks are all read-only probes (allowlisted modules or programs, changed_when: false).
    res = lint_repo(ROOT / "ansible", "playbooks")
    assert res.ok and not res.findings, res.findings


def test_clean_playbook_passes(tmp_path: Path) -> None:
    assert (
        rules(tmp_path, one("configure", "- name: pkg\n  ansible.builtin.apt: {name: nginx}"))
        == set()
    )


@pytest.mark.parametrize(
    "task",
    [
        "- ansible.builtin.copy: {dest: /etc/x, content: y, password: abc}",
        "- ansible.builtin.uri: {url: 'https://x', headers: {Authorization: 'Bearer {{ api_token }}'}}",
        "- ansible.builtin.command: echo {{ vault_db_password }}",
        "- ansible.builtin.set_fact: {private_key: '{{ k }}'}",
        '- ansible.builtin.copy: {dest: /x, content: \'{{ lookup("vault", "x") }}\'}',
        "- ansible.builtin.debug: {msg: x}\n  vars: {db_secret: abc}",
        "- ansible.builtin.copy: {dest: /x, content: '{{ some.apiKey }}'}",
    ],
)
def test_no_log_is_required_on_secret_like_tasks(tmp_path: Path, task: str) -> None:
    assert "no_log_secret" in rules(tmp_path, one("configure", task)), task


@pytest.mark.parametrize(
    "task",
    [
        "- ansible.builtin.copy: {dest: /x, content: y, password: abc}\n  no_log: true",
        "- block:\n    - ansible.builtin.copy: {dest: /x, content: '{{ db_password }}'}\n  no_log: true",
        "- ansible.builtin.apt: {name: '{{ item.key }}'}\n  loop: '{{ pkgs | dict2items }}'",  # attribute, not a secret
        "- ansible.posix.authorized_key: {user: ovlm, key: x, public_key: y}\n  no_log: true",
        "- ansible.builtin.copy: {dest: /x, content: '{{ keyboard_layout }}'}",
        "- ansible.builtin.stat: {path: /etc/ssl/key_file_path}",
    ],
)
def test_no_log_not_demanded_when_present_or_not_secret(tmp_path: Path, task: str) -> None:
    assert "no_log_secret" not in rules(tmp_path, one("configure", task)), task


def test_play_level_no_log_covers_its_tasks(tmp_path: Path) -> None:
    files = one(
        "configure",
        "- ansible.builtin.copy: {dest: /x, content: '{{ db_password }}'}",
        extra="  no_log: true\n",
    )
    assert "no_log_secret" not in rules(tmp_path, files)


def test_no_log_expression_is_not_proof(tmp_path: Path) -> None:
    task = (
        "- ansible.builtin.copy: {dest: /x, content: '{{ db_password }}'}\n  no_log: '{{ maybe }}'"
    )
    assert "no_log_secret" in rules(tmp_path, one("configure", task))


@pytest.mark.parametrize(
    "hosts", ["all", "localhost", "ovlm_target:&web", "{{ target }}", "ovlm_target,other"]
)
def test_hosts_must_be_ovlm_target(tmp_path: Path, hosts: str) -> None:
    assert "hosts_pattern" in rules(
        tmp_path, one("configure", "- ansible.builtin.ping:", hosts=f"'{hosts}'")
    )


def test_check_mode_forcing_is_blocked(tmp_path: Path) -> None:
    for task in ("- ansible.builtin.command: id\n  check_mode: false", "- ansible.builtin.command: id\n  check_mode: no",
                 "- ansible.builtin.command: id\n  always_run: true"):  # fmt: skip
        assert "check_mode_forced" in rules(tmp_path / str(hash(task)), one("healthcheck", task)), (
            task
        )
    assert "check_mode_forced" not in rules(
        tmp_path / "ok", one("healthcheck", "- ansible.builtin.command: id\n  check_mode: true")
    )


def test_delegate_to_in_configure_only(tmp_path: Path) -> None:
    task = "- ansible.builtin.command: id\n  delegate_to: bastion"
    assert "delegate_to" in rules(tmp_path / "a", one("configure", task))
    assert "delegate_to" in rules(
        tmp_path / "b",
        one("configure", "- ansible.builtin.command: id\n  local_action: command id"),
    )
    assert "delegate_to" not in rules(
        tmp_path / "c", one("healthcheck", task)
    )  # contract: configure.yml only
    assert "delegate_to" in rules(
        tmp_path / "d", one("configure", "- ansible.builtin.ping:", extra="  connection: local\n")
    )


def test_result_writer_is_the_one_exempt_pattern(tmp_path: Path) -> None:
    writer = "- ansible.builtin.copy: {dest: '{{ ovlm_result_path }}', content: x}\n  delegate_to: localhost\n  check_mode: false"
    assert rules(tmp_path / "a", one("configure", writer)) == set()
    evil = writer.replace("{{ ovlm_result_path }}", "/etc/cron.d/x")
    assert {"delegate_to", "check_mode_forced"} <= rules(tmp_path / "b", one("configure", evil))
    remote = writer.replace("localhost", "bastion")
    assert "delegate_to" in rules(tmp_path / "c", one("configure", remote))


@pytest.mark.parametrize(
    "task",
    [
        "- ansible.builtin.command: mkfs.ext4 /dev/vdb",
        "- ansible.builtin.shell: wipefs -a /dev/vdb",
        "- ansible.builtin.command: dd if=/dev/zero of=/dev/vdb",
        "- community.general.filesystem: {dev: /dev/vdb, fstype: ext4}",
        "- community.general.parted: {device: /dev/vdb, number: 1, state: present}",
        "- ansible.builtin.command: sgdisk --zap-all /dev/vdb",
    ],
)
def test_formatting_is_blocked(tmp_path: Path, task: str) -> None:
    assert "formatting" in rules(tmp_path, one("data_attach", task)), task


def test_ignore_errors_on_data_phases(tmp_path: Path) -> None:
    task = "- ansible.builtin.command: id\n  ignore_errors: true"
    assert "ignore_errors" in rules(tmp_path / "a", one("data_attach", task))
    assert "ignore_errors" in rules(tmp_path / "b", one("quiesce", task))
    res = lint_repo(repo(tmp_path / "c", one("configure", task)), "playbooks")
    assert res.ok and any(
        f.rule == "ignore_errors" and f.severity == "warning" for f in res.findings
    )


def test_ssh_overrides_and_agent_forwarding(tmp_path: Path) -> None:
    cases = {
        "a": one("configure", "- ansible.builtin.ping:", extra="  vars: {ansible_ssh_common_args: '-o StrictHostKeyChecking=no'}\n"),
        "b": one("configure", "- ansible.builtin.set_fact: {ansible_host: 10.0.0.9}"),
        "c": one("configure", "- ansible.builtin.command: ssh -A host id"),
        "d": one("configure", "- ansible.builtin.add_host: {name: other, groups: ovlm_target}"),
        "e": {**one("configure", "- ansible.builtin.ping:"), "playbooks/group_vars/all.yml": "ansible_connection: local\n"},
        "f": one("configure", "- ansible.builtin.ping:\n  vars: {ansible_user: root}"),
    }  # fmt: skip
    for name, files in cases.items():
        assert "ssh_override" in rules(tmp_path / name, files), name


def test_quiesce_must_not_edit_fstab_or_disable_units(tmp_path: Path) -> None:
    cases = [
        "- ansible.builtin.lineinfile: {path: /etc/fstab, regexp: x, state: absent}",
        "- ansible.posix.mount: {path: /srv/data, state: absent}",
        "- ansible.builtin.systemd: {name: app, enabled: false}",
    ]
    for i, task in enumerate(cases):
        assert "quiesce_state" in rules(tmp_path / str(i), one("quiesce", task)), task
    assert "quiesce_state" not in rules(
        tmp_path / "ok",
        one("quiesce", "- ansible.posix.mount: {path: /srv/data, state: unmounted}"),
    )


def test_roles_and_includes_are_followed_statically(tmp_path: Path) -> None:
    files = {
        **one("data_attach", "- ansible.builtin.include_role: {name: vol}"),
        "roles/vol/tasks/main.yml": "- ansible.builtin.import_tasks: more.yml\n",
        "roles/vol/tasks/more.yml": "- ansible.builtin.command: mkfs.ext4 /dev/vdb\n",
    }
    res = lint_repo(repo(tmp_path, files), "playbooks")
    assert [(f.rule, f.path) for f in res.blocking] == [("formatting", "roles/vol/tasks/more.yml")]


def test_unresolvable_includes_are_warnings_not_silence(tmp_path: Path) -> None:
    res = lint_repo(
        repo(tmp_path, one("configure", "- ansible.builtin.include_role: {name: '{{ r }}'}")),
        "playbooks",
    )
    assert res.ok and any(f.rule == "unresolved_include" for f in res.findings)


def test_waiver_is_per_rule_and_path_and_calls_the_audit_hook(tmp_path: Path) -> None:
    files = {
        **one("configure", "- ansible.builtin.include_role: {name: r}"),
        "roles/r/tasks/main.yml": "- ansible.builtin.command: id\n  check_mode: false\n",
    }
    applied: list[tuple[str, str]] = []
    w = StaticWaivers((Waiver("wv-1", "check_mode_forced", "roles/r/*", "approver-1", "probe"),))
    res = lint_repo(
        repo(tmp_path / "a", files),
        "playbooks",
        waivers=w,
        on_waiver=lambda f, wv: applied.append((wv.id, f.rule)),
    )
    assert (
        res.ok and applied == [("wv-1", "check_mode_forced")] and res.waived[0].waived_by == "wv-1"
    )
    other_rule = StaticWaivers((Waiver("wv-2", "no_log_secret", "*", "a", "r"),))
    assert not lint_repo(repo(tmp_path / "b", files), "playbooks", waivers=other_rule).ok
    other_path = StaticWaivers((Waiver("wv-3", "check_mode_forced", "roles/other/*", "a", "r"),))
    assert not lint_repo(repo(tmp_path / "c", files), "playbooks", waivers=other_path).ok


def test_warnings_cannot_be_waived_into_silence_and_hook_not_called(tmp_path: Path) -> None:
    called: list[object] = []
    w = StaticWaivers((Waiver("w", "templated_task_name", "*", "a", "r"),))
    res = lint_repo(
        repo(tmp_path, one("configure", "- name: 'x {{ y }}'\n  ansible.builtin.ping:")),
        "playbooks",
        waivers=w,
        on_waiver=lambda *a: called.append(a),
    )
    assert not called and any(f.rule == "templated_task_name" for f in res.findings)


# ---- hostile input to the linter itself (static analysis must not execute anything) -----------------------


def test_python_yaml_tags_are_not_executed(tmp_path: Path) -> None:
    marker = tmp_path / "pwned"
    evil = f"- !!python/object/apply:os.system ['touch {marker}']\n"
    res = lint_repo(repo(tmp_path / "r", {"playbooks/configure.yml": evil}), "playbooks")
    assert not marker.exists()
    assert any(f.rule == "parse_error" for f in res.blocking)


def test_vault_and_unsafe_tags_load_as_text(tmp_path: Path) -> None:
    files = one(
        "configure",
        "- ansible.builtin.copy:\n    dest: /x\n    content: !vault |\n      $ANSIBLE_VAULT;1.1;AES256\n      6162\n  no_log: true",
    )
    assert lint_repo(repo(tmp_path, files), "playbooks").ok


def test_alias_bomb_is_bounded(tmp_path: Path) -> None:
    lines = ["a: &a [x,x,x,x,x,x,x,x,x]"]
    prev = "a"
    for i in range(1, 12):
        lines.append(
            f"{chr(97 + i)}: &{chr(97 + i)} [*{prev},*{prev},*{prev},*{prev},*{prev},*{prev},*{prev},*{prev},*{prev}]"
        )
        prev = chr(97 + i)
    content = (
        "- hosts: ovlm_target\n  vars:\n"
        + "\n".join("    " + line for line in lines)
        + "\n  tasks:\n    - ansible.builtin.ping:\n"
    )
    start = time.monotonic()
    res = lint_repo(repo(tmp_path, {"playbooks/configure.yml": content}), "playbooks")
    assert time.monotonic() - start < 10 and res is not None


def test_oversized_file_and_symlink_are_not_followed(tmp_path: Path) -> None:
    big = "# " + "x" * (lint_mod.MAX_YAML_BYTES + 10) + "\n- hosts: ovlm_target\n"
    res = lint_repo(repo(tmp_path / "a", {"playbooks/configure.yml": big}), "playbooks")
    assert any(f.rule == "parse_error" for f in res.blocking)
    outside = tmp_path / "outside.yml"
    outside.write_text("- hosts: all\n")
    r = repo(tmp_path / "b", {"playbooks/healthcheck.yml": play("- ansible.builtin.ping:")})
    (r / "playbooks" / "configure.yml").symlink_to(outside)
    assert lint_repo(r, "playbooks").ok  # the symlinked "playbook" is ignored, not read


def test_playbook_dir_cannot_escape(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        lint_repo(tmp_path, "../..")


# ---- requirements pins -----------------------------------------------------------------------------------


def test_requirements_pins(tmp_path: Path) -> None:
    def chk(text: str) -> list[str]:
        p = tmp_path / "requirements.yml"
        p.write_text(text)
        return check_requirements_pinned(p)

    assert chk("collections:\n  - name: ansible.posix\n    version: 2.2.2\n") == []
    assert chk("collections:\n  - name: ansible.posix\n") != []
    assert chk("collections:\n  - name: ansible.posix\n    version: '>=2.0.0'\n") != []
    assert chk("collections:\n  - ansible.posix\n") != []
    assert chk("roles:\n  - src: https://x/r.git\n    version: main\n") != []
    assert chk(f"roles:\n  - src: https://x/r.git\n    version: {'a' * 40}\n") == []
    assert chk("roles:\n  - name: geerlingguy.nginx\n    version: latest\n") != []
    assert check_requirements_pinned(tmp_path / "missing.yml") == []


# ---- roles next to the playbook directory (ansible/playbooks + ansible/roles) ---------------------------


def test_the_reference_workload_lints_in_its_real_layout() -> None:
    repo = Path(__file__).resolve().parents[3]
    result = lint_repo(repo, "ansible/playbooks")
    unresolved = [f for f in result.findings if f.rule == "unresolved_include"]
    assert not unresolved, unresolved
    assert result.ok, result.findings


def test_sibling_roles_dir_is_found_and_stays_inside_the_repo(tmp_path: Path) -> None:
    pb = tmp_path / "ansible" / "playbooks"
    pb.mkdir(parents=True)
    (tmp_path / "ansible" / "roles" / "app" / "tasks").mkdir(parents=True)
    (tmp_path / "ansible" / "roles" / "app" / "tasks" / "main.yml").write_text(
        "- ansible.builtin.debug:\n    msg: hi\n"
    )
    linter = lint_mod._Linter(tmp_path, "ansible/playbooks", None, None)  # noqa: SLF001
    assert linter.role_dirs("app") == [tmp_path.resolve() / "ansible" / "roles" / "app"]
    top = lint_mod._Linter(tmp_path, "playbooks", None, None)  # noqa: SLF001
    assert top.role_dirs("app") == []  # the repository root's parent is never searched


@pytest.mark.parametrize(
    "task",
    [
        "- ansible.builtin.command: mountpoint -q /srv/data\n  changed_when: false\n  check_mode: false",
        "- ansible.builtin.command: {argv: [findmnt, -n, /srv/data]}\n  changed_when: false\n  check_mode: false",
        "- ansible.builtin.command: e2fsck -n /dev/vdb\n  changed_when: false\n  check_mode: false",
        "- ansible.builtin.command: start-stop-daemon --status --pidfile /run/x.pid\n  changed_when: false\n  check_mode: false",
        "- ansible.builtin.stat: {path: /srv/data}\n  check_mode: false",
        "- ansible.builtin.uri: {url: 'http://127.0.0.1:8080/health'}\n  check_mode: false",
        "- ansible.builtin.wait_for: {port: 8080}\n  check_mode: false",
    ],
)
def test_read_only_probes_may_force_check_mode(tmp_path: Path, task: str) -> None:
    assert "check_mode_forced" not in rules(tmp_path, one("configure", task))


@pytest.mark.parametrize(
    "task",
    [
        # not provably read-only: shell, an unlisted program, a templated program, a repair flag, a write method
        "- ansible.builtin.shell: mountpoint -q /srv/data\n  changed_when: false\n  check_mode: false",
        "- ansible.builtin.command: rm -rf /srv/data\n  changed_when: false\n  check_mode: false",
        "- ansible.builtin.command: '{{ prog }} /srv/data'\n  changed_when: false\n  check_mode: false",
        "- ansible.builtin.command: e2fsck -n -y /dev/vdb\n  changed_when: false\n  check_mode: false",
        "- ansible.builtin.command: e2fsck -p /dev/vdb\n  changed_when: false\n  check_mode: false",
        "- ansible.builtin.command: start-stop-daemon --stop --pidfile /run/x.pid\n  changed_when: false\n  check_mode: false",
        "- ansible.builtin.command: mountpoint -q /srv/data\n  check_mode: false",  # changed_when missing
        "- ansible.builtin.command: mountpoint -q /srv/data\n  changed_when: false\n  always_run: true",
        "- ansible.builtin.uri: {url: 'http://x/', method: POST}\n  check_mode: false",
        "- ansible.builtin.uri: {url: 'http://x/', dest: /etc/passwd}\n  check_mode: false",
        "- community.general.anything: {}\n  check_mode: false",
        "- block:\n    - ansible.builtin.stat: {path: /x}\n  check_mode: false",  # block-level forcing
    ],
)
def test_anything_else_that_forces_check_mode_stays_blocked(tmp_path: Path, task: str) -> None:
    assert "check_mode_forced" in rules(tmp_path, one("configure", task))
