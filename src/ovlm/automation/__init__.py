"""Ansible runner integration (E5-3): verified checkout, blocking lint, ansible-runner subprocess as `ovlm-ansible`.

Implements docs/automation-contract.md (round-2 revision) and docs/security-model.md sections 5-6. Must never
receive OpenStack credentials and is never imported by api/ui (import-linter). Entry points:

* :class:`ovlm.automation.runner.AutomationRunner` - ``prepare_automation`` (one verified clone + lint per run)
  and ``run_phase`` (one supervised ansible-runner subprocess per phase attempt);
* :mod:`ovlm.automation.hostkeys` - what the ADR-0006 bootstrap-key step needs (pinning, fingerprints, ssh argv);
* :mod:`ovlm.automation.store` - the restricted artefact store (``automation_run`` table).
"""
