"""Authentication, sessions, API tokens, TOTP, step-up, role bindings (security-model.md sections 2 and 3).

E3-1: who you are and which role bindings you hold. E3-2: the RBAC matrix and project scoping
(:mod:`ovlm.auth.authz`, :func:`ovlm.auth.deps.require_action`, :func:`ovlm.auth.deps.ensure_scope`), separation of
duties and approval-evidence re-validation (:mod:`ovlm.auth.sod`), installation settings
(:mod:`ovlm.auth.installation`). May depend on ``db``, ``audit``, ``config`` and ``observability``; never calls
OpenStack.
"""
