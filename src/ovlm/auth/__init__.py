"""Authentication, sessions, API tokens, TOTP, step-up, role bindings (security-model.md sections 2 and 3).

E3-1 scope: who you are and which role bindings you hold. The RBAC matrix, requester sets and separation of duties
are E3-2: they plug in at :func:`ovlm.auth.authz.authorize`, the single decision point behind
:func:`ovlm.auth.deps.require_role`. May depend on ``db``, ``audit``, ``config`` and ``observability``; never calls
OpenStack.
"""
