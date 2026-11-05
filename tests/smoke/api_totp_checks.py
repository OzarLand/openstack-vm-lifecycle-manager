"""Run inside the api container (``python - < api_totp_checks.py``, by ``make smoke``): TOTP enrolment would not fail
closed with 503 (lab blocker G). The vault is loaded exactly as the enrolment route loads it
(:func:`ovlm.auth.deps.get_vault`: ``None`` there is the 503 ``totp-unavailable``), then a fresh TOTP secret makes the
round trip through it. Nothing is written to the database and no account is created, so the check is repeatable."""

import sys
from types import SimpleNamespace

from ovlm.auth.deps import get_vault
from ovlm.auth.totp import new_secret
from ovlm.config import Settings

settings = Settings(process_role="api")
assert settings.auth.totp_key_file is not None, "auth.totp_key_file is not set in the api container"
request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(settings=settings)))
vault = get_vault(request)  # type: ignore[arg-type]
assert vault is not None, "the TOTP key does not load: enrolment would answer 503 totp-unavailable"
secret = new_secret()
assert vault.decrypt(vault.encrypt(secret)) == secret
sys.stdout.write("api TOTP OK: the key loads and encrypts, enrolment will not 503\n")
