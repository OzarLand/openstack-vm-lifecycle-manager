"""Run inside the api container (``python - < api_kek_checks.py``, by ``make smoke``): the api can seal with the
worker's public key, holds no private key, and refuses to load one (security-model.md 5.1, 10 item 13)."""

import os
import sys
from pathlib import Path

from ovlm.secrets.envelope import SealContext, load_public_key
from ovlm.secrets.keyring import KeyringError, load_keyring

pub = load_public_key(Path(os.environ["OVLM_KEK__PUBLIC_KEY_FILE"]))
sealed = pub.seal(b"smoke-canary", SealContext("credential_ref", "smoke", "secret"))
assert b"smoke-canary" not in sealed.ciphertext
assert not Path("/run/secrets/worker_kek").exists(), "the KEK private key is mounted into the api"
try:
    load_keyring(Path("/run/secrets/worker_kek_pub"), process_role="api")
except KeyringError:
    pass
else:
    raise AssertionError("the api loaded a key ring")
sys.stdout.write(f"api KEK OK: seals to {pub.kek_id}, holds no private key\n")
