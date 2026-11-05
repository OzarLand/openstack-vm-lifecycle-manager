"""The credential store's cryptography (security-model.md 5.1). Not to be confused with ``ovlm.config.secrets``, which
only reads secret files.

* ``envelope``: the format and the **sealing** side (public key only). Safe in the api.
* ``store``: the ``sealed_secret`` table.
* ``keyring``: the worker's KEK private key(s): unwrap, unseal, re-wrap. **Worker only** (import-linter contract and a
  runtime check).
"""
