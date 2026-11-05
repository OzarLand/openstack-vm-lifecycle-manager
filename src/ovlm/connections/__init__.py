"""Clouds, project connections and the OpenStack credential store (data-model.md 2, security-model.md 4.4, 5.1).

* ``service`` and ``api``: the api side. Seal only (worker public key), never decrypt.
* ``credentials`` and ``validation``: the worker side. Decrypt in memory (``ovlm.secrets.keyring``), validate
  credentials against Keystone (read-only token check), re-wrap data keys on KEK rotation.

The import-linter contract "the api cannot decrypt" keeps the two sides apart.
"""
