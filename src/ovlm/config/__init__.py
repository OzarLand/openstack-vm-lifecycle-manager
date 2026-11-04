"""Typed settings (architecture.md section 5).

Sources, highest priority first: constructor arguments, environment ``OVLM_<SECTION>__<KEY>``, the TOML file
``$OVLM_CONFIG_FILE`` (default ``/etc/ovlm/ovlm.toml``). Unknown keys are errors. Secrets are *not* settings:
a setting holds the path of a secret file (``*_file``) which is read on demand by ``read_secret_file``.

This module imports no other ``ovlm`` module.
"""

from ovlm.config.secrets import SecretFileError, read_secret_file
from ovlm.config.settings import ProcessRole, Settings

__all__ = ["ProcessRole", "SecretFileError", "Settings", "read_secret_file"]
