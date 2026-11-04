"""Run inside the api container (``python - < api_checks.py``, by ``make smoke``): no ansible, ssh or git."""

import importlib.util
import os
import shutil
import sys

for module in ("ansible", "ansible_runner", "ansible_collections"):
    assert importlib.util.find_spec(module) is None, f"{module} is installed in the api image"
for binary in ("ansible", "ansible-playbook", "ansible-galaxy", "ansible-runner"):
    assert shutil.which(binary) is None, f"{binary} is on the api image's PATH"
for binary in ("ssh", "ssh-keyscan", "ssh-keygen", "scp", "sftp", "git"):
    assert shutil.which(binary) is None, f"{binary} is on the api image's PATH"
assert not os.path.exists("/opt/ovlm"), "/opt/ovlm (collections) exists in the api image"
sys.stdout.write("api image OK: no ansible, no ssh, no git\n")
