"""Inventory: observed-state tables, sync jobs (worker), `gone` marking (data-model.md section 3).

Layout (the split matters for the import contract: the api may import ``service`` and ``tables``, never ``sync``):

* ``tables``   SQLAlchemy Core definitions of ``sync_run`` and ``observed_*`` (+ ``_revision``)
* ``service``  read queries for the api (no OpenStack import)
* ``sync``     the sync job: plain function, runs in the worker with a ``ReadClient`` (imports ``ovlm.openstack``)
* ``cli``      ``ovlm inventory sync --cloud <name>`` for lab runs

May depend on ``openstack.read``, ``db``, ``audit``; must not use the WriteClient.
"""
