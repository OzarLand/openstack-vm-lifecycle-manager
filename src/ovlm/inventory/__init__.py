"""Inventory: observed-state tables, sync jobs (worker), `gone` marking (data-model.md section 3).

Layout (the split matters for the import contract: the api may import ``service`` and ``tables``, never ``sync``):

* ``tables``   SQLAlchemy Core definitions of ``sync_run`` and ``observed_*`` (+ ``_revision``)
* ``service``  read queries for the api (no OpenStack import)
* ``sync``     the sync job: plain function, runs in the worker with a ``ReadClient`` (imports ``ovlm.openstack``)
* ``requests`` queue a sync (``workflow_run`` in ``requested``): the api and the periodic job (no OpenStack import)
* ``job``      the ``inventory_sync`` workflow: the project's read credential from the store, then ``sync``
* ``cli``      ``ovlm inventory sync --cloud <name> --dry-run``: read-only check from ``clouds.yaml``

May depend on ``openstack.read``, ``db``, ``audit``; must not use the WriteClient.
"""
