"""Rebuild readiness (FR-RDY, backlog E4-1 and E4-2): named, versioned checks and explicit, explainable level rules.

Layout (the import contract matters: the api and ui may import ``service``, ``model``, ``levels``, ``checks``,
``tables`` and ``snapshot``; only the worker imports ``job``):

* ``model``     result, severity and category vocabulary; the ``Check`` shape; no I/O
* ``levels``    the FR-RDY-3 rules and the orientation-only count summary; no I/O
* ``snapshot``  the input snapshot (plain JSON the checks read) and the loader that builds it from the DB inventory
* ``checks``    the MVP checks (E4-2); each is a pure function of the snapshot, so a stored assessment can be re-derived
* ``runner``    runs every check, isolates a crashing check as ``unknown``, derives the level
* ``tables``    SQLAlchemy Core definitions of ``readiness_assessment``, ``check_result``, ``attestation``
* ``service``   api side: request an assessment (a ``workflow_run`` in ``requested``), read results, the catalogue
* ``job``       worker side: the ``readiness`` workflow definition (one step)

An assessment runs no repository code on the live VM (SEC-R-28): checks that need it report ``unknown``.
"""
