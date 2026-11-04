"""Strategy ``bluegreen_fip_v1`` (E5-4, E5-5): steps B1-B9, G2, W1-W10, R1/R2/G3/X1, S1-S10, Discarding; approval
gates and evidence re-validation; the closed automatic-restore table with D-1 = B.

Layout: ``config`` (named keys, no invented defaults), ``tables``, ``plans`` (resolution, plan hash, TC),
``evidence`` (worker re-validation of G1-G3) - these four are api-safe and import nothing from ``openstack`` or
``automation``. Worker only: ``ports``, ``ledger``, ``base``, ``steps_build``, ``steps_window``, ``steps_after``,
``closed_table``, ``definition``, ``reprobe``, ``metrics``, ``production`` (the ports' production adapters,
wired into the worker by ``ovlm.worker.main.build_registry``). Importing this package imports nothing.
"""
