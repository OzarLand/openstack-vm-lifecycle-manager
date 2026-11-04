"""Services and managed VMs; registration links an observed server to a managed VM (data-model.md section 4).

* ``tables``  SQLAlchemy Core tables (module-private)
* ``service`` public functions used by the api: services, registration, managed VMs
* ``errors``  ``DomainError`` (status, stable ``code``, ``next_action``) mapped to problem+json by the api

May depend on ``inventory`` (read service), ``db``, ``audit``. Never imports ``ovlm.openstack``.
"""
