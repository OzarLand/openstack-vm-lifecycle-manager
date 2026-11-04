"""Policies, bindings, effective-policy resolution, deadlines and windows, exceptions (data-model.md section 6).

May depend on ``registry``, ``db`` and ``audit``. The pure parts (``durations``, ``windows``, ``resolve``, ``deadline``)
import nothing from the database and carry the rules that the unit tests pin down.
"""
