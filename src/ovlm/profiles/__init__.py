"""Profiles (desired state of a service's VM) and their immutable versions (data-model.md section 5).

Depends on ``db`` and ``audit`` only (architecture.md section 3). The api inserts versions and never changes them
(SEC-R-36); the image is stored as a match rule and resolved at plan time, never as "latest".
"""
