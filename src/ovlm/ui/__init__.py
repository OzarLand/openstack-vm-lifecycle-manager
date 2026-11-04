"""Server-rendered UI: Jinja2 templates + vendored HTMX (ADR-0002). No Node toolchain, no CDN at runtime.

Must not import outbound adapters (``openstack``, ``automation``, ``worker``).
"""

from pathlib import Path

STATIC_DIR = Path(__file__).parent / "static"
TEMPLATE_DIR = Path(__file__).parent / "templates"
