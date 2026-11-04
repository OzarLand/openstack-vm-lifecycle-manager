"""UI routes. Only the base layout page exists in the foundation."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from ovlm import __version__
from ovlm.ui import TEMPLATE_DIR

templates = Jinja2Templates(directory=str(TEMPLATE_DIR))
router = APIRouter()


@router.get("/", response_class=HTMLResponse, include_in_schema=False)
async def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "index.html", {"version": __version__})


@router.get("/ui/fragments/status", response_class=HTMLResponse, include_in_schema=False)
async def status_fragment(request: Request) -> HTMLResponse:
    """Example HTMX fragment; the run timeline will use the same polling pattern."""
    return templates.TemplateResponse(
        request, "fragments/status.html", {"state": "foundation skeleton"}
    )
