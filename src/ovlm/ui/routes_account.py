"""Step-up re-authentication page: the human face of ``POST /api/v1/session/reauth`` (same service call).

The result is a single-use ``stepup_id`` bound to one action and one target. The approval and typed-confirmation
pages (E6-3) embed this form; the page also works on its own, with ``?action=...&target_id=...``.
"""

from __future__ import annotations

from typing import Annotated, Any

from argon2 import PasswordHasher
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ovlm.auth import login as login_svc
from ovlm.auth.deps import current_principal as _me
from ovlm.auth.deps import get_db, get_hasher, get_settings, get_vault
from ovlm.auth.principal import Principal
from ovlm.auth.totp import TotpUnavailableError, TotpVault
from ovlm.config import Settings
from ovlm.ui.support import UiRoute, error_page, render

router = APIRouter(route_class=UiRoute, include_in_schema=False)
Me = Annotated[Principal, Depends(_me)]
Db = Annotated[Session, Depends(get_db)]
Cfg = Annotated[Settings, Depends(get_settings)]
Hasher = Annotated[PasswordHasher, Depends(get_hasher)]
Vault = Annotated[TotpVault | None, Depends(get_vault)]


def _page(request: Request, status: int = 200, **ctx: Any) -> HTMLResponse:
    base: dict[str, Any] = {"action": "", "target_id": "", "error": None, "issued": None}
    return render(request, "account/stepup.html", status, **{**base, **ctx})


@router.get("/account/stepup", response_class=HTMLResponse)
def stepup_page(request: Request, who: Me, action: str = "", target_id: str = "") -> HTMLResponse:
    return _page(request, action=action, target_id=target_id)


@router.post("/account/stepup", response_class=HTMLResponse)
def stepup_submit(
    request: Request, db: Db, settings: Cfg, hasher: Hasher, vault: Vault, who: Me,
    password: Annotated[str, Form()], action: Annotated[str, Form()],
    target_id: Annotated[str, Form()], totp_code: Annotated[str, Form()] = "",
) -> HTMLResponse:  # fmt: skip
    if not who.is_human:
        return error_page(request, 403, "Forbidden", "Step-up needs an interactive human session.")
    if not (action.strip() and target_id.strip()) or len(action) > 100 or len(target_id) > 200:
        return _page(
            request,
            422,
            action=action,
            target_id=target_id,
            error="Action and target are required.",
        )
    try:
        step = login_svc.reauth(
            db, settings, hasher, vault, who, password=password, totp_code=totp_code or None,
            action=action.strip(), target_id=target_id.strip(),
        )  # fmt: skip
    except login_svc.TotpFlowError as exc:
        return _page(request, 403, action=action, target_id=target_id, error=str(exc))
    except login_svc.RateLimitedError as exc:
        return _page(request, 429, action=action, target_id=target_id,
                     error=f"Too many failed attempts. Retry in {exc.retry_after} seconds.")  # fmt: skip
    except (login_svc.AuthFailedError, TotpUnavailableError):
        return _page(
            request, 401, action=action, target_id=target_id, error="Invalid password or code."
        )
    return _page(request, action=action, target_id=target_id, issued=step)
