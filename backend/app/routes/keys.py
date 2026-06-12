"""Provider key management. Keys are AES-GCM encrypted at rest and never
returned after creation (only a masked hint)."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..crypto import encrypt_secret, key_aad
from ..db import get_db
from ..models import AuditLog, ProviderKey, Tenant, User
from ..providers.router import ADAPTERS, _env_key
from ..security import get_current_user, require_admin

router = APIRouter(prefix="/keys", tags=["keys"])


class KeyIn(BaseModel):
    provider: str
    api_key: str = Field(min_length=1, max_length=500)
    base_url: str = ""


def _validate_provider(p: str):
    if p not in ADAPTERS:
        raise HTTPException(422, f"provider must be one of {sorted(ADAPTERS)}")


def _upsert(db: Session, tenant_id: str, user_id: str | None, body: KeyIn, scope: str):
    s = get_settings()
    row = db.scalar(select(ProviderKey).where(
        ProviderKey.tenant_id == tenant_id,
        ProviderKey.user_id == user_id if user_id else ProviderKey.user_id.is_(None),
        ProviderKey.provider == body.provider))
    ct = encrypt_secret(s.master_key_bytes, body.api_key,
                        key_aad(tenant_id, user_id, body.provider))
    if row:
        row.ciphertext, row.base_url = ct, body.base_url
    else:
        db.add(ProviderKey(tenant_id=tenant_id, user_id=user_id, provider=body.provider,
                           scope=scope, ciphertext=ct, base_url=body.base_url))
    db.commit()


@router.put("/mine")
def set_my_key(body: KeyIn, user: User = Depends(get_current_user),
               db: Session = Depends(get_db)):
    _validate_provider(body.provider)
    tenant = db.get(Tenant, user.tenant_id)
    if tenant.key_policy == "central":
        raise HTTPException(403, "Your team uses company-managed keys only.")
    _upsert(db, user.tenant_id, user.id, body, "user")
    db.add(AuditLog(tenant_id=user.tenant_id, user_id=user.id,
                    action="key.set", detail=f"user:{body.provider}"))
    db.commit()
    return {"ok": True, "provider": body.provider, "scope": "user"}


@router.put("/tenant")
def set_tenant_key(body: KeyIn, admin: User = Depends(require_admin),
                   db: Session = Depends(get_db)):
    _validate_provider(body.provider)
    _upsert(db, admin.tenant_id, None, body, "tenant")
    db.add(AuditLog(tenant_id=admin.tenant_id, user_id=admin.id,
                    action="key.set", detail=f"tenant:{body.provider}"))
    db.commit()
    return {"ok": True, "provider": body.provider, "scope": "tenant"}


@router.get("/status")
def key_status(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Which providers are usable right now, and via which scope."""
    tenant = db.get(Tenant, user.tenant_id)
    out = {}
    for p in ADAPTERS:
        mine = db.scalar(select(ProviderKey).where(
            ProviderKey.tenant_id == user.tenant_id, ProviderKey.user_id == user.id,
            ProviderKey.provider == p)) is not None
        central = db.scalar(select(ProviderKey).where(
            ProviderKey.tenant_id == user.tenant_id, ProviderKey.user_id.is_(None),
            ProviderKey.provider == p)) is not None or bool(_env_key(p))
        usable = (mine and tenant.key_policy in ("byo", "both")) or \
                 (central and tenant.key_policy in ("central", "both")) or p == "ollama"
        out[p] = {"byo_key_set": mine, "central_available": central, "usable": usable}
    return {"key_policy": tenant.key_policy, "providers": out}


@router.delete("/mine/{provider}")
def delete_my_key(provider: str, user: User = Depends(get_current_user),
                  db: Session = Depends(get_db)):
    _validate_provider(provider)
    row = db.scalar(select(ProviderKey).where(
        ProviderKey.tenant_id == user.tenant_id, ProviderKey.user_id == user.id,
        ProviderKey.provider == provider))
    if not row:
        raise HTTPException(404, "No key stored for that provider")
    db.delete(row)
    db.commit()
    return {"ok": True}
