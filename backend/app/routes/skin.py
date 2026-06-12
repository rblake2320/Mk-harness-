"""Skin analysis: photo upload -> EXIF strip + re-encode -> vision model ->
structured cosmetic-only JSON, validated server-side before storage/return."""
import base64
import io
import json

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from PIL import Image
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..models import Customer, SkinAnalysis, User
from ..providers.base import ChatMessage, ChatRequest, ImagePart, ProviderError
from ..providers.router import complete_with_failover
from ..ratelimit import check_rate
from ..security import get_current_user
from ..skills import SKIN_ALLOWED_CATEGORIES, SKIN_ANALYSIS_SYSTEM, skin_result_is_compliant

router = APIRouter(prefix="/skin", tags=["skin"])

_ALLOWED_FORMATS = {"JPEG": "image/jpeg", "PNG": "image/png", "WEBP": "image/webp"}


def _sanitize_image(raw: bytes, max_mb: int) -> tuple[str, str]:
    """Validate, strip ALL metadata (EXIF/GPS), downscale, re-encode to JPEG.

    Re-encoding through a fresh pixel buffer guarantees no metadata survives
    and neutralizes malformed-container attacks.
    """
    if len(raw) > max_mb * 1024 * 1024:
        raise HTTPException(413, f"Image exceeds {max_mb} MB limit")
    try:
        img = Image.open(io.BytesIO(raw))
        img.verify()
        img = Image.open(io.BytesIO(raw))  # reopen after verify()
    except Exception:
        raise HTTPException(422, "File is not a valid image")
    if img.format not in _ALLOWED_FORMATS:
        raise HTTPException(422, "Use a JPEG, PNG, or WebP photo")
    img = img.convert("RGB")
    img.thumbnail((1568, 1568))  # plenty for skin observation; caps token cost
    clean = Image.new("RGB", img.size)
    clean.putdata(list(img.getdata()))
    buf = io.BytesIO()
    clean.save(buf, format="JPEG", quality=88)
    return base64.b64encode(buf.getvalue()).decode(), "image/jpeg"


def _parse_and_validate(text: str) -> dict:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        if cleaned.startswith("json"):
            cleaned = cleaned[4:]
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        raise HTTPException(502, "Model returned malformed analysis. Try again or switch model.")
    ok, term = skin_result_is_compliant(json.dumps(data))
    if not ok:
        raise HTTPException(502, "Analysis failed compliance review and was discarded. Try again.")
    obs = data.get("observations")
    if not isinstance(obs, list) or not obs:
        raise HTTPException(502, "Analysis missing observations. Try again.")
    data["observations"] = [o for o in obs
                            if isinstance(o, dict) and o.get("category") in SKIN_ALLOWED_CATEGORIES]
    data["disclaimer"] = "Cosmetic observations only — not medical advice or a diagnosis."
    data.setdefault("see_professional", False)
    return data


@router.post("/analyze")
async def analyze(
    file: UploadFile = File(...),
    customer_id: str | None = Form(default=None),
    provider: str | None = Form(default=None),
    model: str | None = Form(default=None),
    user: User = Depends(check_rate),
    db: Session = Depends(get_db),
):
    s = get_settings()
    raw = await file.read()
    data_b64, media_type = _sanitize_image(raw, s.max_upload_mb)

    if customer_id:
        cust = db.get(Customer, customer_id)
        if not cust or cust.user_id != user.id:
            raise HTTPException(404, "Customer not found")

    req = ChatRequest(
        messages=[ChatMessage(role="user",
                              content="Analyze this face photo per your instructions.",
                              images=[ImagePart(media_type=media_type, data_b64=data_b64)])],
        system=SKIN_ANALYSIS_SYSTEM, model=model or "", max_tokens=1200,
        temperature=0.2, json_mode=True,
    )
    try:
        result = await complete_with_failover(db, user, req, provider=provider, kind="vision")
    except ProviderError as e:
        raise HTTPException(502, f"Vision analysis failed: {e}")

    payload = _parse_and_validate(result.text)
    row = SkinAnalysis(tenant_id=user.tenant_id, user_id=user.id, customer_id=customer_id,
                       result_json=json.dumps(payload), provider=result.provider,
                       model=result.model)
    db.add(row)
    db.commit()
    return {"id": row.id, "provider": result.provider, "model": result.model, "result": payload}


@router.get("/history")
def history(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(SkinAnalysis).where(SkinAnalysis.user_id == user.id)
                      .order_by(SkinAnalysis.created_at.desc()).limit(50))
    return [{"id": r.id, "customer_id": r.customer_id, "created_at": r.created_at.isoformat(),
             "provider": r.provider, "model": r.model,
             "result": json.loads(r.result_json)} for r in rows]
