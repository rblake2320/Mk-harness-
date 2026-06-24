"""Skin analysis: photo upload -> EXIF strip + re-encode -> analysis -> structured
cosmetic-only JSON, validated server-side before storage/return.

Provider hierarchy:
  1. Local PanDerm (port 8101) when SKIN_ANALYSIS_URL is set — medical-grade model,
     zero API cost, image never leaves the machine.
  2. Cloud vision model (Anthropic / OpenAI / Gemini) as fallback.

COMPLIANCE: PanDerm can detect skin cancer. We suppress ALL oncology output —
only cosmetic dimensions (7 scores + undertone + Fitzpatrick) are forwarded.
FDA/FTC line: cosmetic observations only; `see_professional` is the only
safe exit for ambiguous findings.
"""
import base64
import io
import json
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from PIL import Image
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..models import ConsultantProfile, Customer, SkinAnalysis, User
from ..providers.base import ChatMessage, ChatRequest, ImagePart, ProviderError
from ..providers.router import complete_with_failover
from ..ratelimit import check_rate
from ..security import get_current_user
from ..skills import SKIN_ALLOWED_CATEGORIES, SKIN_ANALYSIS_SYSTEM, skin_result_is_compliant

router = APIRouter(prefix="/skin", tags=["skin"])

_ALLOWED_FORMATS = {"JPEG": "image/jpeg", "PNG": "image/png", "WEBP": "image/webp"}

# PanDerm → harness category mapping (cosmetic-safe subset only)
_PANDERM_TO_CATEGORY = {
    "dryness":     ("hydration",       lambda v: 1.0 - v),  # inverse
    "pores":       ("pore_visibility", lambda v: v),
    "fine_lines":  ("fine_lines",      lambda v: v),
    "pigmentation":("tone_evenness",   lambda v: 1.0 - v),  # inverse: high pigment = low evenness
    "blemishes":   ("visible_texture", lambda v: v),
}

_LEVEL = [(0.40, "low"), (0.70, "moderate"), (1.01, "notable")]


def _score_to_level(score: float) -> str:
    for threshold, label in _LEVEL:
        if score <= threshold:
            return label
    return "notable"


def _panderm_to_standard(report: dict) -> dict:
    """Convert PanDerm response to harness standard skin analysis format.

    Only cosmetic fields are forwarded; all oncology / clinical fields are
    silently dropped here and never reach the caller.
    """
    observations = []
    scores = report.get("scores", {})
    for pd_key, (cat, transform) in _PANDERM_TO_CATEGORY.items():
        raw = scores.get(pd_key)
        if raw is None:
            continue
        val = float(transform(raw))
        observations.append({
            "category": cat,
            "level": _score_to_level(val),
            "note": f"Score {val:.2f} from PanDerm analysis.",
        })

    pig = report.get("pigmentation_analysis", {})
    wrk = report.get("wrinkle_analysis", {})
    care_focus = []
    if scores.get("dryness", 0) > 0.5:
        care_focus.append("hydrating cleanser")
    if scores.get("pores", 0) > 0.5:
        care_focus.append("pore-minimizing toner")
    if scores.get("fine_lines", 0) > 0.4:
        care_focus.append("retinol night treatment")
    if pig.get("evenness_score", 1) < 0.6:
        care_focus.append("brightening serum")
    care_focus = care_focus or ["moisturizer", "SPF"]

    am = ["cleanse", "moisturize", "SPF"]
    pm = ["cleanse", "repair serum", "night cream"]
    if scores.get("fine_lines", 0) > 0.4:
        pm.append("retinol treatment")

    talking_points = []
    ut = pig.get("undertone", "")
    if ut:
        talking_points.append(
            f"Your skin has a {ut} undertone — great for finding the right foundation shade."
        )
    sev = wrk.get("severity", "")
    if sev in ("mild", "moderate"):
        talking_points.append("Some early fine lines are visible — a consistent routine now makes a big difference.")
    talking_points = talking_points or ["Your skin has a lovely natural quality."]

    return {
        "observations": observations,
        "care_focus": care_focus,
        "routine_suggestion": {"am": am, "pm": pm},
        "consultant_talking_points": talking_points,
        "see_professional": False,
        "disclaimer": "Cosmetic observations only — not medical advice or a diagnosis.",
    }


def _sanitize_image(raw: bytes, max_mb: int) -> tuple[str, str]:
    """Validate, strip ALL metadata (EXIF/GPS), downscale, re-encode to JPEG."""
    if len(raw) > max_mb * 1024 * 1024:
        raise HTTPException(413, f"Image exceeds {max_mb} MB limit")
    try:
        img = Image.open(io.BytesIO(raw))
        img.verify()
        img = Image.open(io.BytesIO(raw))
    except Exception:
        raise HTTPException(422, "File is not a valid image")
    if img.format not in _ALLOWED_FORMATS:
        raise HTTPException(422, "Use a JPEG, PNG, or WebP photo")
    img = img.convert("RGB")
    img.thumbnail((1568, 1568))
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


async def _call_local_panderm(data_b64: str, actual_age: int | None) -> dict | None:
    """Call the local PanDerm API. Returns cosmetic-safe standard payload or None on any error."""
    url = get_settings().skin_analysis_url
    if not url:
        return None
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.post(
                f"{url.rstrip('/')}/analyze-base64",
                json={"image_base64": data_b64, "actual_age": actual_age, "fast_mode": True},
            )
        if r.status_code != 200 or not r.json().get("success"):
            return None
        report = r.json().get("report", {})
        payload = _panderm_to_standard(report)
        ok, term = skin_result_is_compliant(json.dumps(payload))
        if not ok:
            return None  # compliance gate — discard, fall through to cloud
        # Attach skin profile data (undertone + Fitzpatrick) as a top-level field.
        pig = report.get("pigmentation_analysis", {})
        payload["skin_profile"] = {
            "undertone": pig.get("undertone", ""),
            "fitzpatrick_type": pig.get("fitzpatrick_type"),
            "overall_score": report.get("overall_score"),
            "skin_type": report.get("skin_type", ""),
            "skin_age": report.get("skin_age"),
            "scores": report.get("scores", {}),
        }
        return payload
    except Exception:
        return None  # any failure → fall through to cloud


def _update_skin_profile(db: Session, customer_id: str | None, user_id: str,
                         payload: dict) -> None:
    """Persist undertone + Fitzpatrick to the customer record when available."""
    if not customer_id:
        return
    profile = payload.get("skin_profile", {})
    undertone = profile.get("undertone", "")
    fitz = profile.get("fitzpatrick_type")
    if not undertone and not fitz:
        return
    cust = db.get(Customer, customer_id)
    if not cust or cust.user_id != user_id:
        return
    if undertone:
        cust.skin_undertone = undertone
    if fitz is not None:
        cust.fitzpatrick_type = int(fitz)
    cust.skin_profile_json = json.dumps(profile.get("scores", {}))
    cust.skin_profile_at = datetime.now(timezone.utc)
    db.add(cust)


def _bump_skin_analytics(db: Session, user: User) -> None:
    """Increment skin analysis count on ConsultantProfile (create if absent)."""
    prof = db.scalar(select(ConsultantProfile).where(ConsultantProfile.user_id == user.id))
    if not prof:
        prof = ConsultantProfile(
            user_id=user.id, tenant_id=user.tenant_id,
            skill_usage_json="{}", total_conversations=0,
            total_skin_analyses=0, compliance_flags=0,
        )
        db.add(prof)
        db.flush()
    prof.total_skin_analyses = (prof.total_skin_analyses or 0) + 1
    prof.last_active = datetime.now(timezone.utc)
    prof.updated_at = datetime.now(timezone.utc)


@router.post("/analyze")
async def analyze(
    file: UploadFile = File(...),
    customer_id: str | None = Form(default=None),
    provider: str | None = Form(default=None),
    model: str | None = Form(default=None),
    actual_age: int | None = Form(default=None),
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

    # Try local PanDerm first — better analysis, zero API cost, privacy-preserving.
    local_payload = await _call_local_panderm(data_b64, actual_age)
    if local_payload:
        payload = local_payload
        result_provider, result_model = "panderm_local", "panderm"
    else:
        # Fall back to cloud vision model.
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
        result_provider, result_model = result.provider, result.model

    # Persist skin profile to customer record.
    _update_skin_profile(db, customer_id, user.id, payload)
    _bump_skin_analytics(db, user)

    row = SkinAnalysis(tenant_id=user.tenant_id, user_id=user.id, customer_id=customer_id,
                       result_json=json.dumps(payload), provider=result_provider,
                       model=result_model)
    db.add(row)
    db.commit()
    return {"id": row.id, "provider": result_provider, "model": result_model, "result": payload}


@router.get("/history")
def history(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(SkinAnalysis).where(SkinAnalysis.user_id == user.id)
                      .order_by(SkinAnalysis.created_at.desc()).limit(50))
    return [{"id": r.id, "customer_id": r.customer_id, "created_at": r.created_at.isoformat(),
             "provider": r.provider, "model": r.model,
             "result": json.loads(r.result_json)} for r in rows]
