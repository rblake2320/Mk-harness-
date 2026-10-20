"""Bounded drafting with controlled product claims (WP05, rows P1–P3).

Two kinds of content, kept apart by construction:
* **relationship language** — greeting, acknowledgment, references to confirmed customer
  context (the commitment text, the customer's first name). The model writes this.
* **controlled product claims** — only `ApprovedClaim.approved_text` rows that are
  approved, in market, effective and unexpired. The model may *select* claim ids from
  the candidate list it was shown; it cannot write, edit, strengthen or paraphrase one.

The assembled draft = relationship text with `{claim:<id>}` placeholders replaced by the
exact approved text. Any model output that contains text resembling a product claim
outside a placeholder is rejected (the draft is not produced; a review task is created).

No model output can change tenant/customer, grant consent, clear suppression, pick a
destination, approve, alter approved content or execute a tool: this module has no
handle to any of those. It returns a `DraftVersion` row and nothing else.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .commitments import aware
from .foundation import audit, seal, utcnow
from .models import ApprovedClaim, Commitment, Customer, DraftVersion, ExceptionRecord, KnowledgeSource

PLACEHOLDER = re.compile(r"\{claim:([A-Za-z0-9_.-]{1,64})\}")
# Words that indicate an efficacy/benefit claim. Relationship text may not contain them
# outside an approved-claim placeholder. Deliberately broad; false positives create a
# review task, never a sent claim.
CLAIM_MARKERS = re.compile(
    r"\b(clinically|proven|guarantee[sd]?|cures?|heals?|treats?|reduces? wrinkles|anti-?aging|"
    r"dermatologist|medical(ly)?|prescription|eliminates?|erases?|reverses?|"
    r"results? in \d+|instantly|permanent(ly)?|miracle|detox|collagen|"
    r"acne|eczema|rosacea|psoriasis|melasma|hyperpigmentation|spf\s?\d+|sunscreen)\b"
    r"|\d+\s?%",   # percentages are results claims; '%' is not a word char so no trailing \b
    re.IGNORECASE,
)
# Destination-like strings (phone numbers, e-mail addresses, URLs) never belong in relationship text:
# the destination is chosen by the kernel from consented records, never by the model or the text.
DESTINATION_LIKE = re.compile(r"(\+?\d[\d\s().-]{7,}\d)|([\w.+-]+@[\w-]+\.[\w.]+)|(https?://\S+)", re.IGNORECASE)
# Income / earnings and medical-outcome language is never allowed anywhere in a draft.
FORBIDDEN_ANYWHERE = re.compile(
    r"\b(earn(ings)?|income|make money|get rich|replace your salary|diagnos(e|is)|prescrib|disease|infection)\b",
    re.IGNORECASE,
)
MAX_SMS_CHARS = 480


@dataclass
class ClaimCandidate:
    claim_id: str
    product_id: str
    approved_text: str
    source_version: str
    row_id: str


@dataclass
class DraftOutcome:
    draft: DraftVersion | None
    text: str | None
    limitation: str | None = None
    review_task_id: str | None = None
    claims_used: list[str] = field(default_factory=list)
    source_versions: dict[str, str] = field(default_factory=dict)


def live_claims(db: Session, tenant_id: str, product_ids: list[str] | None, market: str = "US",
                now: datetime | None = None) -> list[ClaimCandidate]:
    """Approved, in-market, effective, unexpired claims whose source is approved and
    unexpired. Tenant-specific rows override platform rows with the same claim_id."""
    now = now or utcnow()
    q = select(ApprovedClaim, KnowledgeSource).join(KnowledgeSource, KnowledgeSource.id == ApprovedClaim.source_id).where(
        ApprovedClaim.review_status == "approved", KnowledgeSource.review_status == "approved",
        ApprovedClaim.market == market)
    if product_ids:
        q = q.where(ApprovedClaim.product_id.in_(product_ids))
    out: dict[str, ClaimCandidate] = {}
    for claim, src in db.execute(q):
        if claim.tenant_id not in (None, tenant_id):
            continue
        if aware(claim.effective_at) > now or (claim.expires_at and aware(claim.expires_at) <= now):
            continue
        if aware(src.effective_at) > now or (src.expires_at and aware(src.expires_at) <= now):
            continue
        cand = ClaimCandidate(claim.claim_id, claim.product_id, claim.approved_text, claim.source_version, claim.id)
        if claim.claim_id not in out or claim.tenant_id == tenant_id:
            out[claim.claim_id] = cand
    return sorted(out.values(), key=lambda c: c.claim_id)


def drafting_system_prompt(candidates: list[ClaimCandidate], opt_out_phrase: str) -> str:
    menu = "\n".join(f'- {c.claim_id} (product {c.product_id}): "{c.approved_text}"' for c in candidates) or "- (none available)"
    return (
        "You write ONE short, warm SMS from an independent beauty consultant to a customer, in English, "
        "based only on the confirmed context given. Return ONLY JSON: "
        '{"relationship_text":"<the message; where a product statement belongs, insert the placeholder '
        '{claim:<claim_id>} and NOTHING else about the product>","claims_used":["<claim_id>",...]}. '
        "Rules: never state, imply or paraphrase any product benefit, ingredient, result, medical or earnings "
        "claim yourself — only placeholders from this list are allowed:\n" + menu +
        f"\nEnd with the opt-out text exactly: \"{opt_out_phrase}\". Keep under {MAX_SMS_CHARS} characters."
    )


def context_leak(db: Session, *, user_id: str, customer: Customer, text: str, allowed_text: str = "") -> str | None:
    """Cross-customer and private-notes leakage check (rows A2/P3). Returns a reason or None.
    False positives create a review task, never a sent message, so the check is deliberately broad."""
    low = text.lower()
    own_first = (customer.name.split()[0].lower() if customer.name else "")
    others = db.scalars(select(Customer).where(Customer.user_id == user_id, Customer.id != customer.id)).all()
    for o in others:
        name = (o.name or "").strip().lower()
        if len(name) >= 3 and name in low:
            return "draft references another customer"
        first = name.split()[0] if name else ""
        if len(first) >= 4 and first != own_first and re.search(rf"\b{re.escape(first)}\b", low):
            return "draft references another customer"
        if o.phone and o.phone in text:
            return "draft contains another customer's number"
    # Private notes are context for the consultant, never material to quote back to the customer.
    words = re.findall(r"[a-z']+", (customer.notes or "").lower())
    for i in range(len(words) - 2):
        if " ".join(words[i:i + 3]) in low:
            return "draft quotes private customer notes"
    allowed = set(re.findall(r"[a-z']+", allowed_text.lower()))
    for w in set(words):
        if len(w) >= 7 and w not in allowed and re.search(rf"\b{re.escape(w)}\b", low):
            return "draft quotes private customer notes"
    return None


def _digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


def assemble(db: Session, *, tenant_id: str, user_id: str, customer: Customer, commitment: Commitment | None,
             brief_item_id: str | None, model_output: str, candidates: list[ClaimCandidate],
             generated_by: str, opt_out_phrase: str) -> DraftOutcome:
    """Validate model output and assemble the draft, or refuse with a review task."""
    def refuse(reason: str, kind: str = "unsupported_claim") -> DraftOutcome:
        aref = audit(db, tenant_id, user_id, "draft.refused", {"customer_id": customer.id, "reason": reason, "kind": kind})
        ex = ExceptionRecord(tenant_id=tenant_id, customer_id=customer.id, kind="draft_review",
                             source_reference=commitment.id if commitment else (brief_item_id or ""),
                             detail_enc=seal(tenant_id, "exception", reason), audit_ref=aref)
        db.add(ex)
        db.flush()
        return DraftOutcome(draft=None, text=None, limitation=reason, review_task_id=ex.id)

    try:
        data = json.loads(model_output)
        rel = str(data["relationship_text"])
        used = [str(x) for x in data.get("claims_used", [])]
    except (ValueError, KeyError, TypeError):
        return refuse("model output was not the required JSON; no draft produced", "model_output_invalid")
    by_id = {c.claim_id: c for c in candidates}
    placeholders = PLACEHOLDER.findall(rel)
    unknown = [p for p in placeholders if p not in by_id]
    if unknown:
        return refuse(f"model referenced claims not in the approved list: {unknown}")
    if set(used) - set(placeholders) or set(placeholders) - set(used):
        return refuse("claims_used does not match placeholders in the text")
    # Relationship text (placeholders removed) may not contain claim-like language.
    rel_only = PLACEHOLDER.sub("", rel)
    if CLAIM_MARKERS.search(rel_only):
        m = CLAIM_MARKERS.search(rel_only).group(0)
        return refuse(f"relationship text contains product-claim language ('{m}') outside an approved claim")
    if FORBIDDEN_ANYWHERE.search(rel):
        return refuse(f"forbidden language: '{FORBIDDEN_ANYWHERE.search(rel).group(0)}'", "forbidden_language")
    if DESTINATION_LIKE.search(rel_only):
        return refuse("relationship text contains a phone number, address or link; destinations are never chosen in text",
                      "destination_in_text")
    allowed = " ".join([commitment.commitment_text if commitment else ""] + [c.approved_text for c in candidates])
    leak = context_leak(db, user_id=user_id, customer=customer, text=rel_only, allowed_text=allowed)
    if leak:
        return refuse(leak, "context_leak")
    text = PLACEHOLDER.sub(lambda m: by_id[m.group(1)].approved_text, rel).strip()
    if opt_out_phrase.lower() not in text.lower():
        text = f"{text} {opt_out_phrase}".strip()
    if len(text) > MAX_SMS_CHARS:
        return refuse(f"draft exceeds {MAX_SMS_CHARS} characters", "too_long")
    # Record claim spans so the UI can show controlled vs relationship text.
    spans = []
    for m in PLACEHOLDER.finditer(rel):
        spans.append({"claim_id": m.group(1), "approved_text": by_id[m.group(1)].approved_text})
    source_versions = {c.claim_id: c.source_version for c in candidates if c.claim_id in placeholders}
    aref = audit(db, tenant_id, user_id, "draft.generate",
                 {"customer_id": customer.id, "claims_used": sorted(set(placeholders)),
                  "text_digest": _digest(text), "generated_by": generated_by})
    dv = DraftVersion(tenant_id=tenant_id, customer_id=customer.id, brief_item_id=brief_item_id,
                      text_enc=seal(tenant_id, "draft", text), text_digest=_digest(text),
                      relationship_spans_json=json.dumps({"relationship_text": rel}),
                      claim_ids_json=json.dumps(sorted(set(placeholders))),
                      source_versions_json=json.dumps(source_versions, sort_keys=True),
                      generated_by=generated_by, audit_ref=aref)
    db.add(dv)
    db.flush()
    return DraftOutcome(draft=dv, text=text, claims_used=sorted(set(placeholders)), source_versions=source_versions)


def consultant_edit(db: Session, *, tenant_id: str, user_id: str, prior: DraftVersion, new_text: str) -> DraftOutcome:
    """A consultant may rewrite relationship language freely but may not introduce claim
    language that is not an exact approved claim. Produces a new version (W5: the old
    digest is a different digest; approvals bound to it are invalid by construction)."""
    candidates = live_claims(db, tenant_id, None)
    stripped = new_text
    for c in candidates:
        stripped = stripped.replace(c.approved_text, "")
    if CLAIM_MARKERS.search(stripped) or FORBIDDEN_ANYWHERE.search(new_text):
        raise HTTPException(422, {"code": "UNAPPROVED_CLAIM_LANGUAGE",
                                  "detail": "edited text contains product-claim or forbidden language that is not an approved claim"})
    if len(new_text) > MAX_SMS_CHARS:
        raise HTTPException(422, f"draft exceeds {MAX_SMS_CHARS} characters")
    cust = db.get(Customer, prior.customer_id)
    leak = context_leak(db, user_id=user_id, customer=cust, text=stripped,
                        allowed_text=" ".join(c.approved_text for c in candidates)) if cust else None
    if leak:
        raise HTTPException(422, {"code": "CONTEXT_LEAK", "detail": leak})
    used = sorted(c.claim_id for c in candidates if c.approved_text in new_text)
    aref = audit(db, tenant_id, user_id, "draft.edit", {"prior_version_id": prior.id, "text_digest": _digest(new_text)})
    dv = DraftVersion(tenant_id=tenant_id, customer_id=prior.customer_id, brief_item_id=prior.brief_item_id,
                      text_enc=seal(tenant_id, "draft", new_text), text_digest=_digest(new_text),
                      relationship_spans_json=json.dumps({"edited_from": prior.id}),
                      claim_ids_json=json.dumps(used),
                      source_versions_json=json.dumps({c.claim_id: c.source_version for c in candidates if c.claim_id in used}, sort_keys=True),
                      generated_by=user_id, version=prior.version + 1, audit_ref=aref)
    db.add(dv)
    db.flush()
    return DraftOutcome(draft=dv, text=new_text, claims_used=used)
