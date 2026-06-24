"""Chat: SSE streaming with skill prompts, conversation persistence,
model/provider selection, and usage metering."""
import json

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Conversation, Message, User
from ..providers.base import ChatMessage, ChatRequest, MODEL_CATALOG, ProviderError
from ..providers.router import DEFAULT_CHAIN, NoKeyAvailable, record_usage, resolve
from ..ratelimit import check_rate
from ..security import get_current_user
from ..skills import SKILLS, _PROMPT_LEAK_REPLY, response_has_income_claim, response_leaks_system_prompt

router = APIRouter(prefix="/chat", tags=["chat"])


class ChatIn(BaseModel):
    message: str = Field(min_length=1, max_length=20000)
    conversation_id: str | None = None
    skill: str = "assistant"
    provider: str | None = None   # None = auto (failover chain)
    model: str | None = None
    temperature: float = Field(default=0.7, ge=0.0, le=1.0)


def _own_conversation(db: Session, user: User, cid: str) -> Conversation:
    conv = db.get(Conversation, cid)
    if not conv or conv.tenant_id != user.tenant_id or conv.user_id != user.id:
        raise HTTPException(404, "Conversation not found")
    return conv


@router.get("/skills")
def list_skills():
    return {k: {"label": v["label"]} for k, v in SKILLS.items()}


@router.get("/models")
def list_models():
    return {m: {"provider": v["provider"], "vision": v["vision"]}
            for m, v in MODEL_CATALOG.items()}


@router.get("/conversations")
def list_conversations(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(Conversation).where(
        Conversation.user_id == user.id).order_by(Conversation.created_at.desc()).limit(100))
    return [{"id": c.id, "title": c.title, "skill": c.skill,
             "created_at": c.created_at.isoformat()} for c in rows]


@router.get("/conversations/{cid}")
def get_conversation(cid: str, user: User = Depends(get_current_user),
                     db: Session = Depends(get_db)):
    conv = _own_conversation(db, user, cid)
    return {"id": conv.id, "title": conv.title, "skill": conv.skill,
            "messages": [{"role": m.role, "content": m.content, "model": m.model,
                          "provider": m.provider} for m in conv.messages]}


@router.delete("/conversations/{cid}")
def delete_conversation(cid: str, user: User = Depends(get_current_user),
                        db: Session = Depends(get_db)):
    conv = _own_conversation(db, user, cid)
    db.delete(conv)
    db.commit()
    return {"ok": True}


@router.post("/stream")
async def chat_stream(body: ChatIn, user: User = Depends(check_rate),
                      db: Session = Depends(get_db)):
    if body.skill not in SKILLS:
        raise HTTPException(422, f"Unknown skill. Choose from {sorted(SKILLS)}")
    if body.provider and body.provider not in DEFAULT_CHAIN:
        raise HTTPException(422, f"Unknown provider. Choose from {DEFAULT_CHAIN}")

    if body.conversation_id:
        conv = _own_conversation(db, user, body.conversation_id)
    else:
        conv = Conversation(tenant_id=user.tenant_id, user_id=user.id,
                            skill=body.skill, title=body.message[:60])
        db.add(conv)
        db.commit()

    history = [ChatMessage(role=m.role, content=m.content) for m in conv.messages][-20:]
    history.append(ChatMessage(role="user", content=body.message))
    req = ChatRequest(messages=history, system=SKILLS[body.skill]["system"],
                      model=body.model or "", max_tokens=1500, temperature=body.temperature)

    chain = [body.provider] if body.provider else DEFAULT_CHAIN

    async def event_gen():
        yield f"data: {json.dumps({'type': 'meta', 'conversation_id': conv.id})}\n\n"
        errors = []
        for name in chain:
            try:
                resolved = resolve(db, user, name)
            except NoKeyAvailable as e:
                errors.append(str(e))
                continue
            model = req.model if req.model and \
                MODEL_CATALOG.get(req.model, {}).get("provider") == name \
                else resolved.adapter.default_model()
            sub = ChatRequest(messages=req.messages, system=req.system, model=model,
                              max_tokens=req.max_tokens, temperature=req.temperature)
            full, usage = "", None
            try:
                async for chunk in resolved.adapter.stream(sub):
                    if chunk.delta:
                        full += chunk.delta
                        yield f"data: {json.dumps({'type': 'delta', 'text': chunk.delta})}\n\n"
                    if chunk.done:
                        usage = chunk.usage
            except ProviderError as e:
                errors.append(str(e))
                if e.retryable and not body.provider and not full:
                    continue  # failover to next provider
                yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
                return
            # Server-side compliance checks — must run before any persistence.
            # 1. System prompt leak: replace streamed text with a safe refusal.
            if response_leaks_system_prompt(full):
                yield f"data: {json.dumps({'type': 'correction', 'text': _PROMPT_LEAK_REPLY})}\n\n"
                full = _PROMPT_LEAK_REPLY
            # 2. FTC income claim: block persistence and warn; streamed deltas already sent.
            claim_found, claim_phrase = response_has_income_claim(full)
            if claim_found:
                yield f"data: {json.dumps({'type': 'income_claim_warning', 'phrase': claim_phrase, 'message': 'This response may contain a prohibited income representation and was not saved. Review before sharing with anyone.'})}\n\n"
                return
            # Persist turn + meter usage
            db.add(Message(conversation_id=conv.id, role="user", content=body.message))
            db.add(Message(conversation_id=conv.id, role="assistant", content=full,
                           provider=name, model=model))
            db.commit()
            if usage:
                record_usage(db, user, model, name, resolved.key_scope, usage, "chat")
            yield f"data: {json.dumps({'type': 'done', 'provider': name, 'model': model})}\n\n"
            return
        msg = "No provider available: " + " | ".join(errors)
        yield f"data: {json.dumps({'type': 'error', 'message': msg})}\n\n"

    return StreamingResponse(event_gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
