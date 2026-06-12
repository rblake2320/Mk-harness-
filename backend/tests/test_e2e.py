"""End-to-end flows through the live ASGI app with provider wire formats
simulated at the HTTP boundary (test-only mocking)."""
import base64
import io
import json
import uuid

import httpx
import respx
from PIL import Image

from tests.conftest import auth_headers, signup


def _email():
    return f"u{uuid.uuid4().hex[:10]}@example.com"


def _setup_user_with_anthropic_key(client):
    t = signup(client, email=_email())
    client.put("/api/keys/mine", headers=auth_headers(t),
               json={"provider": "anthropic", "api_key": "sk-ant-test"})
    return t


def _anthropic_sse(text="Sure thing!"):
    return (
        'data: {"type":"message_start","message":{"usage":{"input_tokens":20}}}\n\n'
        f'data: {{"type":"content_block_delta","delta":{{"type":"text_delta","text":"{text}"}}}}\n\n'
        'data: {"type":"message_delta","usage":{"output_tokens":5}}\n\n'
        'data: {"type":"message_stop"}\n\n'
    )


@respx.mock
def test_chat_stream_persists_and_meters(client):
    t = _setup_user_with_anthropic_key(client)
    respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=httpx.Response(200, content=_anthropic_sse().encode(),
                                    headers={"content-type": "text/event-stream"}))
    with client.stream("POST", "/api/chat/stream", headers=auth_headers(t),
                       json={"message": "How do I book more parties?",
                             "skill": "sales_coach", "provider": "anthropic"}) as r:
        assert r.status_code == 200
        events = [json.loads(line[5:]) for line in r.iter_lines() if line.startswith("data:")]
    types = [e["type"] for e in events]
    assert types[0] == "meta" and "delta" in types and types[-1] == "done"
    cid = events[0]["conversation_id"]

    conv = client.get(f"/api/chat/conversations/{cid}", headers=auth_headers(t)).json()
    assert conv["messages"][0]["content"] == "How do I book more parties?"
    assert conv["messages"][1]["content"] == "Sure thing!"

    usage = client.get("/api/usage/me", headers=auth_headers(t)).json()
    assert usage and usage[0]["input_tokens"] == 20 and usage[0]["output_tokens"] == 5
    assert usage[0]["cost_usd"] > 0


@respx.mock
def test_chat_failover_anthropic_down_openai_up(client):
    """Anthropic 529 (retryable) -> router falls through to OpenAI."""
    t = signup(client, email=_email())
    h = auth_headers(t)
    client.put("/api/keys/mine", headers=h, json={"provider": "anthropic", "api_key": "a"})
    client.put("/api/keys/mine", headers=h, json={"provider": "openai", "api_key": "b"})
    respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=httpx.Response(529, json={"error": {"message": "overloaded"}}))
    openai_sse = (
        'data: {"choices":[{"delta":{"content":"Backup says hi"}}]}\n\n'
        'data: {"choices":[],"usage":{"prompt_tokens":8,"completion_tokens":3}}\n\n'
        "data: [DONE]\n\n"
    )
    respx.post("https://api.openai.com/v1/chat/completions").mock(
        return_value=httpx.Response(200, content=openai_sse.encode(),
                                    headers={"content-type": "text/event-stream"}))
    with client.stream("POST", "/api/chat/stream", headers=h,
                       json={"message": "test failover", "skill": "assistant"}) as r:
        events = [json.loads(line[5:]) for line in r.iter_lines() if line.startswith("data:")]
    done = [e for e in events if e["type"] == "done"]
    assert done and done[0]["provider"] == "openai"
    assert "".join(e.get("text", "") for e in events if e["type"] == "delta") == "Backup says hi"


def test_chat_no_keys_returns_clear_error(client):
    t = signup(client, email=_email(), key_policy="byo")
    with client.stream("POST", "/api/chat/stream", headers=auth_headers(t),
                       json={"message": "hi", "skill": "assistant",
                             "provider": "anthropic"}) as r:
        events = [json.loads(line[5:]) for line in r.iter_lines() if line.startswith("data:")]
    assert events[-1]["type"] == "error"
    assert "API key" in events[-1]["message"]


def _face_jpeg() -> bytes:
    img = Image.new("RGB", (640, 640), (220, 180, 160))
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    return buf.getvalue()


def _skin_json(extra_note="even tone overall"):
    return json.dumps({
        "observations": [
            {"category": "hydration", "level": "moderate", "note": "Some dryness on cheeks."},
            {"category": "radiance", "level": "notable", "note": extra_note},
            {"category": "not_a_real_category", "level": "low", "note": "should be filtered"},
        ],
        "care_focus": ["hydrating serum", "gentle cleanser"],
        "routine_suggestion": {"am": ["cleanse", "moisturize", "SPF"], "pm": ["cleanse", "serum"]},
        "consultant_talking_points": ["Your skin shows lovely natural radiance."],
        "see_professional": False,
        "disclaimer": "x",
    })


@respx.mock
def test_skin_analysis_happy_path(client):
    t = _setup_user_with_anthropic_key(client)
    route = respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=httpx.Response(200, json={
            "model": "claude-sonnet-4-6",
            "content": [{"type": "text", "text": _skin_json()}],
            "usage": {"input_tokens": 900, "output_tokens": 200}}))
    r = client.post("/api/skin/analyze", headers=auth_headers(t),
                    files={"file": ("face.jpg", _face_jpeg(), "image/jpeg")},
                    data={"provider": "anthropic"})
    assert r.status_code == 200, r.text
    result = r.json()["result"]
    # Unknown category filtered; disclaimer enforced server-side
    cats = {o["category"] for o in result["observations"]}
    assert cats == {"hydration", "radiance"}
    assert "not medical advice" in result["disclaimer"]
    # Image actually reached the provider as base64 jpeg
    sent = json.loads(route.calls[0].request.content)
    img_block = sent["messages"][0]["content"][0]
    assert img_block["type"] == "image" and img_block["source"]["media_type"] == "image/jpeg"
    # History records it
    hist = client.get("/api/skin/history", headers=auth_headers(t)).json()
    assert len(hist) == 1


@respx.mock
def test_skin_analysis_blocks_medical_language(client):
    """If a model leaks a diagnosis term, the result is discarded — never shown."""
    t = _setup_user_with_anthropic_key(client)
    respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=httpx.Response(200, json={
            "model": "claude-sonnet-4-6",
            "content": [{"type": "text", "text": _skin_json("possible rosacea on cheeks")}],
            "usage": {"input_tokens": 1, "output_tokens": 1}}))
    r = client.post("/api/skin/analyze", headers=auth_headers(t),
                    files={"file": ("face.jpg", _face_jpeg(), "image/jpeg")},
                    data={"provider": "anthropic"})
    assert r.status_code == 502
    assert "compliance" in r.json()["detail"]
    assert client.get("/api/skin/history", headers=auth_headers(t)).json() == []


def test_skin_rejects_non_image(client):
    t = _setup_user_with_anthropic_key(client)
    r = client.post("/api/skin/analyze", headers=auth_headers(t),
                    files={"file": ("evil.jpg", b"<script>alert(1)</script>", "image/jpeg")})
    assert r.status_code == 422


def test_skin_strips_exif_gps():
    """Sanitizer must remove EXIF (incl. GPS) — privacy requirement."""
    from app.routes.skin import _sanitize_image
    img = Image.new("RGB", (300, 300), (200, 150, 140))
    exif = Image.Exif()
    exif[0x010F] = "TestPhone"          # Make
    exif[0x0110] = "TestModel GPS-1"    # Model
    buf = io.BytesIO()
    img.save(buf, format="JPEG", exif=exif.tobytes())
    b64, _ = _sanitize_image(buf.getvalue(), max_mb=8)
    out = Image.open(io.BytesIO(base64.b64decode(b64)))
    assert dict(out.getexif()) == {}


@respx.mock
def test_customer_follow_up_uses_notes(client):
    t = _setup_user_with_anthropic_key(client)
    h = auth_headers(t)
    cid = client.post("/api/customers", headers=h, json={
        "name": "Brenda", "notes": "Loves the satin hands set; reorders quarterly"}).json()["id"]
    route = respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=httpx.Response(200, json={
            "model": "claude-sonnet-4-6",
            "content": [{"type": "text", "text": "Draft 1... Draft 2..."}],
            "usage": {"input_tokens": 80, "output_tokens": 60}}))
    r = client.post(f"/api/customers/{cid}/follow-up", headers=h,
                    json={"goal": "quarterly reorder", "provider": "anthropic"})
    assert r.status_code == 200 and "Draft" in r.json()["drafts"]
    sent = json.loads(route.calls[0].request.content)
    assert "satin hands" in sent["messages"][0]["content"]


def test_health(client):
    assert client.get("/api/health").json() == {"status": "ok"}
