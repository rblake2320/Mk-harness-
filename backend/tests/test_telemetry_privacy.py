"""Do not log raw HTTP targets or exception strings, including stream failures."""
import asyncio
import logging
import traceback
from types import SimpleNamespace

import pytest
from app.telemetry import PrivateHttpTelemetry, SanitizedStreamFailure


@pytest.mark.parametrize("failure",["none","before_start","stream"])
def test_http_metadata_and_failures_are_content_free(caplog,failure):
    canary="SYNTHETIC-PRIVATE-PERSON-123"
    async def app(scope,receive,send):
        scope["route"]=SimpleNamespace(path="/customers/{customer_id}")
        if failure=="before_start": raise RuntimeError(canary)
        await send({"type":"http.response.start","status":200,"headers":[]})
        if failure=="stream": raise RuntimeError(canary)
        await send({"type":"http.response.body","body":b"ok"})
    messages=[]
    async def send(message): messages.append(message)
    async def receive(): return {"type":"http.request","body":b""}
    with caplog.at_level(logging.INFO):
        wrapped=PrivateHttpTelemetry(app)
        run=wrapped({"type":"http","method":"GET","path":"/customers/"+canary,
            "query_string":canary.encode(),"client":(canary,123)},receive,send)
        if failure=="stream":
            with pytest.raises(SanitizedStreamFailure) as captured: asyncio.run(run)
            assert canary not in "".join(traceback.format_exception(captured.value))
        else: asyncio.run(run)
    assert canary not in caplog.text
    assert "http_request method=GET route=/customers/{customer_id}" in caplog.text
    assert f"status={200 if failure=='none' else 500}" in caplog.text
    assert logging.getLogger("uvicorn.access").disabled
    if failure=="before_start":
        assert messages[0]["status"]==500
        assert canary.encode() not in messages[1]["body"]


def test_unmatched_path_and_nonstandard_method_never_become_labels(caplog):
    canary="PRIVATE-CALLER-METHOD"
    async def app(scope,receive,send):
        await send({"type":"http.response.start","status":404,"headers":[]})
    async def sink(_): pass
    with caplog.at_level(logging.INFO):
        asyncio.run(PrivateHttpTelemetry(app)({"type":"http","method":canary,"path":canary},sink,sink))
    assert canary not in caplog.text
    assert "method=OTHER route=unmatched status=404" in caplog.text
