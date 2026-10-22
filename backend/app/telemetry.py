"""Content-free HTTP telemetry, including failures and unknown routes.

Uvicorn's default access logger includes the raw URL, query and peer address.
Only route templates, closed method names, status and timing belong in logs.
"""
import logging
import time


class SanitizedStreamFailure(RuntimeError):
    """Response streaming failed; private exception details were suppressed."""


class PrivateHttpTelemetry:
    def __init__(self, app):
        self.app = app
        logging.getLogger("uvicorn.access").disabled = True
        self.logger = logging.getLogger("uvicorn.error.safe_access")

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        started = time.monotonic()
        status, response_started = 500, False

        async def record_send(message):
            nonlocal status, response_started
            if message["type"] == "http.response.start":
                status, response_started = message["status"], True
            await send(message)

        try:
            await self.app(scope, receive, record_send)
        except Exception as exc:
            # Driver/provider exceptions can contain SQL parameters or bodies.
            # Never forward their repr/traceback into the ASGI server's logger.
            self.logger.error("http_failure exception_type=%s", type(exc).__name__)
            status = 500
            if response_started:
                raise SanitizedStreamFailure("response_stream_failed") from None
            await record_send({"type":"http.response.start", "status":500,
                "headers":[(b"content-type",b"application/json"),(b"cache-control",b"no-store")]})
            await send({"type":"http.response.body", "body":b'{"detail":"Internal server error"}'})
        finally:
            method = scope.get("method", "")
            if method not in {"GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS","CONNECT","TRACE"}:
                method = "OTHER"
            route = getattr(scope.get("route"), "path", "unmatched")
            self.logger.info("http_request method=%s route=%s status=%d duration_ms=%.2f",
                method, route, status, (time.monotonic()-started)*1000)
