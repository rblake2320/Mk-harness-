"""Resolve policy keys from registered routes, including router prefixes.

FastAPI keeps the original (unprefixed) APIRoute in the request scope. Never
derive an authorization decision from that path alone, or from a raw URL.
"""
from fastapi import HTTPException
from fastapi.routing import iter_route_contexts
from starlette._utils import get_route_path


def matched_route_template(scope: dict) -> str:
    original = scope.get("route")
    application = scope.get("app")
    candidates = {
        context.path
        for context in iter_route_contexts(getattr(application, "routes", ()))
        if context.original_route is original
        and scope.get("method") in (context.methods or ())
        and context.path_regex.fullmatch(get_route_path(scope))
    }
    if len(candidates) != 1:
        raise HTTPException(403, {"code": "ROUTE_POLICY_UNAVAILABLE",
            "message": "The matched operation could not be authorized."})
    return candidates.pop()
