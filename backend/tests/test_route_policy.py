"""Policy identity is the matched, prefixed template, never caller URL text."""
import pytest
from fastapi import APIRouter, FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

from app.route_policy import matched_route_template


def test_reused_nested_router_keeps_each_registered_prefix():
    leaf = APIRouter()

    @leaf.get("/items/{item_id}")
    def identity(request: Request):
        return {"template": matched_route_template(request.scope)}

    nested = APIRouter()
    nested.include_router(leaf, prefix="/private")
    application = FastAPI()
    application.include_router(nested, prefix="/one")
    application.include_router(nested, prefix="/two")
    with TestClient(application, root_path="/gateway") as client:
        for prefix in ("one", "two"):
            response = client.get(f"/gateway/{prefix}/private/items/CALLER-CANARY?path=/api/account/export")
            assert response.status_code == 200
            assert response.json() == {"template": f"/{prefix}/private/items/{{item_id}}"}


@pytest.mark.parametrize("method,path,matched", [
    ("GET", "/api/items/one", False),
    ("DELETE", "/api/items/one", True),
    ("GET", "/unregistered", True),
])
def test_missing_or_inconsistent_matched_route_fails_closed(method, path, matched):
    application = FastAPI()

    @application.get("/api/items/{item_id}")
    def item():
        return {}

    scope = {"type": "http", "method": method, "path": path, "app": application}
    if matched:
        scope["route"] = application.routes[-1]
    with pytest.raises(HTTPException) as exc:
        matched_route_template(scope)
    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "ROUTE_POLICY_UNAVAILABLE"
