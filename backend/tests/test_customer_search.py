"""F7/S11: bounded customer search never returns foreign tenant or owner data."""
import pytest

from app import db as dbmod
from app.models import Customer
from .test_foundation import _user


def test_search_is_tenant_and_owner_scoped_with_literal_matching_and_pagination(client):
    owner, foreign = _user(client), _user(client)
    ids = []
    for name, phone, email in [("Angela 100%", "+15555550111", "angela@example.com"),
                               ("Angela Two", "+15555550222", "second@example.com"),
                               ("A_B", "+15555550333", "literal@example.com")]:
        response = client.post("/api/customers", json={"name": name, "phone": phone, "email": email}, headers=owner)
        assert response.status_code == 201
        ids.append(response.json()["id"])
    alien = client.post("/api/customers", json={"name": "Angela private", "phone": "+15555550999"}, headers=foreign).json()["id"]
    with dbmod._SessionLocal() as db:
        own, other = db.get(Customer, ids[0]), db.get(Customer, alien)
        # Independently challenge both predicates: same tenant/different owner,
        # and same owner/different tenant. Neither row may be returned.
        db.add(Customer(name="Angela coworker", tenant_id=own.tenant_id, user_id=other.user_id))
        db.add(Customer(name="Angela corrupt ownership", tenant_id=other.tenant_id, user_id=own.user_id))
        db.commit()
    def search(query, **kw):
        result = client.post("/api/customers/search", json={"query": query, **kw}, headers=owner)
        assert result.status_code == 200, result.text
        return result.json()
    first = search("ANGELA", limit=1)
    assert [c["id"] for c in first["items"]] == [ids[0]] and first["next_offset"] == 1
    second = search("ANGELA", limit=1, offset=first["next_offset"])
    assert [c["id"] for c in second["items"]] == [ids[1]] and second["next_offset"] is None
    assert [c["id"] for c in search("%")['items']] == [ids[0]]
    assert [c["id"] for c in search("_")['items']] == [ids[2]]
    assert [c["id"] for c in search("SECOND@EXAMPLE.COM")['items']] == [ids[1]]
    assert [c["id"] for c in search("50111")['items']] == [ids[0]]
    assert search("' OR 1=1 --")["items"] == []
    assert {c["id"] for c in client.get("/api/customers", headers=owner).json()} == set(ids)
    assert client.get(f"/api/customers/{alien}", headers=owner).status_code == 404


@pytest.mark.parametrize("body", [{"query": ""}, {"query": " "}, {"query": "a" * 121},
                                  {"query": "a", "limit": 101}, {"query": "a", "offset": -1}])
def test_search_rejects_unbounded_or_empty_input(client, body):
    assert client.post("/api/customers/search", json=body, headers=_user(client)).status_code == 422


def test_search_requires_authentication(client):
    assert client.post("/api/customers/search", json={"query": "Angela"}).status_code == 401
