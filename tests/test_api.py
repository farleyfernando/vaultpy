"""Integration tests for the VaultPy API."""

from __future__ import annotations

from urllib.parse import quote

import factory
from fastapi.testclient import TestClient
from sqlalchemy import text

from tests.factories import SecretPayloadFactory
from vaultpy.presentation.dependencies import get_container


def test_bootstrap_login_crud_search_and_audit_flow(client: TestClient, master_password: str) -> None:
    """The end-to-end API flow should work for the master user."""
    status_response = client.get("/api/v1/status")
    assert status_response.status_code == 200
    assert status_response.json()["bootstrapped"] is False

    setup_response = client.post("/api/v1/setup", json={"master_password": master_password})
    assert setup_response.status_code == 201

    login_response = client.post("/api/v1/auth/login", json={"master_password": master_password})
    assert login_response.status_code == 200
    tokens = login_response.json()
    assert "access_token" in tokens
    assert "refresh_token" in tokens

    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    payload = factory.build(dict, FACTORY_CLASS=SecretPayloadFactory)

    create_response = client.post("/api/v1/secrets", json=payload, headers=headers)
    assert create_response.status_code == 201
    secret = create_response.json()
    secret_id = secret["id"]
    assert secret["name"] == payload["name"]
    assert secret["secret_kind"] == payload["secret_kind"]

    db_session = get_container().database.session()
    encrypted_value = db_session.execute(
        text("SELECT secret_value_encrypted FROM secrets WHERE id = :id"),
        {"id": secret_id},
    ).scalar_one()
    db_session.close()
    assert encrypted_value != payload["secret_value"]

    dashboard_response = client.get("/api/v1/dashboard", headers=headers)
    assert dashboard_response.status_code == 200
    assert dashboard_response.json()["total_secrets"] == 1

    list_response = client.get("/api/v1/secrets", headers=headers)
    assert list_response.status_code == 200
    assert len(list_response.json()) == 1

    get_response = client.get(f"/api/v1/secrets/{secret_id}", headers=headers)
    assert get_response.status_code == 200
    assert get_response.json()["name"] == payload["name"]

    search_response = client.get("/api/v1/secrets/search", params={"q": "GitLab"}, headers=headers)
    assert search_response.status_code == 200
    assert len(search_response.json()) == 1

    value_response = client.get(f"/api/v1/secrets/{secret_id}/value", headers=headers)
    assert value_response.status_code == 200
    assert value_response.json()["secret_name"] == payload["name"]
    assert value_response.json()["secret_value"] == payload["secret_value"]

    value_by_name_response = client.get(
        f"/api/v1/secrets/by-name/{quote(payload['name'], safe='')}/value",
        headers=headers,
    )
    assert value_by_name_response.status_code == 200
    assert value_by_name_response.json()["secret_name"] == payload["name"]
    assert value_by_name_response.json()["secret_value"] == payload["secret_value"]

    update_response = client.put(
        f"/api/v1/secrets/{secret_id}",
        json={
            "category": "Cloud",
            "tags": ["rotated", "production"],
            "secret_value": "N3w$ecret2026",
        },
        headers=headers,
    )
    assert update_response.status_code == 200
    assert update_response.json()["category"] == "Cloud"
    assert update_response.json()["tags"] == ["production", "rotated"]

    refresh_response = client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert refresh_response.status_code == 200
    assert refresh_response.json()["access_token"] != ""

    audit_response = client.get("/api/v1/audit-logs", headers=headers)
    assert audit_response.status_code == 200
    actions = [entry["action"] for entry in audit_response.json()]
    assert "login" in actions
    assert "create" in actions
    assert "secret_view" in actions
    assert "update" in actions

    delete_response = client.delete(f"/api/v1/secrets/{secret_id}", headers=headers)
    assert delete_response.status_code == 204

    final_list_response = client.get("/api/v1/secrets", headers=headers)
    assert final_list_response.status_code == 200
    assert final_list_response.json() == []

    logout_response = client.post("/api/v1/auth/logout", headers=headers)
    assert logout_response.status_code == 204


def test_invalid_login_is_rejected(client: TestClient) -> None:
    """Incorrect master passwords should return a client error."""
    response = client.post("/api/v1/auth/login", json={"master_password": "WrongPassword#2026"})

    assert response.status_code == 400


def test_secret_can_store_multiple_named_values(
    client: TestClient,
    master_password: str,
) -> None:
    """One secret entry should support multiple named secret fields."""
    client.post("/api/v1/setup", json={"master_password": master_password})
    login_response = client.post("/api/v1/auth/login", json={"master_password": master_password})
    tokens = login_response.json()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    create_response = client.post(
        "/api/v1/secrets",
        json={
            "name": "api_fluid",
            "category": "API",
            "username": "service-user",
            "secret_kind": "secret_key",
            "secret_fields": {
                "chave_secret": "xxxxx",
                "intarid": "xxxxxxx",
                "id": "xxxxx",
            },
            "notes": "Structured API credentials",
            "tags": ["api", "fluid"],
        },
        headers=headers,
    )
    assert create_response.status_code == 201
    secret_id = create_response.json()["id"]

    value_response = client.get(f"/api/v1/secrets/{secret_id}/value", headers=headers)
    assert value_response.status_code == 200
    assert value_response.json()["secret_name"] == "api_fluid"
    assert value_response.json()["secret_value"] is None
    assert value_response.json()["secret_fields"] == {
        "chave_secret": "xxxxx",
        "id": "xxxxx",
        "intarid": "xxxxxxx",
    }

    update_response = client.put(
        f"/api/v1/secrets/{secret_id}",
        json={
            "secret_fields": {
                "chave_secret": "rotacionada",
                "intarid": "xxxxxxx",
                "id": "xxxxx",
                "tenant": "fluid-prod",
            }
        },
        headers=headers,
    )
    assert update_response.status_code == 200

    updated_value_response = client.get(f"/api/v1/secrets/{secret_id}/value", headers=headers)
    assert updated_value_response.status_code == 200
    assert updated_value_response.json()["secret_name"] == "api_fluid"
    assert updated_value_response.json()["secret_fields"]["chave_secret"] == "rotacionada"
    assert updated_value_response.json()["secret_fields"]["tenant"] == "fluid-prod"
