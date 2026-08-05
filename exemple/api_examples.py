"""Example helpers for consuming VaultPy via HTTP."""

from __future__ import annotations

from urllib.parse import quote

import httpx


def login(base_url: str, master_password: str) -> dict:
    """Authenticate and return the token pair."""
    url = f"{base_url.rstrip('/')}/api/v1/auth/login"
    payload = {"master_password": master_password}
    with httpx.Client(timeout=30.0) as client:
        response = client.post(url, json=payload)
        response.raise_for_status()
        return response.json()


def get_secret_value_by_name(base_url: str, access_token: str, secret_name: str) -> dict:
    """Fetch and decrypt a secret by its name."""
    encoded_name = quote(secret_name, safe="")
    url = f"{base_url.rstrip('/')}/api/v1/secrets/by-name/{encoded_name}/value"
    headers = {"Authorization": f"Bearer {access_token}"}
    with httpx.Client(timeout=30.0, headers=headers) as client:
        response = client.get(url)
        response.raise_for_status()
        return response.json()


def fetch_secret_credentials(base_url: str, master_password: str, secret_name: str) -> dict:
    """Log in and fetch a secret by name in one call."""
    tokens = login(base_url, master_password)
    return get_secret_value_by_name(base_url, tokens["access_token"], secret_name)
