"""Example helpers for consuming VaultPy via HTTP."""

from __future__ import annotations

import json
from urllib.parse import quote
from urllib.request import Request, urlopen


def login(base_url: str, master_password: str) -> dict:
    """Authenticate and return the token pair."""
    url = f"{base_url.rstrip('/')}/api/v1/auth/login"
    payload = json.dumps({"master_password": master_password}).encode("utf-8")
    request = Request(url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def get_secret_value_by_name(base_url: str, access_token: str, secret_name: str) -> dict:
    """Fetch and decrypt a secret by its name."""
    encoded_name = quote(secret_name, safe="")
    url = f"{base_url.rstrip('/')}/api/v1/secrets/by-name/{encoded_name}/value"
    request = Request(url, headers={"Authorization": f"Bearer {access_token}"})
    with urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def fetch_secret_credentials(base_url: str, master_password: str, secret_name: str) -> dict:
    """Log in and fetch a secret by name in one call."""
    tokens = login(base_url, master_password)
    return get_secret_value_by_name(base_url, tokens["access_token"], secret_name)

data = fetch_secret_credentials("http://127.0.0.1:8000", "your_password-xxxxxxxx", "xxxxxxx")
print(data['secret_fields']['token'])




