"""Factory Boy payload factories used by API tests."""

from __future__ import annotations

import factory


class SecretPayloadFactory(factory.DictFactory):
    """Factory for secret creation payloads."""

    name = factory.Sequence(lambda n: f"GitLab Production {n}")
    category = "Git"
    username = "farley.santos"
    secret_value = "Sup3r$ecret!"
    secret_fields: dict[str, str] = {}
    secret_kind = "password"
    url = "https://gitlab.company.com"
    notes = "Production GitLab credential"
    tags = ["gitlab", "production"]
