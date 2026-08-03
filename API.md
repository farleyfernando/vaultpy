# API Guide

## Bootstrap

```http
POST /api/v1/setup
Content-Type: application/json

{
  "master_password": "VaultMaster#2026"
}
```

## Login

```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "master_password": "VaultMaster#2026"
}
```

## Create secret

```http
POST /api/v1/secrets
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "name": "GitLab Production",
  "category": "Git",
  "username": "farley.santos",
  "secret_value": "Sup3r$ecret!",
  "secret_kind": "password",
  "url": "https://gitlab.company.com",
  "notes": "Production GitLab credential",
  "tags": ["gitlab", "production"]
}
```

## Create secret with multiple keys

```http
POST /api/v1/secrets
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "name": "api_fluid",
  "category": "API",
  "username": "service-user",
  "secret_kind": "secret_key",
  "secret_fields": {
    "chave_secret": "xxxxx",
    "intarid": "xxxxxxx",
    "id": "xxxxx"
  },
  "notes": "Structured API credentials",
  "tags": ["api", "fluid"]
}
```

## Read decrypted secret value

```http
GET /api/v1/secrets/1/value
Authorization: Bearer <access_token>
```

Example response for a structured secret:

```json
{
  "secret_value": null,
  "secret_fields": {
    "chave_secret": "xxxxx",
    "intarid": "xxxxxxx",
    "id": "xxxxx"
  }
}
```

## Search

```http
GET /api/v1/secrets/search?q=GitLab
Authorization: Bearer <access_token>
```

## Password generation

```http
POST /api/v1/passwords/generate
Content-Type: application/json

{
  "length": 24,
  "include_symbols": true,
  "include_numbers": true,
  "include_uppercase": true,
  "include_lowercase": true
}
```
