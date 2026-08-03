# VaultPy - Complete Project Generation Prompt

## Context

Act as a Senior Software Architect, Cybersecurity Specialist, Senior Python Developer, Open Source Maintainer, and Product Engineer.

Design and implement a production-ready Open Source project called **VaultPy**.

VaultPy is a lightweight secure secrets manager built entirely with Python.

The application must provide:

- Web Interface
- REST API
- Secure Secret Storage
- CRUD Management
- Audit Logs
- Master Password Authentication
- Encryption at Rest
- Open Source Quality Standards

The project must be suitable for developers, RPA professionals, DevOps engineers, and small teams.

---

# Project Vision

VaultPy is a simplified alternative to:

- HashiCorp Vault
- Azure Key Vault
- AWS Secrets Manager

Focused on:

- Local usage
- Small teams
- Simplicity
- Security
- Easy installation

---

# Technology Stack

## Backend

- Python 3.12+
- FastAPI
- Pydantic v2
- SQLAlchemy 2.x
- Alembic

## Frontend

- NiceGUI

Entire UI must be developed in Python.

No React.
No Angular.
No Vue.

---

## Database

- PostgreSQL

---

## Security

- Cryptography (Fernet)
- PBKDF2-HMAC-SHA256
- Secrets Module

---

## Logging

- Loguru

---

## Testing

- Pytest
- Pytest-Cov
- Factory Boy

---

## Quality

- Ruff
- Black
- Flake8
- isort
- MyPy

---

## Containerization

- Docker
- Docker Compose

---

# Core Features

## Master Password

First application startup:

User creates:

- Master Password

Requirements:

- Minimum 12 characters
- Uppercase
- Lowercase
- Number
- Special character

Never store password in plain text.

Store only:

- Hash
- Salt

Implement:

- PBKDF2-HMAC-SHA256

---

# Secrets CRUD

Create complete CRUD.

Fields:

- Name
- Category
- Username
- Password
- URL
- Notes
- Tags
- Created At
- Updated At

Example:

GitLab Production

Username:
farley.santos

Password:
********

URL:
https://gitlab.company.com

---

# Categories

Default categories:

- Database
- API
- Git
- Cloud
- RPA
- Infrastructure
- Email
- Other

---

# Search

Implement real-time search.

Search by:

- Name
- Category
- Username
- Tags

---

# Secret Encryption

Sensitive fields must always be encrypted.

Required:

- Password
- Token
- Secret Key
- Connection String

Encryption at database level.

Never store plaintext secrets.

---

# Web Interface

Develop entire frontend using NiceGUI.

## Dashboard

Display:

- Total Secrets
- Categories
- Recent Updates
- Last Access

---

## Secret List

Display table:

- Name
- Category
- Username
- Updated At

Actions:

- View
- Edit
- Delete
- Copy Password

---

## Create Secret

Modern form.

Validation.

Clear error messages.

---

## Update Secret

Edit any field.

Audit changes.

---

## Delete Secret

Confirmation required.

Soft Delete preferred.

---

## Password Generator

Options:

- Length
- Symbols
- Numbers
- Uppercase
- Lowercase

Generate strong passwords.

---

# REST API

Create API versioning.

Base URL:

/api/v1

---

## Create Secret

POST /api/v1/secrets

---

## List Secrets

GET /api/v1/secrets

---

## Get Secret

GET /api/v1/secrets/{id}

---

## Update Secret

PUT /api/v1/secrets/{id}

---

## Delete Secret

DELETE /api/v1/secrets/{id}

---

## Get Secret Value

GET /api/v1/secrets/{id}/value

Return decrypted secret only for authenticated requests.

---

## Search Secret

GET /api/v1/secrets/search

---

# API Authentication

Implement:

- JWT Authentication

Endpoints:

POST /api/v1/auth/login

POST /api/v1/auth/refresh

---

# Audit Log

Track:

- Login
- Logout
- Create
- Update
- Delete
- Secret View

Fields:

- User
- Action
- Date
- IP

---

# Architecture

Use Clean Architecture.

```text
src/
├── domain/
├── application/
├── infrastructure/
├── presentation/
├── shared/
├── tests/
├── docs/
└── scripts/
```

---

# SOLID Requirements

Apply:

- Single Responsibility Principle
- Open Closed Principle
- Liskov Substitution Principle
- Interface Segregation Principle
- Dependency Inversion Principle

---

# Design Patterns

Implement when appropriate:

- Repository Pattern
- Factory Pattern
- Strategy Pattern
- Dependency Injection
- Unit Of Work

---

# Error Handling

Custom Exceptions:

- SecretNotFoundError
- InvalidMasterPasswordError
- EncryptionError
- AuthenticationError
- AuthorizationError
- ValidationError

Never use:

except:
    pass

---

# Logging

Use Loguru.

Levels:

- INFO
- WARNING
- ERROR
- CRITICAL

Log every business operation.

---

# Security Requirements

Mandatory:

- Encryption At Rest
- Input Validation
- Secure Headers
- JWT Authentication
- Password Hashing
- Secret Rotation Ready
- Rate Limiting Ready
- Environment Variables
- No Hardcoded Secrets

---

# Testing

Minimum:

80% Coverage

Implement:

- Unit Tests
- Integration Tests
- API Tests
- Security Tests

---

# Documentation

Generate:

- README.md
- CONTRIBUTING.md
- CHANGELOG.md
- ROADMAP.md
- ARCHITECTURE.md
- API.md
- SECURITY.md
- LICENSE (MIT)

---

# CI/CD

Create GitHub Actions workflows.

Run:

- Ruff
- Black Check
- Flake8
- MyPy
- Pytest

---

# Code Standards

Mandatory:

- Type Hints Everywhere
- Google Style Docstrings
- Clean Code
- Small Classes
- Small Functions
- No Business Rules in UI
- No Business Rules in Controllers
- Explicit Names
- No Duplicate Code

---

# Deliverables

Generate:

1. Complete folder structure.
2. Domain layer.
3. Database models.
4. Encryption service.
5. Authentication module.
6. REST API.
7. NiceGUI web interface.
8. Secrets CRUD.
9. Password generator.
10. Audit logs.
11. Unit tests.
12. Integration tests.
13. Dockerfile.
14. Docker Compose.
15. GitHub Actions.
16. Complete documentation.
17. Example screenshots placeholders.
18. API examples.
19. Installation guide.
20. Production deployment guide.

---

# Acceptance Criteria

Project is complete only if:

- Application starts successfully.
- Master password works.
- Secrets are encrypted.
- CRUD works.
- Search works.
- JWT authentication works.
- API works.
- NiceGUI interface works.
- Audit log works.
- Tests pass.
- Coverage >= 80%.
- Lint passes.
- Type checking passes.
- Documentation is complete.
- Ready for GitHub publication.

####################

