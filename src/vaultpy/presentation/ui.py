"""NiceGUI interface for VaultPy."""

from __future__ import annotations

import json
from collections.abc import MutableMapping
from typing import Any

from fastapi import FastAPI
from nicegui import app as nicegui_app
from nicegui import ui

from vaultpy.application.dto import (
    LoginRequest,
    PasswordGenerateRequest,
    RefreshRequest,
    SecretCreateRequest,
    SecretUpdateRequest,
    SetupRequest,
)
from vaultpy.application.services import AuthService
from vaultpy.domain.entities import AuthenticatedContext, SecretKind
from vaultpy.domain.exceptions import AuthorizationError, VaultPyError
from vaultpy.presentation.dependencies import Container


def clear_auth_storage(storage: MutableMapping[str, Any]) -> None:
    """Remove authentication tokens from UI storage."""
    storage.pop("access_token", None)
    storage.pop("refresh_token", None)


def resolve_authenticated_context(
    storage: MutableMapping[str, Any],
    auth_service: AuthService,
) -> AuthenticatedContext | None:
    """Resolve a valid UI session context, refreshing tokens when possible."""
    access_token = storage.get("access_token")
    if not access_token:
        return None
    try:
        return auth_service.context_from_token(str(access_token))
    except AuthorizationError:
        refresh_token = storage.get("refresh_token")
        if not refresh_token:
            clear_auth_storage(storage)
            return None
        try:
            tokens = auth_service.refresh(RefreshRequest(refresh_token=str(refresh_token)))
            storage["access_token"] = tokens.access_token
            storage["refresh_token"] = tokens.refresh_token
            return auth_service.context_from_token(tokens.access_token)
        except AuthorizationError:
            clear_auth_storage(storage)
            return None


def collect_secret_fields(rows: list[dict[str, str]]) -> dict[str, str]:
    """Normalize dashboard key/value rows into a structured secret mapping."""
    normalized: dict[str, str] = {}
    for row in rows:
        key = str(row.get("key", "")).strip()
        value = str(row.get("value", "")).strip()
        if key and value:
            normalized[key] = value
    return normalized


def secret_field_rows_from_mapping(secret_fields: dict[str, str]) -> list[dict[str, str]]:
    """Convert stored structured fields into editable dashboard rows."""
    return [{"key": key, "value": value} for key, value in secret_fields.items()]


def register_ui(fastapi_app: FastAPI, container: Container) -> None:
    """Register all NiceGUI pages and mount them on the FastAPI app."""

    def token() -> str | None:
        return nicegui_app.storage.user.get("access_token")

    def redirect() -> None:
        if not container.auth_service.is_bootstrapped():
            ui.navigate.to("/setup")
        elif resolve_authenticated_context(
            nicegui_app.storage.user,
            container.auth_service,
        ):
            ui.navigate.to("/app")
        else:
            ui.navigate.to("/login")

    def current_context() -> AuthenticatedContext:
        context = resolve_authenticated_context(
            nicegui_app.storage.user,
            container.auth_service,
        )
        if context is None:
            raise AuthorizationError("Please sign in first.")
        return context

    def notify_error(exc: Exception) -> None:
        ui.notify(str(exc), color="negative")

    def parse_tags(raw_value: object) -> list[str]:
        return [item.strip() for item in str(raw_value or "").split(",") if item.strip()]

    @ui.page("/")
    def index_page() -> None:
        redirect()

    @ui.page("/setup")
    def setup_page() -> None:
        if container.auth_service.is_bootstrapped():
            ui.navigate.to("/login")
            return
        with ui.column().classes("w-full max-w-lg mx-auto gap-4 mt-16"):
            ui.label("VaultPy Setup").classes("text-3xl font-bold")
            ui.label("Configure the master password to unlock the local secure vault.")
            password = ui.input("Master password", password=True, password_toggle_button=True).classes("w-full")
            confirm = ui.input("Confirm master password", password=True, password_toggle_button=True).classes("w-full")

            def submit() -> None:
                try:
                    if password.value != confirm.value:
                        raise VaultPyError("Master password confirmation does not match.")
                    container.auth_service.bootstrap(SetupRequest(master_password=str(password.value)), "ui-local")
                    ui.notify("Vault initialized successfully.", color="positive")
                    ui.navigate.to("/login")
                except Exception as exc:  # pragma: no cover
                    notify_error(exc)

            ui.button("Initialize vault", on_click=submit).classes("bg-primary text-white")

    @ui.page("/login")
    def login_page() -> None:
        if not container.auth_service.is_bootstrapped():
            ui.navigate.to("/setup")
            return
        with ui.column().classes("w-full max-w-lg mx-auto gap-4 mt-16"):
            ui.label("VaultPy Login").classes("text-3xl font-bold")
            ui.label("Use the master password to unlock encrypted secrets and the API session.")
            password = ui.input("Master password", password=True, password_toggle_button=True).classes("w-full")

            def submit() -> None:
                try:
                    tokens = container.auth_service.login(LoginRequest(master_password=str(password.value)), "ui-local")
                    nicegui_app.storage.user["access_token"] = tokens.access_token
                    nicegui_app.storage.user["refresh_token"] = tokens.refresh_token
                    ui.notify("Login successful.", color="positive")
                    ui.navigate.to("/app")
                except Exception as exc:  # pragma: no cover
                    notify_error(exc)

            ui.button("Sign in", on_click=submit).classes("bg-primary text-white")

    @ui.page("/app")
    def vault_page() -> None:
        try:
            context = current_context()
        except Exception:
            redirect()
            return

        dashboard = container.secret_service.dashboard()
        with ui.column().classes("w-full max-w-7xl mx-auto gap-6 p-6"):
            edit_dialog: Any
            generator_dialog: Any
            logout_dialog: Any

            with ui.row().classes("w-full items-center justify-between"):
                with ui.column().classes("gap-1"):
                    ui.label("VaultPy Dashboard").classes("text-3xl font-bold")
                    ui.label("FastAPI + NiceGUI secure secrets manager")
                with ui.row().classes("gap-2"):
                    ui.button("Audit Logs", on_click=lambda: open_audit_logs())
                    ui.button("Generate Password", on_click=lambda: generator_dialog.open())
                    ui.button("New Secret", on_click=lambda: open_new_secret()).classes("bg-primary text-white")
                    ui.button("Logout", on_click=lambda: logout_dialog.open(), color="negative")

            stat_total = ui.label(f"Total secrets: {dashboard.total_secrets}").classes("text-lg font-medium")
            stat_categories = ui.label(
                "Categories: " + ", ".join(f"{name} ({count})" for name, count in dashboard.categories.items())
            )
            stat_last_access = ui.label(
                f"Last access: {dashboard.last_access_at.isoformat() if dashboard.last_access_at else 'Never'}"
            )

            search_box = ui.input("Real-time search by name, category, or tag").classes("w-full")
            table = ui.table(
                columns=[
                    {"name": "id", "label": "ID", "field": "id"},
                    {"name": "name", "label": "Name", "field": "name"},
                    {"name": "category", "label": "Category", "field": "category"},
                    {"name": "updated_at", "label": "Updated At", "field": "updated_at"},
                    {"name": "actions", "label": "Actions", "field": "actions", "align": "right"},
                ],
                rows=[],
                row_key="id",
                selection="single",
                pagination=10,
            ).classes("w-full")

            with ui.dialog() as edit_dialog, ui.card().classes("w-[720px] max-w-full"):
                ui.label("Add secret").classes("text-xl font-semibold")
                form_name = ui.input("Name").classes("w-full")
                form_category = ui.select(
                    container.categories, label="Category", value=container.categories[0]
                ).classes("w-full")
                form_kind = SecretKind.SECRET_KEY
                secret_field_rows: list[dict[str, str]] = []
                ui.label("Secret Fields").classes("text-sm font-medium")
                fields_container = ui.column().classes("w-full gap-2")
                form_notes = ui.textarea("Notes").classes("w-full")
                form_tags = ui.input("Tags (comma separated)").classes("w-full")
                form_secret_id: dict[str, int | None] = {"value": None}

                def update_secret_field(index: int, field_name: str, value: object) -> None:
                    secret_field_rows[index][field_name] = str(value or "")

                def render_secret_fields() -> None:
                    fields_container.clear()
                    with fields_container:
                        if not secret_field_rows:
                            ui.label("Add key/value pairs for grouped secrets like api_fluid.").classes(
                                "text-sm text-gray-500"
                            )
                        for index, row in enumerate(secret_field_rows):
                            with ui.row().classes("w-full items-center gap-2"):
                                ui.input(
                                    "Key",
                                    value=row["key"],
                                    on_change=lambda e, idx=index: update_secret_field(
                                        idx,
                                        "key",
                                        e.value,
                                    ),
                                ).classes("w-1/3")
                                ui.input(
                                    "Value",
                                    value=row["value"],
                                    password=True,
                                    password_toggle_button=True,
                                    on_change=lambda e, idx=index: update_secret_field(
                                        idx,
                                        "value",
                                        e.value,
                                    ),
                                ).classes("flex-1")
                                ui.button(
                                    "Remove",
                                    on_click=lambda idx=index: remove_secret_field_row(idx),
                                    color="negative",
                                )

                def add_secret_field_row(
                    key: str = "",
                    value: str = "",
                ) -> None:
                    secret_field_rows.append({"key": key, "value": value})
                    render_secret_fields()

                def remove_secret_field_row(index: int) -> None:
                    secret_field_rows.pop(index)
                    render_secret_fields()

                def reset_form() -> None:
                    form_secret_id["value"] = None
                    form_name.value = ""
                    form_category.value = container.categories[0]
                    secret_field_rows.clear()
                    render_secret_fields()
                    form_notes.value = ""
                    form_tags.value = ""

                def save_secret() -> None:
                    try:
                        if form_secret_id["value"] is None:
                            request = SecretCreateRequest(
                                name=str(form_name.value),
                                category=str(form_category.value),
                                secret_kind=form_kind,
                                secret_fields=collect_secret_fields(secret_field_rows),
                                notes=str(form_notes.value) or None,
                                tags=parse_tags(form_tags.value),
                            )
                            container.secret_service.create_secret(context, request, "ui-local")
                            ui.notify("Secret created.", color="positive")
                        else:
                            update_request = SecretUpdateRequest(
                                name=str(form_name.value),
                                category=str(form_category.value),
                                secret_kind=form_kind,
                                secret_fields=collect_secret_fields(secret_field_rows),
                                notes=str(form_notes.value) or None,
                                tags=parse_tags(form_tags.value),
                            )
                            container.secret_service.update_secret(
                                context,
                                int(form_secret_id["value"]),
                                update_request,
                                "ui-local",
                            )
                            ui.notify("Secret updated.", color="positive")
                        refresh_dashboard()
                        refresh_rows()
                        refresh_audits()
                        edit_dialog.close()
                    except Exception as exc:  # pragma: no cover
                        notify_error(exc)

                with ui.row().classes("justify-end w-full"):
                    ui.button("Add Secret Field", on_click=add_secret_field_row)
                    ui.button("Cancel", on_click=edit_dialog.close)
                    ui.button("Save", on_click=save_secret).classes("bg-primary text-white")

            with ui.dialog() as generator_dialog, ui.card().classes("w-[480px] max-w-full"):
                ui.label("Password Generator").classes("text-xl font-semibold")
                gen_length = ui.number("Length", value=24, min=12, max=128).classes("w-full")
                gen_symbols = ui.checkbox("Include symbols", value=True)
                gen_numbers = ui.checkbox("Include numbers", value=True)
                gen_upper = ui.checkbox("Include uppercase", value=True)
                gen_lower = ui.checkbox("Include lowercase", value=True)
                generated = ui.input("Generated password").props("readonly").classes("w-full")

                def generate_password() -> None:
                    try:
                        response = container.secret_service.generate_password(
                            PasswordGenerateRequest(
                                length=int(gen_length.value or 24),
                                include_symbols=bool(gen_symbols.value),
                                include_numbers=bool(gen_numbers.value),
                                include_uppercase=bool(gen_upper.value),
                                include_lowercase=bool(gen_lower.value),
                            )
                        )
                        generated.value = response.password
                    except Exception as exc:  # pragma: no cover
                        notify_error(exc)

                with ui.row().classes("justify-end w-full"):
                    ui.button("Generate", on_click=generate_password)
                    ui.button(
                        "Copy",
                        on_click=lambda: ui.run_javascript(
                            f"navigator.clipboard.writeText({json.dumps(str(generated.value or ''))})"
                        ),
                    )

            def logout() -> None:
                access_token = str(nicegui_app.storage.user.get("access_token", ""))
                try:
                    if access_token:
                        container.auth_service.logout(access_token, "ui-local")
                except AuthorizationError:
                    ui.notify("Session already expired. Signed out locally.", color="warning")
                finally:
                    clear_auth_storage(nicegui_app.storage.user)
                    logout_dialog.close()
                    ui.navigate.to("/login")

            with ui.dialog() as logout_dialog, ui.card().classes("w-[420px] max-w-full"):
                ui.label("Confirm logout").classes("text-xl font-semibold")
                ui.label("Are you sure you want to sign out?")
                with ui.row().classes("justify-end w-full gap-2"):
                    ui.button("Cancel", on_click=logout_dialog.close)
                    ui.button("Logout", on_click=logout, color="negative")

            with ui.dialog() as audit_dialog, ui.card().classes("w-[960px] max-w-full"):
                ui.label("Audit Logs").classes("text-xl font-semibold")
                audit_table = ui.table(
                    columns=[
                        {"name": "created_at", "label": "Timestamp", "field": "created_at"},
                        {"name": "action", "label": "Action", "field": "action"},
                        {"name": "user", "label": "User", "field": "user"},
                        {"name": "ip_address", "label": "Source", "field": "ip_address"},
                        {"name": "details", "label": "Details", "field": "details"},
                    ],
                    rows=[],
                    row_key="id",
                    pagination=10,
                ).classes("w-full")
                with ui.row().classes("justify-end w-full"):
                    ui.button("Close", on_click=audit_dialog.close)

            pending_delete: dict[str, int | str | None] = {"id": None, "name": None}
            with ui.dialog() as delete_dialog, ui.card().classes("w-[420px] max-w-full"):
                ui.label("Confirm deletion").classes("text-xl font-semibold")
                delete_message = ui.label("Are you sure you want to delete this secret?")
                with ui.row().classes("justify-end w-full gap-2"):
                    ui.button("Cancel", on_click=delete_dialog.close)
                    ui.button("Delete", on_click=lambda: confirm_delete_secret(), color="negative")

            def resolve_secret_id(secret_id: int | None = None) -> int | None:
                if secret_id is not None:
                    return secret_id
                selected_rows = table.selected
                if not selected_rows:
                    ui.notify("Select a secret first.", color="warning")
                    return None
                return int(selected_rows[0]["id"])

            def refresh_dashboard() -> None:
                current = container.secret_service.dashboard()
                stat_total.text = f"Total secrets: {current.total_secrets}"
                stat_categories.text = "Categories: " + ", ".join(
                    f"{name} ({count})" for name, count in current.categories.items()
                )
                last_access = current.last_access_at.isoformat() if current.last_access_at else "Never"
                stat_last_access.text = f"Last access: {last_access}"

            def refresh_rows() -> None:
                secrets = container.secret_service.list_secrets(query=str(search_box.value or "").strip() or None)
                table.rows = [
                    {
                        "id": secret.id,
                        "name": secret.name,
                        "category": secret.category,
                        "updated_at": secret.updated_at.isoformat(timespec="seconds"),
                    }
                    for secret in secrets
                ]
                table.update()

            def refresh_audits() -> None:
                audit_table.rows = [
                    {
                        "id": entry.id,
                        "created_at": entry.created_at.isoformat(timespec="seconds"),
                        "action": entry.action.upper(),
                        "user": entry.user,
                        "ip_address": entry.ip_address,
                        "details": entry.details,
                    }
                    for entry in container.secret_service.list_audit_logs()
                ]
                audit_table.update()

            def open_audit_logs() -> None:
                refresh_audits()
                audit_dialog.open()

            def open_new_secret() -> None:
                reset_form()
                edit_dialog.open()

            def populate_for_edit(secret_id: int) -> None:
                secret = container.secret_service.get_secret(secret_id)
                secret_content = container.secret_service.get_secret_value(
                    context,
                    secret_id,
                    "ui-local",
                )
                form_secret_id["value"] = secret.id
                form_name.value = secret.name
                form_category.value = secret.category
                secret_field_rows.clear()
                secret_field_rows.extend(secret_field_rows_from_mapping(secret_content.secret_fields))
                render_secret_fields()
                form_notes.value = secret.notes or ""
                form_tags.value = ",".join(secret.tags)

            def view_secret(secret_id: int | None = None) -> None:
                secret_id = resolve_secret_id(secret_id)
                if secret_id is None:
                    return
                try:
                    secret = container.secret_service.get_secret(secret_id)
                    content = container.secret_service.get_secret_value(
                        context,
                        secret_id,
                        "ui-local",
                    )
                    with ui.dialog() as dialog, ui.card().classes("w-[680px] max-w-full"):
                        ui.label(secret.name).classes("text-xl font-semibold")
                        ui.label(f"Category: {secret.category}")
                        ui.label(f"Type: {secret.secret_kind.value}")
                        ui.label(f"Tags: {', '.join(secret.tags) if secret.tags else '-'}")
                        ui.label(f"Notes: {secret.notes or '-'}")
                        ui.label(f"Secret Value: {content.secret_value or '-'}")
                        if content.secret_fields:
                            ui.label("Secret Fields:")
                            ui.code(
                                json.dumps(content.secret_fields, indent=2, ensure_ascii=True),
                                language="json",
                            ).classes("w-full")
                        ui.button("Close", on_click=dialog.close)
                    dialog.open()
                    refresh_audits()
                except Exception as exc:  # pragma: no cover
                    notify_error(exc)

            def edit_secret(secret_id: int | None = None) -> None:
                secret_id = resolve_secret_id(secret_id)
                if secret_id is None:
                    return
                try:
                    populate_for_edit(secret_id)
                    edit_dialog.open()
                except Exception as exc:  # pragma: no cover
                    notify_error(exc)

            def request_delete_secret(secret_id: int | None = None) -> None:
                secret_id = resolve_secret_id(secret_id)
                if secret_id is None:
                    return
                try:
                    secret = container.secret_service.get_secret(secret_id)
                    pending_delete["id"] = secret.id
                    pending_delete["name"] = secret.name
                    delete_message.text = f"Delete secret '{secret.name}'? This action cannot be undone."
                    delete_dialog.open()
                except Exception as exc:  # pragma: no cover
                    notify_error(exc)

            def confirm_delete_secret() -> None:
                secret_id = pending_delete["id"]
                if not isinstance(secret_id, int):
                    ui.notify("No secret selected for deletion.", color="warning")
                    delete_dialog.close()
                    return
                try:
                    container.secret_service.delete_secret(context, secret_id, "ui-local")
                    ui.notify("Secret deleted.", color="positive")
                    pending_delete["id"] = None
                    pending_delete["name"] = None
                    delete_dialog.close()
                    refresh_dashboard()
                    refresh_rows()
                    refresh_audits()
                except Exception as exc:  # pragma: no cover
                    notify_error(exc)

            def copy_secret(secret_id: int | None = None) -> None:
                secret_id = resolve_secret_id(secret_id)
                if secret_id is None:
                    return
                try:
                    content = container.secret_service.get_secret_value(
                        context,
                        secret_id,
                        "ui-local",
                    )
                    copy_value = (
                        json.dumps(content.secret_fields, indent=2, ensure_ascii=True)
                        if content.secret_fields
                        else str(content.secret_value or "")
                    )
                    ui.run_javascript(f"navigator.clipboard.writeText({json.dumps(copy_value)})")
                    ui.notify("Secret copied to clipboard.", color="positive")
                    refresh_audits()
                except Exception as exc:  # pragma: no cover
                    notify_error(exc)

            with table.add_slot("body-cell-actions"):
                with table.cell("actions"):
                    with ui.row().classes("items-center justify-end no-wrap q-gutter-xs"):
                        ui.button(icon="visibility").props("flat round dense color=primary").tooltip("View").on(
                            "click",
                            handler=lambda e: view_secret(int(e.args)),
                            js_handler="() => emit(props.row.id)",
                        )
                        ui.button(icon="edit").props("flat round dense color=secondary").tooltip("Edit").on(
                            "click",
                            handler=lambda e: edit_secret(int(e.args)),
                            js_handler="() => emit(props.row.id)",
                        )
                        ui.button(icon="content_copy").props("flat round dense color=accent").tooltip("Copy").on(
                            "click",
                            handler=lambda e: copy_secret(int(e.args)),
                            js_handler="() => emit(props.row.id)",
                        )
                        ui.button(icon="delete").props("flat round dense color=negative").tooltip("Delete").on(
                            "click",
                            handler=lambda e: request_delete_secret(int(e.args)),
                            js_handler="() => emit(props.row.id)",
                        )
            search_box.on("update:model-value", lambda _: refresh_rows())
            reset_form()
            refresh_rows()
            refresh_audits()

    ui.run_with(
        fastapi_app,
        mount_path="/",
        storage_secret=container.settings.ui_storage_secret,
        reconnect_timeout=30.0,
        title=container.settings.app_name,
    )
