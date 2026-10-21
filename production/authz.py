"""Role-based access control for the Flask application.

Roles:
- admin: system/global-data administration plus normal product use.
- user: normal product use on authenticated, account-scoped workflows.

Account configuration remains backward compatible with the existing environment variables.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from functools import wraps
from typing import Dict, Optional, Tuple

from flask import jsonify, request, session


ROLE_ADMIN = "admin"
ROLE_USER = "user"
VALID_ROLES = {ROLE_ADMIN, ROLE_USER}
ROLE_LABELS = {
    ROLE_ADMIN: "管理员",
    ROLE_USER: "使用人员",
}

_INTERNAL_TOKEN_ENV = "BETTAFISH_INTERNAL_TOKEN"
if not os.getenv(_INTERNAL_TOKEN_ENV):
    os.environ[_INTERNAL_TOKEN_ENV] = secrets.token_urlsafe(32)


def normalize_role(value, default: str = ROLE_USER) -> str:
    role = str(value or "").strip().lower()
    return role if role in VALID_ROLES else default


def _decode_json_object(raw: str, *, setting_name: str) -> dict:
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}


def load_accounts() -> Dict[str, dict]:
    """Build the account registry from environment settings.

    Backward compatibility:
    - WEB_AUTH_USERNAME / WEB_AUTH_PASSWORD is the primary account and defaults
      to admin unless WEB_AUTH_PRIMARY_ROLE overrides it.
    - Legacy WEB_AUTH_ACCOUNTS values may still be plain password strings; those
      accounts default to the user role.
    - New WEB_AUTH_ACCOUNTS values may be objects:
      {"alice": {"password": "...", "role": "user"}}
    - WEB_AUTH_ROLES optionally overrides roles without duplicating passwords.
    """
    accounts: Dict[str, dict] = {}

    primary_username = str(os.getenv("WEB_AUTH_USERNAME", "") or "").strip()
    primary_password = str(os.getenv("WEB_AUTH_PASSWORD", "") or "")
    if primary_username:
        accounts[primary_username] = {
            "password": primary_password,
            "role": normalize_role(
                os.getenv("WEB_AUTH_PRIMARY_ROLE", ROLE_ADMIN),
                ROLE_ADMIN,
            ),
        }

    additional = _decode_json_object(
        os.getenv("WEB_AUTH_ACCOUNTS", ""),
        setting_name="WEB_AUTH_ACCOUNTS",
    )
    for raw_username, spec in additional.items():
        username = str(raw_username or "").strip()
        if not username:
            continue
        if isinstance(spec, dict):
            password = str(spec.get("password") or "")
            role = normalize_role(spec.get("role"), ROLE_USER)
        else:
            password = str(spec or "")
            role = ROLE_USER
        accounts[username] = {"password": password, "role": role}

    overrides = _decode_json_object(
        os.getenv("WEB_AUTH_ROLES", ""),
        setting_name="WEB_AUTH_ROLES",
    )
    for raw_username, raw_role in overrides.items():
        username = str(raw_username or "").strip()
        if username in accounts:
            accounts[username]["role"] = normalize_role(
                raw_role,
                accounts[username]["role"],
            )

    return accounts


def credentials_configured() -> bool:
    return any(
        username and str(record.get("password") or "")
        for username, record in load_accounts().items()
    )


def authenticate_account(username: str, password: str) -> Tuple[Optional[str], bool]:
    """Return (role, configured). role is None for failed authentication."""
    accounts = load_accounts()
    configured = any(
        name and str(record.get("password") or "")
        for name, record in accounts.items()
    )
    record = accounts.get(str(username or ""))
    if not configured or not record:
        return None, configured

    expected = str(record.get("password") or "")
    if expected and hmac.compare_digest(str(password or ""), expected):
        return normalize_role(record.get("role"), ROLE_USER), configured
    return None, configured


def role_for_username(username: str) -> Optional[str]:
    record = load_accounts().get(str(username or ""))
    if not record or not str(record.get("password") or ""):
        return None
    return normalize_role(record.get("role"), ROLE_USER)


def session_version_for_username(username: str) -> Optional[str]:
    """Fingerprint current account credentials/role without exposing the password."""
    record = load_accounts().get(str(username or ""))
    if not record:
        return None
    password = str(record.get("password") or "")
    if not password:
        return None
    role = normalize_role(record.get("role"), ROLE_USER)
    material = f"{username}\0{password}\0{role}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def session_is_valid() -> bool:
    if session.get("authenticated") is not True:
        return False
    username = str(session.get("username") or "")
    supplied_version = str(session.get("auth_version") or "")
    expected_version = session_version_for_username(username)
    return bool(
        username
        and supplied_version
        and expected_version
        and hmac.compare_digest(supplied_version, expected_version)
    )


def current_role() -> Optional[str]:
    if not session_is_valid():
        return None
    username = str(session.get("username") or "")
    role = role_for_username(username)
    if role:
        session["role"] = role
    return role


def current_username() -> str:
    if not session_is_valid():
        return ""
    return str(session.get("username") or "")


def is_internal_request() -> bool:
    """Authenticate a same-host service-to-service HTTP request.

    A random token is generated once in the Flask parent process and inherited by
    child workers. The token is required in addition to a loopback source address,
    so an external request forwarded by a reverse proxy cannot use this bypass.
    """
    supplied = str(request.headers.get("X-BettaFish-Internal-Token") or "")
    expected = str(os.getenv(_INTERNAL_TOKEN_ENV) or "")
    remote = str(request.remote_addr or "")
    if remote not in {"127.0.0.1", "::1"} or not supplied or not expected:
        return False
    return hmac.compare_digest(supplied, expected)


def role_label(role: Optional[str]) -> str:
    return ROLE_LABELS.get(str(role or ""), "使用人员")


def require_roles_response(*allowed_roles: str):
    """Return None when allowed, otherwise a JSON (response, status) tuple."""
    if not session_is_valid() or not current_username():
        return jsonify(success=False, message="请先登录"), 401

    role = current_role()
    allowed = {normalize_role(item) for item in allowed_roles}
    if role not in allowed:
        return jsonify(
            success=False,
            message="当前账号无权执行此操作",
            required_role="admin" if allowed == {ROLE_ADMIN} else sorted(allowed),
        ), 403
    return None


def role_required(*allowed_roles: str):
    def decorator(func):
        @wraps(func)
        def wrapped(*args, **kwargs):
            denied = require_roles_response(*allowed_roles)
            if denied is not None:
                return denied
            return func(*args, **kwargs)

        return wrapped

    return decorator


admin_required = role_required(ROLE_ADMIN)
authenticated_required = role_required(ROLE_ADMIN, ROLE_USER)
