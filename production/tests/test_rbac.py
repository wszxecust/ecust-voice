import pytest
from flask import Flask, jsonify, session

import authz


_ENV_KEYS = (
    "WEB_AUTH_USERNAME",
    "WEB_AUTH_PASSWORD",
    "WEB_AUTH_PRIMARY_ROLE",
    "WEB_AUTH_ACCOUNTS",
    "WEB_AUTH_ROLES",
)


@pytest.fixture(autouse=True)
def clean_auth_env(monkeypatch):
    for key in _ENV_KEYS:
        monkeypatch.delenv(key, raising=False)


def test_primary_account_defaults_to_admin(monkeypatch):
    monkeypatch.setenv("WEB_AUTH_USERNAME", "root")
    monkeypatch.setenv("WEB_AUTH_PASSWORD", "secret")

    role, configured = authz.authenticate_account("root", "secret")

    assert configured is True
    assert role == authz.ROLE_ADMIN


def test_legacy_additional_account_defaults_to_user(monkeypatch):
    monkeypatch.setenv("WEB_AUTH_ACCOUNTS", '{"reader":"pw"}')

    role, configured = authz.authenticate_account("reader", "pw")

    assert configured is True
    assert role == authz.ROLE_USER


def test_structured_account_can_be_admin(monkeypatch):
    monkeypatch.setenv(
        "WEB_AUTH_ACCOUNTS",
        '{"ops":{"password":"pw","role":"admin"}}',
    )

    role, _ = authz.authenticate_account("ops", "pw")

    assert role == authz.ROLE_ADMIN


def test_role_override_wins(monkeypatch):
    monkeypatch.setenv("WEB_AUTH_ACCOUNTS", '{"alice":"pw"}')
    monkeypatch.setenv("WEB_AUTH_ROLES", '{"alice":"admin"}')

    role, _ = authz.authenticate_account("alice", "pw")

    assert role == authz.ROLE_ADMIN


def test_admin_required_rejects_user():
    app = Flask(__name__)
    app.secret_key = "test"

    @app.get("/admin")
    @authz.admin_required
    def admin_endpoint():
        return jsonify(success=True)

    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["authenticated"] = True
            sess["username"] = "user"
            sess["role"] = "user"
        response = client.get("/admin")

    assert response.status_code == 403
    assert response.get_json()["success"] is False


def test_admin_required_allows_admin():
    app = Flask(__name__)
    app.secret_key = "test"

    @app.get("/admin")
    @authz.admin_required
    def admin_endpoint():
        return jsonify(success=True)

    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["authenticated"] = True
            sess["username"] = "admin"
            sess["role"] = "admin"
        response = client.get("/admin")

    assert response.status_code == 200
    assert response.get_json()["success"] is True
