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


def test_admin_required_rejects_user(monkeypatch):
    monkeypatch.setenv("WEB_AUTH_ACCOUNTS", '{"user":{"password":"pw","role":"user"}}')
    app = Flask(__name__)
    app.secret_key = "test"

    @app.get("/admin")
    @authz.admin_required
    def admin_endpoint():
        return jsonify(success=True)

    app.config["TESTING"] = True
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["authenticated"] = True
            sess["username"] = "user"
            sess["role"] = "user"
            sess["auth_version"] = authz.session_version_for_username("user")
        response = client.get("/admin")

    assert response.status_code == 403
    assert response.get_json()["success"] is False


def test_admin_required_allows_admin(monkeypatch):
    monkeypatch.setenv("WEB_AUTH_ACCOUNTS", '{"admin":{"password":"pw","role":"admin"}}')
    app = Flask(__name__)
    app.secret_key = "test"

    @app.get("/admin")
    @authz.admin_required
    def admin_endpoint():
        return jsonify(success=True)

    app.config["TESTING"] = True
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["authenticated"] = True
            sess["username"] = "admin"
            sess["role"] = "admin"
            sess["auth_version"] = authz.session_version_for_username("admin")
        response = client.get("/admin")

    assert response.status_code == 200
    assert response.get_json()["success"] is True



def test_password_change_revokes_existing_session(monkeypatch):
    monkeypatch.setenv("WEB_AUTH_ACCOUNTS", '{"alice":{"password":"old","role":"user"}}')
    app = Flask(__name__)
    app.secret_key = "test"

    with app.test_request_context("/"):
        session["authenticated"] = True
        session["username"] = "alice"
        session["role"] = "user"
        session["auth_version"] = authz.session_version_for_username("alice")
        assert authz.session_is_valid() is True

        monkeypatch.setenv("WEB_AUTH_ACCOUNTS", '{"alice":{"password":"new","role":"user"}}')
        assert authz.session_is_valid() is False


def test_role_change_revokes_existing_session(monkeypatch):
    monkeypatch.setenv("WEB_AUTH_ACCOUNTS", '{"alice":{"password":"pw","role":"admin"}}')
    app = Flask(__name__)
    app.secret_key = "test"

    with app.test_request_context("/"):
        session["authenticated"] = True
        session["username"] = "alice"
        session["role"] = "admin"
        session["auth_version"] = authz.session_version_for_username("alice")
        assert authz.session_is_valid() is True

        monkeypatch.setenv("WEB_AUTH_ACCOUNTS", '{"alice":{"password":"pw","role":"user"}}')
        assert authz.session_is_valid() is False
