import pytest
from flask import redirect
from app import app, db


def test_login_google_redirects(client, monkeypatch):
    """Visiting /login/google should return a redirect to the provider (mocked)."""

    def fake_authorize_redirect(uri):
        # Return a Flask redirect response like Authlib would
        return redirect("https://accounts.google.com/o/oauth2/auth?fake")

    monkeypatch.setattr(app.oauth.google, "authorize_redirect", fake_authorize_redirect)

    resp = client.get("/login/google")
    assert resp.status_code in (301, 302)
    assert "accounts.google.com" in resp.headers.get("Location", "")


def test_auth_google_creates_user(client, monkeypatch):
    """Simulate provider callback and ensure a user row is created and user is logged in."""

    def fake_authorize_access_token():
        return {"access_token": "dummy", "id_token": "dummy"}

    def fake_parse_id_token(token):
        return {"email": "guser@example.com"}

    monkeypatch.setattr(app.oauth.google, "authorize_access_token", fake_authorize_access_token)
    monkeypatch.setattr(app.oauth.google, "parse_id_token", fake_parse_id_token)

    # Call the auth endpoint (follow redirect to final page)
    resp = client.get("/auth/google", follow_redirects=True)
    assert resp.status_code == 200

    # Verify the DB contains the created user (local-part of email used as username)
    users = db.execute("SELECT username FROM users WHERE username LIKE ?", "guser%")
    assert users is not None
    assert len(users) > 0
