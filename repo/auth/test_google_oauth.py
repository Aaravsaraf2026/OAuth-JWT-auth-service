"""
Tests for google_oauth wrapper.

Run:
    pip install pytest pytest-asyncio httpx
    pytest test_google_oauth.py -v
"""

import asyncio
import os
import time
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta, timezone

# Set env before import
os.environ.update({
    "GOOGLE_CLIENT_ID":     "test-client-id",
    "GOOGLE_CLIENT_SECRET": "test-client-secret",
    "GOOGLE_REDIRECT_URI":  "http://localhost:8000/auth/callback",
    "APP_SECRET_KEY":       "a" * 40,  # 40-char key passes entropy check
    "REDIRECT_AFTER_LOGIN": "/home",
    "ENVIRONMENT":          "development",
})

import google_oauth as auth_module
from google_oauth import (
    GoogleOAuth,
    _InMemoryStore,
    _RateLimiter,
    OAuthConfigError,
    OAuthNotInitializedError,
    setup,
    get,
)


# ─────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────

@pytest.fixture
def cfg():
    return {
        "client_id":           "test-client-id",
        "client_secret":       "test-secret",
        "redirect_uri":        "http://localhost:8000/auth/callback",
        "secret_key":          "x" * 40,
        "redirect_after_login": "/home",
        "environment":         "development",
        "session_ttl":         900,
        "cookie_domain":       None,
    }


@pytest_asyncio.fixture
async def store():
    s = _InMemoryStore()
    await s.start()
    yield s
    await s.stop()


@pytest_asyncio.fixture
async def oauth(cfg, store):
    instance = GoogleOAuth(cfg, store)
    await instance.initialize()
    yield instance
    await instance.shutdown()


def mock_request(cookies: dict = None, query_params: dict = None, ip: str = "127.0.0.1"):
    req = MagicMock()
    req.cookies = cookies or {}
    req.query_params = query_params or {}
    req.headers = {}
    req.client = MagicMock()
    req.client.host = ip
    return req


# ─────────────────────────────────────────────
# setup() validation tests
# ─────────────────────────────────────────────

class TestSetup:
    def test_missing_env_raises(self, monkeypatch):
        monkeypatch.delenv("GOOGLE_CLIENT_ID", raising=False)
        auth_module._instance = None
        with pytest.raises(OAuthConfigError, match="GOOGLE_CLIENT_ID"):
            setup()

    def test_weak_secret_too_short(self, monkeypatch):
        monkeypatch.setenv("APP_SECRET_KEY", "short")
        auth_module._instance = None
        with pytest.raises(OAuthConfigError, match="32 characters"):
            setup()

    def test_weak_secret_low_entropy(self, monkeypatch):
        monkeypatch.setenv("APP_SECRET_KEY", "a" * 40)
        auth_module._instance = None
        # 'a' * 40 has only 1 unique char → low entropy
        with pytest.raises(OAuthConfigError, match="entropy"):
            setup()

    def test_production_requires_redis(self, monkeypatch):
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.delenv("REDIS_URL", raising=False)
        auth_module._instance = None
        with pytest.raises(OAuthConfigError, match="REDIS_URL"):
            setup()

    def test_production_requires_https(self, monkeypatch):
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("REDIS_URL", "redis://localhost:6379")
        monkeypatch.setenv("GOOGLE_REDIRECT_URI", "http://myapp.com/callback")
        auth_module._instance = None
        with pytest.raises(OAuthConfigError, match="HTTPS"):
            setup()

    def test_get_before_setup_raises(self):
        auth_module._instance = None
        with pytest.raises(OAuthNotInitializedError):
            get()

    def test_valid_setup_returns_instance(self, monkeypatch):
        monkeypatch.setenv("APP_SECRET_KEY", "abcdefghijklmnopqrstuvwxyz012345")
        monkeypatch.setenv("ENVIRONMENT", "development")
        auth_module._instance = None
        instance = setup()
        assert isinstance(instance, GoogleOAuth)
        assert get() is instance


# ─────────────────────────────────────────────
# InMemoryStore tests
# ─────────────────────────────────────────────

class TestInMemoryStore:
    @pytest.mark.asyncio
    async def test_set_and_get(self, store):
        await store.set("key1", {"a": 1}, ttl=60)
        result = await store.get("key1")
        assert result == {"a": 1}

    @pytest.mark.asyncio
    async def test_expired_returns_none(self, store):
        await store.set("key2", {"x": 1}, ttl=1)
        await asyncio.sleep(1.1)
        assert await store.get("key2") is None

    @pytest.mark.asyncio
    async def test_delete(self, store):
        await store.set("key3", {"y": 2}, ttl=60)
        await store.delete("key3")
        assert await store.get("key3") is None

    @pytest.mark.asyncio
    async def test_missing_key_returns_none(self, store):
        assert await store.get("nonexistent") is None


# ─────────────────────────────────────────────
# RateLimiter tests
# ─────────────────────────────────────────────

class TestRateLimiter:
    @pytest.mark.asyncio
    async def test_allows_within_burst(self):
        limiter = _RateLimiter(per_minute=60, burst=3)
        for _ in range(3):
            assert await limiter.check("client1") is True

    @pytest.mark.asyncio
    async def test_blocks_over_burst(self):
        limiter = _RateLimiter(per_minute=1, burst=2)
        await limiter.check("client2")
        await limiter.check("client2")
        assert await limiter.check("client2") is False

    @pytest.mark.asyncio
    async def test_different_clients_independent(self):
        limiter = _RateLimiter(per_minute=1, burst=1)
        assert await limiter.check("a") is True
        assert await limiter.check("b") is True


# ─────────────────────────────────────────────
# PKCE tests
# ─────────────────────────────────────────────

class TestPKCE:
    def test_pair_is_unique(self):
        from google_oauth import _pkce_pair
        v1, c1 = _pkce_pair()
        v2, c2 = _pkce_pair()
        assert v1 != v2
        assert c1 != c2

    def test_challenge_is_base64url(self):
        from google_oauth import _pkce_pair
        _, challenge = _pkce_pair()
        assert "=" not in challenge
        assert len(challenge) > 0


# ─────────────────────────────────────────────
# Login route tests
# ─────────────────────────────────────────────

class TestLogin:
    @pytest.mark.asyncio
    async def test_returns_redirect(self, oauth):
        req = mock_request()
        response = await oauth.login(req)
        assert response.status_code == 302
        location = response.headers["location"]
        assert "accounts.google.com" in location
        assert "code_challenge" in location
        assert "state" in location

    @pytest.mark.asyncio
    async def test_state_stored_in_store(self, oauth):
        req = mock_request()
        response = await oauth.login(req)
        location = response.headers["location"]

        # Extract state from redirect URL
        params = dict(p.split("=") for p in location.split("?")[1].split("&"))
        state_key = GoogleOAuth._STATE + params["state"]
        stored = await oauth._store.get(state_key)
        assert stored is not None
        assert "verifier" in stored

    @pytest.mark.asyncio
    async def test_rate_limited_login(self, oauth):
        oauth._limiter = _RateLimiter(per_minute=1, burst=0)
        req = mock_request()
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            await oauth.login(req)
        assert exc.value.status_code == 429


# ─────────────────────────────────────────────
# Callback route tests
# ─────────────────────────────────────────────

class TestCallback:
    @pytest.mark.asyncio
    async def test_missing_code_raises_400(self, oauth):
        from fastapi import HTTPException
        req = mock_request(query_params={"state": "abc"})
        with pytest.raises(HTTPException) as exc:
            await oauth.callback(req)
        assert exc.value.status_code == 400

    @pytest.mark.asyncio
    async def test_google_error_param_raises_400(self, oauth):
        from fastapi import HTTPException
        req = mock_request(query_params={"error": "access_denied", "state": "s", "code": "c"})
        with pytest.raises(HTTPException) as exc:
            await oauth.callback(req)
        assert exc.value.status_code == 400

    @pytest.mark.asyncio
    async def test_invalid_state_raises_400(self, oauth):
        from fastapi import HTTPException
        req = mock_request(query_params={"state": "invalid_state", "code": "some_code"})
        with pytest.raises(HTTPException) as exc:
            await oauth.callback(req)
        assert exc.value.status_code == 400

    @pytest.mark.asyncio
    async def test_successful_callback_sets_cookie(self, oauth):
        # Seed a valid state
        state = "validstate123"
        await oauth._store.set(
            GoogleOAuth._STATE + state,
            {"verifier": "v" * 64, "ip": "127.0.0.1"},
            ttl=300,
        )

        # Mock HTTP calls
        mock_http = AsyncMock()
        mock_http.post.return_value = MagicMock(
            status_code=200,
            raise_for_status=MagicMock(),
            json=MagicMock(return_value={"access_token": "goog_token"}),
        )
        mock_http.get.return_value = MagicMock(
            status_code=200,
            raise_for_status=MagicMock(),
            json=MagicMock(return_value={
                "id": "user123",
                "email": "test@example.com",
                "name": "Test User",
                "picture": "https://example.com/pic.jpg",
                "verified_email": True,
            }),
        )
        oauth._http = mock_http

        req = mock_request(query_params={"state": state, "code": "auth_code_xyz"})
        response = await oauth.callback(req)

        assert response.status_code == 302
        assert response.headers["location"] == "/home"
        assert "session" in response.headers.get("set-cookie", "")

    @pytest.mark.asyncio
    async def test_state_consumed_after_callback(self, oauth):
        """State must be one-time use to prevent replay attacks."""
        state = "oneuse_state"
        await oauth._store.set(
            GoogleOAuth._STATE + state,
            {"verifier": "v" * 64, "ip": "127.0.0.1"},
            ttl=300,
        )

        mock_http = AsyncMock()
        mock_http.post.return_value = MagicMock(
            raise_for_status=MagicMock(),
            json=MagicMock(return_value={"access_token": "tok"}),
        )
        mock_http.get.return_value = MagicMock(
            raise_for_status=MagicMock(),
            json=MagicMock(return_value={
                "id": "u1", "email": "a@b.com",
                "name": "A", "verified_email": True,
            }),
        )
        oauth._http = mock_http

        req = mock_request(query_params={"state": state, "code": "code"})
        await oauth.callback(req)

        # Second use of same state should fail
        from fastapi import HTTPException
        req2 = mock_request(query_params={"state": state, "code": "code2"})
        with pytest.raises(HTTPException) as exc:
            await oauth.callback(req2)
        assert exc.value.status_code == 400


# ─────────────────────────────────────────────
# Session / current_user tests
# ─────────────────────────────────────────────

class TestSession:
    def _make_token(self, oauth, overrides: dict = None):
        user = {"id": "u1", "email": "user@test.com", "name": "User", "picture": None}
        if overrides:
            user.update(overrides)
        return oauth._build_jwt(user)

    @pytest.mark.asyncio
    async def test_valid_session_returns_user(self, oauth):
        token = self._make_token(oauth)
        req = mock_request(cookies={"session": token})
        user = await oauth._get_current_user(req)
        assert user["email"] == "user@test.com"
        assert user["id"] == "u1"

    @pytest.mark.asyncio
    async def test_missing_session_raises_401(self, oauth):
        from fastapi import HTTPException
        req = mock_request()
        with pytest.raises(HTTPException) as exc:
            await oauth._get_current_user(req)
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_tampered_token_raises_401(self, oauth):
        from fastapi import HTTPException
        req = mock_request(cookies={"session": "not.a.valid.token"})
        with pytest.raises(HTTPException) as exc:
            await oauth._get_current_user(req)
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_blacklisted_token_raises_401(self, oauth):
        from fastapi import HTTPException
        import jwt as pyjwt

        token = self._make_token(oauth)
        payload = pyjwt.decode(token, oauth._secret_key, algorithms=["HS256"])
        jti = payload["jti"]

        # Blacklist it
        await oauth._store.set(GoogleOAuth._BL + jti, {"revoked": True}, ttl=900)

        req = mock_request(cookies={"session": token})
        with pytest.raises(HTTPException) as exc:
            await oauth._get_current_user(req)
        assert exc.value.status_code == 401


# ─────────────────────────────────────────────
# Logout tests
# ─────────────────────────────────────────────

class TestLogout:
    @pytest.mark.asyncio
    async def test_logout_clears_cookie_and_redirects(self, oauth):
        import jwt as pyjwt
        token = oauth._build_jwt({"id": "u1", "email": "a@b.com", "name": "A", "picture": None})

        req = mock_request(cookies={"session": token})
        response = await oauth.logout(req)

        assert response.status_code == 302
        assert response.headers["location"] == "/"
        cookie_header = response.headers.get("set-cookie", "")
        # Cookie should be cleared (max-age=0 or deleted)
        assert "session" in cookie_header

    @pytest.mark.asyncio
    async def test_logout_blacklists_jti(self, oauth):
        import jwt as pyjwt
        token = oauth._build_jwt({"id": "u1", "email": "a@b.com", "name": "A", "picture": None})
        payload = pyjwt.decode(token, oauth._secret_key, algorithms=["HS256"])
        jti = payload["jti"]

        req = mock_request(cookies={"session": token})
        await oauth.logout(req)

        blacklisted = await oauth._store.get(GoogleOAuth._BL + jti)
        assert blacklisted is not None

    @pytest.mark.asyncio
    async def test_logout_without_cookie_is_safe(self, oauth):
        """Logout should not crash if there's no session cookie."""
        req = mock_request()
        response = await oauth.logout(req)
        assert response.status_code == 302
