"""
Google OAuth Wrapper — Production Grade
========================================

Simple. Secure. No bloat.

Flow:
    1. setup()              → validate .env + initialize
    2. GET /auth/login      → redirect to Google
    3. GET /auth/callback   → receive tokens, set cookie, redirect to /home
    4. Depends(current_user) → protect routes

Required .env:
    GOOGLE_CLIENT_ID
    GOOGLE_CLIENT_SECRET
    GOOGLE_REDIRECT_URI        e.g. https://yourdomain.com/auth/callback
    APP_SECRET_KEY             min 32-char random string
    REDIRECT_AFTER_LOGIN       e.g. /home

Optional .env:
    ENVIRONMENT                development | production  (default: development)
    REDIS_URL                  required if ENVIRONMENT=production
    SESSION_TTL_SECONDS        default: 900 (15 min)
    COOKIE_DOMAIN              e.g. yourdomain.com
"""

from __future__ import annotations

import logging
import os
import secrets
import hashlib
import base64
import uuid
import asyncio
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import httpx
import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse, JSONResponse

logger = logging.getLogger("google_oauth")
_audit = logging.getLogger("google_oauth.audit")


# ─────────────────────────────────────────────
# Exceptions
# ─────────────────────────────────────────────

class OAuthNotInitializedError(RuntimeError):
    """Raised when auth is used before setup() is called."""


class OAuthConfigError(ValueError):
    """Raised when .env configuration is invalid."""


# ─────────────────────────────────────────────
# Storage Backends
# ─────────────────────────────────────────────

class _InMemoryStore:
    """Dev-only in-memory store. Auto-expires keys."""

    def __init__(self) -> None:
        self._data: Dict[str, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()
        self._task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        self._task = asyncio.create_task(self._cleanup_loop())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _cleanup_loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(300)
                now = datetime.now(timezone.utc)
                async with self._lock:
                    expired = [k for k, v in self._data.items() if v["exp"] < now]
                    for k in expired:
                        del self._data[k]
            except asyncio.CancelledError:
                break

    async def set(self, key: str, value: dict, ttl: int) -> None:
        exp = datetime.now(timezone.utc) + timedelta(seconds=ttl)
        async with self._lock:
            self._data[key] = {"value": value, "exp": exp}

    async def get(self, key: str) -> Optional[dict]:
        async with self._lock:
            rec = self._data.get(key)
            if not rec or rec["exp"] < datetime.now(timezone.utc):
                return None
            return rec["value"]

    async def delete(self, key: str) -> None:
        async with self._lock:
            self._data.pop(key, None)


class RedisStore:
    """Production Redis-backed store."""

    def __init__(self, url: str) -> None:
        try:
            import redis.asyncio as aioredis
            self._lib = aioredis
        except ImportError:
            raise ImportError("Install redis: pip install redis[asyncio]")
        self._url = url
        self._client = None

    async def _conn(self):
        if not self._client:
            self._client = self._lib.from_url(
                self._url, encoding="utf-8", decode_responses=True
            )
            await self._client.ping()
        return self._client

    async def start(self) -> None:
        await self._conn()
        logger.info("Redis connection established")

    async def stop(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def set(self, key: str, value: dict, ttl: int) -> None:
        import json
        client = await self._conn()
        await client.setex(key, ttl, json.dumps(value))

    async def get(self, key: str) -> Optional[dict]:
        import json
        client = await self._conn()
        raw = await client.get(key)
        return json.loads(raw) if raw else None

    async def delete(self, key: str) -> None:
        client = await self._conn()
        await client.delete(key)


# ─────────────────────────────────────────────
# Rate Limiter (token bucket)
# ─────────────────────────────────────────────

class _RateLimiter:
    def __init__(self, per_minute: int = 20, burst: int = 5) -> None:
        self._rate = per_minute / 60.0
        self._burst = burst
        self._buckets: Dict[str, tuple] = {}
        self._lock = asyncio.Lock()

    async def check(self, key: str) -> bool:
        now = time.monotonic()
        async with self._lock:
            tokens, last = self._buckets.get(key, (self._burst, now))
            tokens = min(self._burst, tokens + (now - last) * self._rate)
            if tokens >= 1:
                self._buckets[key] = (tokens - 1, now)
                return True
            self._buckets[key] = (tokens, now)
            return False


# ─────────────────────────────────────────────
# PKCE helpers
# ─────────────────────────────────────────────

def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).decode().rstrip("=")
    return verifier, challenge


# ─────────────────────────────────────────────
# Core Auth Class
# ─────────────────────────────────────────────

class GoogleOAuth:
    """
    Production-grade Google OAuth2 wrapper.

    Do not instantiate directly — use setup() module function.
    """

    # Storage key prefixes
    _STATE  = "oa:state:"
    _SESS   = "oa:sess:"
    _BL     = "oa:bl:"

    # Google endpoints (stable, no reason to override in normal use)
    _AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    _TOKEN_URL     = "https://oauth2.googleapis.com/token"
    _USERINFO_URL  = "https://www.googleapis.com/oauth2/v2/userinfo"
    _REVOKE_URL    = "https://oauth2.googleapis.com/revoke"

    def __init__(self, cfg: Dict[str, Any], store) -> None:
        self._client_id       = cfg["client_id"]
        self._client_secret   = cfg["client_secret"]
        self._redirect_uri    = cfg["redirect_uri"]
        self._secret_key      = cfg["secret_key"]
        self._redirect_home   = cfg["redirect_after_login"]
        self._cookie_domain   = cfg.get("cookie_domain")
        self._session_ttl     = int(cfg.get("session_ttl", 900))
        self._is_prod         = cfg.get("environment", "development") == "production"

        self._store           = store
        self._http: Optional[httpx.AsyncClient] = None
        self._limiter         = _RateLimiter(per_minute=30, burst=10)
        self._initialized     = False

    # ── Lifecycle ────────────────────────────

    async def initialize(self) -> None:
        if self._initialized:
            return
        await self._store.start()
        self._http = httpx.AsyncClient(
            timeout=10.0,
            limits=httpx.Limits(max_keepalive_connections=5, max_connections=10),
        )
        self._initialized = True
        _audit.info("GoogleOAuth initialized (prod=%s)", self._is_prod)

    async def shutdown(self) -> None:
        if self._http:
            await self._http.aclose()
            self._http = None
        await self._store.stop()
        self._initialized = False
        logger.info("GoogleOAuth shutdown complete")

    # ── Internal helpers ─────────────────────

    def _client_ip(self, request: Request) -> str:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    async def _rate_check(self, request: Request, endpoint: str) -> None:
        ip = self._client_ip(request)
        if not await self._limiter.check(ip):
            _audit.warning("Rate limit: endpoint=%s ip=%s", endpoint, ip)
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many requests")

    def _set_session_cookie(self, response, token: str) -> None:
        response.set_cookie(
            key="session",
            value=token,
            httponly=True,
            secure=self._is_prod,
            samesite="lax",
            max_age=self._session_ttl,
            path="/",
            domain=self._cookie_domain,
        )

    def _clear_session_cookie(self, response) -> None:
        response.delete_cookie("session", path="/", domain=self._cookie_domain)

    def _build_jwt(self, user: dict) -> str:
        now = datetime.now(timezone.utc)
        payload = {
            "sub":     user["id"],
            "email":   user["email"],
            "name":    user.get("name"),
            "picture": user.get("picture"),
            "iat":     int(now.timestamp()),
            "exp":     int((now + timedelta(seconds=self._session_ttl)).timestamp()),
            "jti":     str(uuid.uuid4()),
        }
        return jwt.encode(payload, self._secret_key, algorithm="HS256")

    def _decode_jwt(self, token: str) -> dict:
        return jwt.decode(
            token,
            self._secret_key,
            algorithms=["HS256"],
            options={"verify_exp": True},
        )

    # ── Route handlers ───────────────────────

    async def login(self, request: Request) -> RedirectResponse:
        """
        Redirect user to Google login.
        Mount at GET /auth/login.
        """
        await self._rate_check(request, "login")

        state = secrets.token_urlsafe(32)
        verifier, challenge = _pkce_pair()

        await self._store.set(
            self._STATE + state,
            {"verifier": verifier, "ip": self._client_ip(request)},
            ttl=300,  # state valid 5 min
        )

        params = {
            "client_id":             self._client_id,
            "redirect_uri":          self._redirect_uri,
            "response_type":         "code",
            "scope":                 "openid email profile",
            "state":                 state,
            "code_challenge":        challenge,
            "code_challenge_method": "S256",
            "access_type":           "online",
            "prompt":                "select_account",
        }

        url = self._AUTHORIZE_URL + "?" + "&".join(
            f"{k}={v}" for k, v in params.items()
        )
        return RedirectResponse(url, status_code=302)

    async def callback(self, request: Request) -> RedirectResponse:
        """
        Handle Google OAuth callback.
        Mount at GET /auth/callback.
        """
        await self._rate_check(request, "callback")

        # ── Validate state ────────────────────
        state = request.query_params.get("state")
        code  = request.query_params.get("code")
        error = request.query_params.get("error")

        if error:
            _audit.warning("OAuth error from Google: %s", error)
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Google OAuth error: {error}")

        if not state or not code:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Missing state or code")

        state_data = await self._store.get(self._STATE + state)
        if not state_data:
            _audit.warning("Invalid/expired state. ip=%s", self._client_ip(request))
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid or expired state — please try again")

        await self._store.delete(self._STATE + state)  # one-time use

        # ── Exchange code for tokens ──────────
        try:
            token_resp = await self._http.post(
                self._TOKEN_URL,
                data={
                    "code":           code,
                    "client_id":      self._client_id,
                    "client_secret":  self._client_secret,
                    "redirect_uri":   self._redirect_uri,
                    "grant_type":     "authorization_code",
                    "code_verifier":  state_data["verifier"],
                },
                headers={"Accept": "application/json"},
            )
            token_resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            logger.error("Token exchange failed: %s", exc.response.text)
            raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Failed to exchange code with Google")

        tokens = token_resp.json()

        # ── Fetch user info ───────────────────
        try:
            user_resp = await self._http.get(
                self._USERINFO_URL,
                headers={"Authorization": f"Bearer {tokens['access_token']}"},
            )
            user_resp.raise_for_status()
        except httpx.HTTPStatusError:
            raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Failed to fetch user info from Google")

        user = user_resp.json()

        if not user.get("verified_email", True):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Google account email not verified")

        # ── Issue session cookie ──────────────
        session_token = self._build_jwt({
            "id":      user["id"],
            "email":   user["email"],
            "name":    user.get("name"),
            "picture": user.get("picture"),
        })

        _audit.info("Login success: email=%s ip=%s", user["email"], self._client_ip(request))

        response = RedirectResponse(self._redirect_home, status_code=302)
        self._set_session_cookie(response, session_token)
        return response
    
    async def callback_with_user(self, request: Request):
        """
        Same as callback() but also returns the user dict.
        Use when you need to read/print user data after login.
        """
        await self._rate_check(request, "callback")

        state = request.query_params.get("state")
        code  = request.query_params.get("code")
        error = request.query_params.get("error")

        if error:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Google OAuth error: {error}")
        if not state or not code:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Missing state or code")

        state_data = await self._store.get(self._STATE + state)
        if not state_data:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid or expired state")

        await self._store.delete(self._STATE + state)

        # Exchange code
        token_resp = await self._http.post(
            self._TOKEN_URL,
            data={
                "code":          code,
                "client_id":     self._client_id,
                "client_secret": self._client_secret,
                "redirect_uri":  self._redirect_uri,
                "grant_type":    "authorization_code",
                "code_verifier": state_data["verifier"],
            },
            headers={"Accept": "application/json"},
        )
        token_resp.raise_for_status()
        tokens = token_resp.json()

        # Fetch user
        user_resp = await self._http.get(
            self._USERINFO_URL,
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )
        user_resp.raise_for_status()
        user = user_resp.json()

        # ── Print / use user data here ────────────────────────────────────────
        print("=== USER LOGGED IN ===")
        print("ID:      ", user["id"])
        print("Name:    ", user["name"])
        print("Email:   ", user["email"])
        print("Picture: ", user["picture"])
        print("Verified:", user["verified_email"])
        print("======================")

        # Build session and redirect as normal
        token = self._build_jwt({
            "id":      user["id"],
            "email":   user["email"],
            "name":    user.get("name"),
            "picture": user.get("picture"),
        })

        response = RedirectResponse(self._redirect_home, status_code=302)
        self._set_session_cookie(response, token)
        return response, user       # ← returns both



    async def logout(self, request: Request) -> RedirectResponse:
        """
        Clear session and redirect to /.
        Mount at GET /auth/logout.
        """
        session = request.cookies.get("session")

        if session:
            try:
                payload = self._decode_jwt(session)
                jti = payload.get("jti")
                exp = payload.get("exp", 0)
                if jti:
                    ttl = max(1, exp - int(datetime.now(timezone.utc).timestamp()))
                    await self._store.set(self._BL + jti, {"revoked": True}, ttl)
                _audit.info("Logout: email=%s", payload.get("email"))
            except Exception:
                pass  # invalid token — still clear the cookie

        response = RedirectResponse("/", status_code=302)
        self._clear_session_cookie(response)
        return response

    # ── FastAPI dependency ────────────────────

    async def _get_current_user(self, request: Request) -> dict:
        """Internal: extract and validate session."""
        session = request.cookies.get("session")
        if not session:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")

        try:
            payload = self._decode_jwt(session)
        except jwt.ExpiredSignatureError:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session expired")
        except jwt.InvalidTokenError:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid session")

        # Blacklist check
        jti = payload.get("jti")
        if jti and await self._store.get(self._BL + jti):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session has been revoked")

        return {
            "id":      payload["sub"],
            "email":   payload["email"],
            "name":    payload.get("name"),
            "picture": payload.get("picture"),
        }

    def current_user(self) -> Any:
        """
        FastAPI dependency — require authenticated user.

        Usage:
            @app.get("/dashboard")
            async def dashboard(user = Depends(auth.current_user())):
                return {"hello": user["email"]}
        """
        async def _dep(request: Request) -> dict:
            return await self._get_current_user(request)
        return Depends(_dep)

    def optional_user(self) -> Any:
        """
        FastAPI dependency — user if authenticated, else None.

        Usage:
            @app.get("/")
            async def home(user = Depends(auth.optional_user())):
                ...
        """
        async def _dep(request: Request) -> Optional[dict]:
            try:
                return await self._get_current_user(request)
            except HTTPException:
                return None
        return Depends(_dep)


# ─────────────────────────────────────────────
# Module-level singleton
# ─────────────────────────────────────────────

_instance: Optional[GoogleOAuth] = None


def setup() -> GoogleOAuth:
    """
    Read .env, validate config, create and return the auth instance.

    Call once at app startup — before any routes are served.

    Required env vars:
        GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET,
        GOOGLE_REDIRECT_URI, APP_SECRET_KEY, REDIRECT_AFTER_LOGIN

    Optional:
        ENVIRONMENT (default: development)
        REDIS_URL   (required when ENVIRONMENT=production)
        SESSION_TTL_SECONDS (default: 900)
        COOKIE_DOMAIN
    """
    global _instance

    # ── Read env ──────────────────────────────
    required = {
        "GOOGLE_CLIENT_ID":     "client_id",
        "GOOGLE_CLIENT_SECRET": "client_secret",
        "GOOGLE_REDIRECT_URI":  "redirect_uri",
        "APP_SECRET_KEY":       "secret_key",
        "REDIRECT_AFTER_LOGIN": "redirect_after_login",
    }
    cfg: Dict[str, Any] = {}
    missing = []
    for env_var, key in required.items():
        val = os.getenv(env_var)
        if not val:
            missing.append(env_var)
        else:
            cfg[key] = val

    if missing:
        raise OAuthConfigError(
            f"Missing required environment variables: {', '.join(missing)}\n"
            "Add them to your .env file and restart."
        )

    # ── Validate secret strength ──────────────
    secret = cfg["secret_key"]
    if len(secret) < 32:
        raise OAuthConfigError(
            "APP_SECRET_KEY must be at least 32 characters.\n"
            "Generate one: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
        )
    if len(set(secret)) < 16:
        raise OAuthConfigError("APP_SECRET_KEY has too little entropy. Use a random string.")

    # ── Optional env ──────────────────────────
    environment = os.getenv("ENVIRONMENT", "development").lower()
    cfg["environment"]        = environment
    cfg["session_ttl"]        = int(os.getenv("SESSION_TTL_SECONDS", "900"))
    cfg["cookie_domain"]      = os.getenv("COOKIE_DOMAIN") or None

    # ── Storage ───────────────────────────────
    redis_url = os.getenv("REDIS_URL")

    if environment == "production":
        if not redis_url:
            raise OAuthConfigError(
                "REDIS_URL is required when ENVIRONMENT=production.\n"
                "Set REDIS_URL=redis://localhost:6379/0 (or your Redis URL)."
            )
        # Enforce HTTPS on redirect URI in production
        redirect_uri = cfg["redirect_uri"]
        if redirect_uri.startswith("http://") and "localhost" not in redirect_uri:
            raise OAuthConfigError(
                f"GOOGLE_REDIRECT_URI must use HTTPS in production. Got: {redirect_uri}"
            )
        store = RedisStore(redis_url)
        logger.info("Using Redis store (production)")
    else:
        store = _InMemoryStore()
        logger.warning("Using in-memory store — development only")

    _instance = GoogleOAuth(cfg, store)
    logger.info("Google OAuth setup complete (env=%s)", environment)
    return _instance


def get() -> GoogleOAuth:
    """
    Return the initialized auth instance.

    Raises OAuthNotInitializedError if setup() hasn't been called.
    """
    if _instance is None:
        raise OAuthNotInitializedError(
            "Auth not initialized. Call setup() during app startup."
        )
    return _instance


__all__ = [
    "setup",
    "get",
    "GoogleOAuth",
    "RedisStore",
    "OAuthConfigError",
    "OAuthNotInitializedError"
    
]
