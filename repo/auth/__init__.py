"""
google_oauth — Production Google OAuth wrapper for FastAPI.

Usage:
    import google_oauth as auth

    # Startup
    oauth = auth.setup()
    await oauth.initialize()

    # Routes
    @app.get("/auth/login")    async def login(r):    return await auth.get().login(r)
    @app.get("/auth/callback") async def callback(r): return await auth.get().callback(r)
    @app.get("/auth/logout")   async def logout(r):   return await auth.get().logout(r)

    # Protect routes
    @app.get("/dashboard")
    async def dashboard(user = Depends(auth.get().current_user())):
        return {"email": user["email"]}
"""

from .google_oauth import (
    # ── Core setup ────────────────────────────
    setup,                      # validate .env + create instance
    get,  
                                              # get the initialized singleton

    # ── Main class (for type hints) ───────────
    GoogleOAuth,

    # ── Storage backends ──────────────────────
    RedisStore,                 # production Redis-backed store

    # ── Exceptions ────────────────────────────
    OAuthConfigError,           # bad / missing .env values
    OAuthNotInitializedError,   # get() called before setup()
    
)

__all__ = [
    # Setup
    "setup",
    "get",

    # Class
    "GoogleOAuth",

    # Storage
    "RedisStore",

    # Exceptions
    "OAuthConfigError",
    "OAuthNotInitializedError",
    "callback_with_user"
]

__version__ = "1.0.0"
