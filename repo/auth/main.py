"""
Example FastAPI app using google_oauth wrapper.

Install:
    pip install fastapi uvicorn httpx pyjwt redis[asyncio] python-dotenv

.env:
    GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
    GOOGLE_CLIENT_SECRET=your-secret
    GOOGLE_REDIRECT_URI=http://localhost:8000/auth/callback
    APP_SECRET_KEY=<run: python -c "import secrets; print(secrets.token_urlsafe(32))">
    REDIRECT_AFTER_LOGIN=/home
    ENVIRONMENT=development
    # REDIS_URL=redis://localhost:6379/0   ← required only in production
"""

from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, Depends, Request
from fastapi.responses import HTMLResponse

import google_oauth as auth

load_dotenv()


# ── App lifecycle ─────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: validate .env and connect storage
    oauth = auth.setup()
    await oauth.initialize()
    yield
    # Shutdown: close connections cleanly
    await oauth.shutdown()


app = FastAPI(lifespan=lifespan)


# ── Auth routes ───────────────────────────────────────────────────────────────

@app.get("/auth/login")
async def login(request: Request):
    return await auth.get().login(request)


@app.get("/auth/callback")
async def callback(request: Request):
    return await auth.get().callback(request)


@app.get("/auth/logout")
async def logout(request: Request):
    return await auth.get().logout(request)


# ── Protected routes ──────────────────────────────────────────────────────────

@app.get("/home")
async def home(user=Depends(auth.get().current_user())):
    return {"message": f"Welcome, {user['name']}!", "email": user["email"]}


@app.get("/profile")
async def profile(user=Depends(auth.get().current_user())):
    return user


# ── Public routes ─────────────────────────────────────────────────────────────

@app.get("/")
async def index(user=Depends(auth.get().optional_user())):
    if user:
        return HTMLResponse(f"<p>Logged in as {user['email']}. <a href='/home'>Go home</a> | <a href='/auth/logout'>Logout</a></p>")
    return HTMLResponse("<p>Not logged in. <a href='/auth/login'>Login with Google</a></p>")
