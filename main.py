from fastapi import FastAPI
from repo.jwt import jwt_wrapper
from fastapi.responses import RedirectResponse
import uvicorn
from contextlib import asynccontextmanager
import repo.auth as auth

from routes.login import router
from routes.google_auth import api

from database.db import init_schema, close_db


# ── Lifespan ───────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):

    oauth = auth.setup()

    await oauth.initialize()

    # Create database tables
    await init_schema()

    yield

    # Shutdown tasks
    await close_db()

    await oauth.shutdown()


app = FastAPI(lifespan=lifespan)


# ── SECURITY MIDDLEWARE ────────────────────────────────────────────────────

from security.middleware import SecurityMiddleware

app.add_middleware(SecurityMiddleware)


# ── CORS ───────────────────────────────────────────────────────────────────

from repo.secure.cors import CORSManager

cors = CORSManager(
    allow_origins=[
        "http://localhost:3000",
        "https://app.yoursite.com"
    ]
)

cors.apply(app)


# ── LOGOUT ─────────────────────────────────────────────────────────────────

@app.post("/logout")
async def logout():

    response = RedirectResponse("/", status_code=303)

    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")

    return response


# ── ROUTES ─────────────────────────────────────────────────────────────────

app.include_router(router, tags=["Email Auth"])
app.include_router(api, tags=["Google Auth"])


# ── SERVER ─────────────────────────────────────────────────────────────────

