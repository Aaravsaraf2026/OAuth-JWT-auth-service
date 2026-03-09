from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, Request, APIRouter
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.exceptions import HTTPException
from dotenv import load_dotenv
from pathlib import Path
from datetime import datetime
import repo.auth as auth
api = APIRouter()

from database.db import db



from repo.jwt.jwt_wrapper import verify_token 
  # ← module-level function
from repo.jwt import jwt_wrapper

async def current_user(request: Request):
    user = request.state.user

    if not user:
        raise HTTPException(401, "Not authenticated")

    return user


async def optional_user(request: Request):
    """Optional login — returns None if not authenticated."""
    try:
        return await current_user(request)
    except HTTPException:
        return None


# ── Auth routes ───────────────────────────────────────────────────────────────

@api.get("/auth/login")
async def login(request: Request):

    if request.state.user:
        return RedirectResponse("/dashboard")

    return await auth.get().login(request)


@api.get("/auth/callback")
async def callback(request: Request):
    response, user = await auth.get().callback_with_user(request)

    # ── DB ────────────────────────────────────────────────────────────────
    db_user = db.table("users").where(email=user["email"]).first()

    if not db_user:
        db.insert("users", {
            "email":      user["email"],
            "username":   user["name"],
            
            "profile":    {},
            "created_at": datetime.utcnow().isoformat()
        })

    # ── Tokens ────────────────────────────────────────────────────────────
    access_token = jwt_wrapper.create_access_token(
        sub=user["email"]
    )
    refresh_token = jwt_wrapper.create_refresh_token(
        sub=user["email"],
        data={"verified": True, "role": "user"}
    )

    # ── Response ──────────────────────────────────────────────────────────
    response = RedirectResponse("/dashboard", status_code=303)

    response.delete_cookie("session")   # remove wrapper's session cookie

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        samesite="lax"
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        samesite="lax"
    )

    return response


@api.get("/auth/logout")
async def logout(request: Request):
    """Clear your cookies and redirect to home."""
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    response.delete_cookie("session")
    return response


# ── Protected routes ──────────────────────────────────────────────────────────

@api.get("/dashboard")
async def dashboard(user = Depends(current_user)):
    return {
        "email": user["sub"]
    }


@api.get("/me")
async def me(user = Depends(current_user)):
    return user                  # returns full JWT payload


# ── Public routes ─────────────────────────────────────────────────────────────

@api.get("/")
async def home(request: Request, user = Depends(optional_user)):
    if user:
        return HTMLResponse(f"<p>Hello {user['sub']}! <a href='/dashboard'>Dashboard</a> | <a href='/auth/logout'>Logout</a></p>")
    return HTMLResponse("<p><a href='/auth/login'>Login with Google</a></p>")
