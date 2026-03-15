from fastapi import Depends, Request, APIRouter
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.exceptions import HTTPException
from datetime import datetime
from sqlalchemy.orm import Session

import repo.auth as auth

from database.db import get_db, User
from repo.secure.csrf import CSRFManager
from repo.jwt import jwt_wrapper

api = APIRouter()


# ── USER HELPERS ─────────────────────────────────────────

async def current_user(request: Request):
    user = request.state.user

    if not user:
        raise HTTPException(401, "Not authenticated")

    return user


async def optional_user(request: Request):
    try:
        return await current_user(request)
    except HTTPException:
        return None


# ── AUTH ROUTES ─────────────────────────────────────────

@api.get("/auth/login")
async def login(request: Request):

    if request.state.user:
        return RedirectResponse("/dashboard")

    return await auth.get().login(request)


@api.get("/auth/callback")
async def callback(request: Request, db: Session = Depends(get_db)):

    response, user = await auth.get().callback_with_user(request)

    # ── DATABASE ───────────────────────────────────────

    db_user = db.query(User).filter(User.email == user["email"]).first()

    if not db_user:

        db_user = User(
            email=user["email"],
            username=user["name"],
            profile={},
            created_at=datetime.utcnow()
        )

        db.add(db_user)
        db.commit()
        db.refresh(db_user)

    # ── TOKENS ─────────────────────────────────────────

    access_token = jwt_wrapper.create_access_token(
        sub=user["email"]
    )

    refresh_token = jwt_wrapper.create_refresh_token(
        sub=user["email"],
        data={"verified": True, "role": "user"}
    )

    # ── RESPONSE ───────────────────────────────────────

    response = RedirectResponse("/dashboard", status_code=303)

    csrf_token = CSRFManager.generate()

    response.delete_cookie("session")

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

    response.set_cookie(
        key="csrf_token",
        value=csrf_token,
        httponly=False,
        samesite="lax"
    )

    return response


# ── LOGOUT ─────────────────────────────────────────

@api.get("/auth/logout")
async def logout(request: Request):

    response = RedirectResponse("/", status_code=303)

    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    response.delete_cookie("session")

    return response


# ── PROTECTED ROUTES ─────────────────────────────────

@api.get("/dashboard")
async def dashboard(user = Depends(current_user)):

    return {
        "email": user["sub"]
    }


@api.get("/me")
async def me(user = Depends(current_user)):

    return user


# ── PUBLIC ROUTES ───────────────────────────────────

@api.get("/")
async def home(request: Request, user = Depends(optional_user)):

    if user:
        return HTMLResponse(
            f"<p>Hello {user['sub']}! "
            f"<a href='/dashboard'>Dashboard</a> | "
            f"<a href='/auth/logout'>Logout</a></p>"
        )

    return HTMLResponse(
        "<p><a href='/auth/login'>Login with Google</a></p>"
    )