from fastapi import APIRouter, Request, Depends
from pydantic import BaseModel, EmailStr
from fastapi.responses import RedirectResponse
from fastapi.exceptions import HTTPException
from sqlalchemy.orm import Session
from datetime import datetime

from .emailsender import send_otp, verify_otp

from repo.jwt import enhanced_jwt_wrapper, jwt_wrapper
from repo.jwt.jwt_wrapper import get_default_wrapper

from repo.secure.csrf import CSRFManager

from database.db import get_db
from database.db import User

router = APIRouter()
jwt = enhanced_jwt_wrapper


class EmailRequest(BaseModel):
    email: EmailStr


class OTPVerifyRequest(BaseModel):
    email: EmailStr
    otp: str


# ── REQUEST OTP ─────────────────────────────────────────

@router.post("/request-otp")
async def request_otp(data: EmailRequest):
    return await send_otp(data.email)


# ── VERIFY OTP ─────────────────────────────────────────

@router.post("/verify-otp")
async def verify(data: OTPVerifyRequest, db: Session = Depends(get_db)):

    if not await verify_otp(data.email, data.otp):
        return {"valid": False}

    # ------------------------------------------------
    # DATABASE: create user if not exists
    # ------------------------------------------------

    user = db.query(User).filter(User.email == data.email).first()

    if not user:

        user = User(
            email=data.email,
            username=data.email.split("@")[0],
            profile={},
            created_at=datetime.utcnow()
        )

        db.add(user)
        db.commit()
        db.refresh(user)

    access_token = jwt_wrapper.create_access_token(
        sub=data.email
    )

    refresh_token = jwt_wrapper.create_refresh_token(
        sub=data.email,
        data={
            "verified": True,
            "role": "user"
        }
    )

    response = RedirectResponse("/", status_code=303)

    csrf_token = CSRFManager.generate()

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


# ── REFRESH TOKEN ─────────────────────────────────────

jwt = get_default_wrapper()

@router.post("/refresh")
async def refresh(request: Request):

    refresh_token = request.cookies.get("refresh_token")

    if not refresh_token:
        raise HTTPException(401, "Missing refresh token")

    try:
        tokens = jwt.refresh_access_token(refresh_token)
        return tokens

    except Exception as e:
        print("REFRESH ERROR:", e)
        raise HTTPException(401, str(e))


# ── USERS LIST ─────────────────────────────────────

@router.get("/users")
async def get_users(db: Session = Depends(get_db)):

    users = db.query(User).all()

    return {
        "count": len(users),
        "data": users
    }