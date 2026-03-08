from fastapi import APIRouter, Request
from pydantic import BaseModel, EmailStr
from fastapi.responses import RedirectResponse
from .emailsender import send_otp, verify_otp
from repo.jwt import SecurityConfig, enhanced_jwt_wrapper, jwt_wrapper
# import datetime
from datetime import datetime
from database.db import db


router = APIRouter()
jwt = enhanced_jwt_wrapper

class EmailRequest(BaseModel):
    email: EmailStr


class OTPVerifyRequest(BaseModel):
    email: EmailStr
    otp: str


@router.post("/request-otp")
async def request_otp(data: EmailRequest):
    return await send_otp(data.email)


@router.post("/verify-otp")
async def verify(data: OTPVerifyRequest):

    if not await verify_otp(data.email, data.otp):
        return {"valid": False}
    

        # ------------------------------------------------
    # DATABASE: create user if not exists
    # ------------------------------------------------

    user = db.table("users").where(email=data.email).first()

    if not user:
        db.insert(
            "users",
            {
                "email": data.email,
                "username": data.email.split("@")[0],
                "profile": {},
                "created_at": datetime.utcnow().isoformat()
            }
        )


    access_token = jwt_wrapper.create_access_token(
        sub=data.email
    )

    refresh_token = jwt_wrapper.create_refresh_token(
        sub=data.email,
        data = {
            "verified": True,
            "role": "user"
        }

    )
    response = RedirectResponse("/", status_code=303)

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


@router.post("/refresh")
async def refresh(request: Request):

    refresh_token = request.cookies.get("refresh_token")

    tokens = jwt_wrapper.refresh_access_token(refresh_token)

    return tokens


@router.get("/users")
async def get_users():

    users = db.table("users").all()

    return {
        "count": len(users),
        "data": users
    }