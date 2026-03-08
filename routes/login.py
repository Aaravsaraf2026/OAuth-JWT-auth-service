from fastapi import APIRouter
from pydantic import BaseModel, EmailStr
from .emailsender import send_otp, verify_otp
from repo.jwt import SecurityConfig, enhanced_jwt_wrapper


router = APIRouter()
jwt = enhanced_jwt_wrapper()

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
    
    result = await verify_otp(data.email, data.otp)

    print(result)
    try:
        if result == True:
            pass
    except:
        pass

    return {"valid": result}