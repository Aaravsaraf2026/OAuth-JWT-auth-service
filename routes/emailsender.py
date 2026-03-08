import os
import httpx
from dotenv import load_dotenv

from repo.otp import (
    OTPConfig,
    OTPManager,
    RedisStore,
    InMemoryStore,
    Environment
)

load_dotenv()


class Settings:
    """Application settings from environment variables."""

    MAILJET_API_KEY = os.getenv("MAILJET_API_KEY")
    MAILJET_API_SECRET = os.getenv("MAILJET_API_SECRET")
    MAILJET_FROM_EMAIL = os.getenv("MAILJET_FROM_EMAIL", "noreply@yourdomain.com")
    MAILJET_FROM_NAME = os.getenv("MAILJET_FROM_NAME", "OTP Service")

    REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
    REDIS_PASSWORD = os.getenv("REDIS_PASSWORD") or None

    OTP_LENGTH = int(os.getenv("OTP_LENGTH", 6))
    OTP_TTL_SECONDS = int(os.getenv("OTP_TTL_SECONDS", 300))
    OTP_MAX_ATTEMPTS = int(os.getenv("OTP_MAX_ATTEMPTS", 3))
    OTP_RESEND_COOLDOWN = int(os.getenv("OTP_RESEND_COOLDOWN", 60))

    USE_REDIS = os.getenv("USE_REDIS", "false").lower() == "true"


settings = Settings()


# =============================
# MAILJET EMAIL SENDER
# =============================

async def send_email(to: str, subject: str, body: str) -> bool:
    """Send email using Mailjet"""

    url = "https://api.mailjet.com/v3.1/send"

    payload = {
        "Messages": [
            {
                "From": {
                    "Email": settings.MAILJET_FROM_EMAIL,
                    "Name": settings.MAILJET_FROM_NAME
                },
                "To": [{"Email": to}],
                "Subject": subject,
                "TextPart": body
            }
        ]
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(
            url,
            auth=(settings.MAILJET_API_KEY, settings.MAILJET_API_SECRET),
            json=payload
        )

    return response.status_code == 200


# =============================
# STORAGE SETUP
# =============================
print("USE_REDIS =", os.getenv("USE_REDIS"))
if settings.USE_REDIS:
    print("using redis from sender file")
    redis_url = f"redis://{settings.REDIS_HOST}:{settings.REDIS_PORT}"

    storage = RedisStore(
        redis_url=redis_url,
        fallback_store=None
    )

else:
    print("memory is used")
    storage = InMemoryStore()


# =============================
# OTP CONFIGURATION
# =============================

config = OTPConfig(
    length=settings.OTP_LENGTH,
    ttl_seconds=settings.OTP_TTL_SECONDS,
    max_attempts=settings.OTP_MAX_ATTEMPTS,
    resend_cooldown_seconds=settings.OTP_RESEND_COOLDOWN,
    environment=Environment.DEVELOPMENT
)


# =============================
# OTP MANAGER
# =============================

otp_manager = OTPManager(
    storage=storage,
    send_fn=send_email,
    config=config
)


# =============================
# SERVICE FUNCTIONS
# =============================

async def send_otp(email: str):
    """Send OTP to email"""
    return await otp_manager.send_otp(email)


async def verify_otp(email: str, otp: str):
    """Verify OTP"""
    return await otp_manager.verify_otp(email, otp)



