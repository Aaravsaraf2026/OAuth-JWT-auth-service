"""
Real-World Example: FastAPI Authentication System with Enhanced JWT

This example demonstrates a production-ready authentication system using
the enhanced JWT wrapper with FastAPI.

Features demonstrated:
- User registration and login
- Access token + refresh token flow
- Device binding for mobile apps
- Rate limiting on refresh
- Token revocation (logout)
- Protected endpoints
- Audit logging to file
- Security metrics endpoint

Run with:
    pip install fastapi uvicorn redis python-dotenv
    python example_fastapi_auth.py
"""

import os
import json
from datetime import datetime
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, HTTPException, status, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
import uvicorn

# Import our enhanced JWT wrapper
from enhanced_jwt_wrapper import (
    EnhancedJWTWrapper,
    EnhancedJWTConfig,
    SecurityConfig,
    AuditHook,
    AuditEvent,
    TokenExpired,
    TokenRevoked,
    InvalidToken,
    JWTError
)


# ================= CONFIGURATION =================

# In production, load from environment variables
class Settings:
    JWT_SECRET = os.getenv("JWT_SECRET", "your-super-secret-key-minimum-32-characters-required!")
    JWT_REFRESH_SECRET = os.getenv("JWT_REFRESH_SECRET", "your-refresh-secret-key-minimum-32-characters-required!")
    JWT_ACCESS_TTL = int(os.getenv("JWT_ACCESS_TTL", "900"))  # 15 minutes
    JWT_REFRESH_TTL = int(os.getenv("JWT_REFRESH_TTL", "604800"))  # 7 days
    REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))


settings = Settings()


# ================= CUSTOM AUDIT HOOK =================

class FileAuditHook(AuditHook):
    """Log audit events to file for compliance."""
    
    def __init__(self, log_file: str = "audit.log"):
        self.log_file = log_file
    
    def on_event(
        self,
        event: AuditEvent,
        subject: Optional[str] = None,
        jti: Optional[str] = None,
        metadata: Optional[dict] = None
    ):
        """Write audit event to log file."""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event": event.value,
            "subject": subject,
            "jti": jti,
            "metadata": metadata or {}
        }
        
        with open(self.log_file, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
        
        # Also log to console
        super().on_event(event, subject, jti, metadata)


# ================= JWT WRAPPER INITIALIZATION =================

# Configure enhanced security
security_config = SecurityConfig(
    max_payload_size_bytes=2048,
    enable_refresh_rate_limit=True,
    refresh_rate_limit_count=10,
    refresh_rate_limit_window_seconds=3600,
    enable_device_binding=True,  # For mobile apps
    enable_audit_hooks=True,
    enable_metrics=True
)

# Create configuration
jwt_config = EnhancedJWTConfig(
    secret=settings.JWT_SECRET,
    refresh_secret=settings.JWT_REFRESH_SECRET,
    access_ttl=settings.JWT_ACCESS_TTL,
    refresh_ttl=settings.JWT_REFRESH_TTL,
    use_redis=True,
    strict_mode=True,
    rotate_refresh=True,
    security=security_config
)

# Initialize wrapper with audit hook
audit_hook = FileAuditHook("audit.log")
jwt_wrapper = EnhancedJWTWrapper(jwt_config, audit_hook)


# ================= PYDANTIC MODELS =================

class UserRegister(BaseModel):
    """User registration request."""
    email: EmailStr
    password: str
    full_name: str


class UserLogin(BaseModel):
    """User login request."""
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    """Token response model."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshRequest(BaseModel):
    """Refresh token request."""
    refresh_token: str


class User(BaseModel):
    """User model."""
    user_id: str
    email: str
    full_name: str
    role: str


# ================= MOCK DATABASE =================

# In production, use a real database (PostgreSQL, MongoDB, etc.)
USERS_DB = {}


def hash_password(password: str) -> str:
    """Hash password (use bcrypt in production)."""
    import hashlib
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(password: str, hashed: str) -> bool:
    """Verify password (use bcrypt in production)."""
    return hash_password(password) == hashed


def get_user_by_email(email: str) -> Optional[dict]:
    """Get user by email."""
    return USERS_DB.get(email)


def create_user(email: str, password: str, full_name: str) -> dict:
    """Create new user."""
    import uuid
    
    user = {
        "user_id": str(uuid.uuid4()),
        "email": email,
        "password_hash": hash_password(password),
        "full_name": full_name,
        "role": "user",
        "created_at": datetime.utcnow().isoformat()
    }
    
    USERS_DB[email] = user
    return user


# ================= FASTAPI APP =================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager for startup/shutdown."""
    # Startup
    print("🚀 Starting FastAPI authentication server...")
    print(f"📝 Audit logs: audit.log")
    print(f"🔒 Device binding: {'enabled' if security_config.enable_device_binding else 'disabled'}")
    print(f"⏱️  Access token TTL: {settings.JWT_ACCESS_TTL}s")
    print(f"🔄 Refresh token TTL: {settings.JWT_REFRESH_TTL}s")
    
    yield
    
    # Shutdown
    print("\n👋 Shutting down...")


app = FastAPI(
    title="Enhanced JWT Authentication API",
    description="Production-ready authentication with enhanced security",
    version="1.0.0",
    lifespan=lifespan
)

security = HTTPBearer()


# ================= AUTHENTICATION DEPENDENCIES =================

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    x_device_id: Optional[str] = Header(None, alias="X-Device-ID")
) -> User:
    """
    Verify access token and return current user.
    
    Requires:
    - Authorization: Bearer <access_token>
    - X-Device-ID: <device_id> (if device binding enabled)
    """
    token = credentials.credentials
    
    try:
        # Verify token with device binding
        payload = jwt_wrapper.verify(
            token,
            expected_type="access",
            device_id=x_device_id
        )
        
        # Get user data from token
        user_data = payload["data"]
        
        return User(
            user_id=payload["sub"],
            email=user_data["email"],
            full_name=user_data["full_name"],
            role=user_data["role"]
        )
        
    except TokenExpired:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token has expired",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except TokenRevoked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except InvalidToken as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"}
        )


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Require admin role."""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user


# ================= API ENDPOINTS =================

@app.post("/api/auth/register", response_model=dict)
async def register(user_data: UserRegister):
    """
    Register a new user.
    
    Example:
        POST /api/auth/register
        {
            "email": "user@example.com",
            "password": "secure_password123",
            "full_name": "John Doe"
        }
    """
    # Check if user exists
    if get_user_by_email(user_data.email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Create user
    user = create_user(user_data.email, user_data.password, user_data.full_name)
    
    return {
        "message": "User registered successfully",
        "user_id": user["user_id"],
        "email": user["email"]
    }


@app.post("/api/auth/login", response_model=TokenResponse)
async def login(
    credentials: UserLogin,
    x_device_id: Optional[str] = Header(None, alias="X-Device-ID")
):
    """
    Login and receive access + refresh tokens.
    
    Headers:
        X-Device-ID: Device identifier (required if device binding enabled)
    
    Example:
        POST /api/auth/login
        Headers: X-Device-ID: mobile-app-uuid-12345
        {
            "email": "user@example.com",
            "password": "secure_password123"
        }
    """
    # Verify credentials
    user = get_user_by_email(credentials.email)
    if not user or not verify_password(credentials.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
    
    # Prepare user data for token
    user_data = {
        "email": user["email"],
        "full_name": user["full_name"],
        "role": user["role"]
    }
    
    try:
        # Create token pair with device binding
        access_token = jwt_wrapper.create_access_token(
            sub=user["user_id"],
            data=user_data,
            device_id=x_device_id
        )
        
        refresh_token = jwt_wrapper.create_refresh_token(
            sub=user["user_id"],
            data=user_data,
            device_id=x_device_id
        )
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=settings.JWT_ACCESS_TTL
        )
        
    except ValueError as e:
        # Payload validation failed
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@app.post("/api/auth/refresh", response_model=TokenResponse)
async def refresh_token(
    request: RefreshRequest,
    x_device_id: Optional[str] = Header(None, alias="X-Device-ID")
):
    """
    Refresh access token using refresh token.
    
    The refresh token is automatically rotated for security.
    
    Example:
        POST /api/auth/refresh
        Headers: X-Device-ID: mobile-app-uuid-12345
        {
            "refresh_token": "eyJhbGc..."
        }
    """
    try:
        # Refresh tokens (with rate limiting and device binding)
        tokens = jwt_wrapper.refresh_access_token(
            refresh_token=request.refresh_token,
            device_id=x_device_id
        )
        
        return TokenResponse(
            access_token=tokens["access_token"],
            refresh_token=tokens.get("refresh_token", request.refresh_token),
            expires_in=settings.JWT_ACCESS_TTL
        )
        
    except TokenExpired:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired. Please login again."
        )
    except TokenRevoked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked. Please login again."
        )
    except JWTError as e:
        # Could be rate limit or other error
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(e)
        )


@app.post("/api/auth/logout")
async def logout(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    x_device_id: Optional[str] = Header(None, alias="X-Device-ID")
):
    """
    Logout (revoke current access token).
    
    Example:
        POST /api/auth/logout
        Authorization: Bearer <access_token>
    """
    token = credentials.credentials
    
    try:
        # Revoke the token
        success = jwt_wrapper.revoke_token(token)
        
        if success:
            return {"message": "Logged out successfully"}
        else:
            return {"message": "Logout processed (Redis unavailable)"}
            
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Logout failed: {str(e)}"
        )


@app.get("/api/me", response_model=User)
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """
    Get current user information.
    
    Requires valid access token in Authorization header.
    
    Example:
        GET /api/me
        Authorization: Bearer <access_token>
    """
    return current_user


@app.get("/api/protected")
async def protected_route(current_user: User = Depends(get_current_user)):
    """
    Example protected endpoint.
    
    Only accessible with valid access token.
    """
    return {
        "message": f"Hello {current_user.full_name}!",
        "user_id": current_user.user_id,
        "role": current_user.role
    }


@app.get("/api/admin/users")
async def list_users(admin: User = Depends(require_admin)):
    """
    Admin-only endpoint to list all users.
    
    Requires admin role.
    """
    users = [
        {
            "user_id": user["user_id"],
            "email": user["email"],
            "full_name": user["full_name"],
            "role": user["role"]
        }
        for user in USERS_DB.values()
    ]
    
    return {"users": users, "total": len(users)}


@app.get("/api/admin/metrics")
async def get_metrics(admin: User = Depends(require_admin)):
    """
    Get security metrics.
    
    Requires admin role.
    """
    metrics = jwt_wrapper.get_metrics()
    
    return {
        "metrics": metrics,
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    }


# ================= MAIN =================

if __name__ == "__main__":
    print("""
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║          Enhanced JWT Authentication Server                    ║
║                                                                ║
║  Features:                                                     ║
║  ✓ Access + Refresh token flow                               ║
║  ✓ Device binding for mobile apps                            ║
║  ✓ Automatic refresh token rotation                          ║
║  ✓ Rate limiting on refresh                                  ║
║  ✓ Token revocation (logout)                                 ║
║  ✓ Audit logging                                             ║
║  ✓ Security metrics                                          ║
║                                                                ║
║  API Documentation: http://localhost:8000/docs                ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
    """)
    
    # Create a demo admin user
    create_user(
        email="admin@example.com",
        password="admin123",
        full_name="Admin User"
    )
    USERS_DB["admin@example.com"]["role"] = "admin"
    
    print("\n📧 Demo Admin Account:")
    print("   Email: admin@example.com")
    print("   Password: admin123\n")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )
