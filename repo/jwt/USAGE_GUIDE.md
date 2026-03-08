# Enhanced JWT Wrapper - Usage Guide

## Table of Contents
1. [Quick Start](#quick-start)
2. [Basic Usage](#basic-usage)
3. [Advanced Features](#advanced-features)
4. [Real-World Examples](#real-world-examples)
5. [Security Best Practices](#security-best-practices)
6. [Troubleshooting](#troubleshooting)

---

## Quick Start

### Installation

```bash
# Install dependencies
pip install PyJWT redis python-dotenv

# Optional: For FastAPI example
pip install fastapi uvicorn
```

### Environment Setup

Create a `.env` file:

```bash
# JWT Secrets (REQUIRED - minimum 32 characters)
JWT_SECRET=your-super-secret-access-token-key-min-32-chars
JWT_REFRESH_SECRET=your-different-refresh-token-key-min-32-chars

# Token TTL (in seconds)
JWT_ACCESS_TTL=900        # 15 minutes
JWT_REFRESH_TTL=604800    # 7 days

# Redis Configuration
JWT_USE_REDIS=true
REDIS_HOST=localhost
REDIS_PORT=6379

# Security Settings
JWT_STRICT_MODE=true
JWT_ROTATE_REFRESH=true
JWT_ALGORITHM=HS256
```

### Basic Example

```python
from enhanced_jwt_wrapper import create_production_wrapper

# Create wrapper with default security settings
jwt = create_production_wrapper()

# Create tokens for a user
access_token = jwt.create_access_token(
    sub="user123",
    data={"email": "user@example.com", "role": "user"}
)

refresh_token = jwt.create_refresh_token(
    sub="user123", 
    data={"email": "user@example.com", "role": "user"}
)

# Verify access token
try:
    payload = jwt.verify(access_token)
    print(f"User: {payload['sub']}")
    print(f"Email: {payload['data']['email']}")
except TokenExpired:
    print("Token expired - refresh needed")
except TokenRevoked:
    print("Token was revoked - login required")
except InvalidToken:
    print("Invalid token - authentication failed")
```

---

## Basic Usage

### 1. Creating Tokens

#### Access Token Only
```python
from enhanced_jwt_wrapper import EnhancedJWTWrapper

jwt = EnhancedJWTWrapper()

# Simple access token
token = jwt.create_access_token(
    sub="user_id_12345",
    data={"role": "user"}
)
```

#### Access + Refresh Token Pair
```python
# Using parent class method
tokens = jwt.create_token_pair(
    sub="user_id_12345",
    data={"email": "user@example.com", "role": "user"}
)

access_token = tokens["access_token"]
refresh_token = tokens["refresh_token"]
```

#### With Device Binding (Mobile Apps)
```python
# Enhanced method with device binding
access_token = jwt.create_access_token(
    sub="user_id_12345",
    data={"role": "user"},
    device_id="mobile-device-uuid-abc123"
)

refresh_token = jwt.create_refresh_token(
    sub="user_id_12345",
    data={"role": "user"},
    device_id="mobile-device-uuid-abc123"
)
```

### 2. Verifying Tokens

#### Basic Verification
```python
try:
    payload = jwt.verify(access_token, expected_type="access")
    
    user_id = payload["sub"]
    user_data = payload["data"]
    token_id = payload["jti"]
    
    print(f"Authenticated user: {user_id}")
    
except TokenExpired:
    # Token expired - client should refresh
    return {"error": "token_expired", "action": "refresh"}
    
except TokenRevoked:
    # Token was revoked (logout) - re-authentication required
    return {"error": "token_revoked", "action": "login"}
    
except InvalidToken as e:
    # Invalid signature, wrong type, audience mismatch, etc.
    return {"error": "invalid_token", "message": str(e)}
```

#### Verification with Device Binding
```python
# Must provide same device_id used during creation
try:
    payload = jwt.verify(
        token=access_token,
        expected_type="access",
        device_id="mobile-device-uuid-abc123"
    )
except InvalidToken:
    # Could be wrong device or invalid token
    return {"error": "authentication_failed"}
```

### 3. Refreshing Tokens

```python
try:
    # Refresh access token (auto-rotates refresh token if configured)
    new_tokens = jwt.refresh_access_token(
        refresh_token=old_refresh_token
    )
    
    new_access_token = new_tokens["access_token"]
    new_refresh_token = new_tokens.get("refresh_token")  # If rotation enabled
    
    # Return new tokens to client
    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token or old_refresh_token
    }
    
except TokenExpired:
    # Refresh token expired - user must login again
    return {"error": "refresh_expired", "action": "login"}
    
except JWTError as e:
    # Could be rate limit exceeded
    if "rate limit" in str(e):
        return {"error": "too_many_requests", "retry_after": 3600}
    raise
```

### 4. Revoking Tokens (Logout)

```python
# Method 1: Revoke using token string
success = jwt.revoke_token(access_token)

if success:
    print("Token revoked successfully")
else:
    print("Revocation failed (Redis unavailable)")

# Method 2: Revoke using JTI and expiration
payload = jwt.decode(access_token)
jwt.revoke(payload["jti"], payload["exp"])
```

---

## Advanced Features

### 1. Custom Audit Hook for SIEM Integration

```python
from enhanced_jwt_wrapper import AuditHook, AuditEvent
import requests

class SplunkAuditHook(AuditHook):
    """Send audit events to Splunk."""
    
    def __init__(self, splunk_url: str, token: str):
        self.splunk_url = splunk_url
        self.token = token
    
    def on_event(self, event, subject=None, jti=None, metadata=None):
        # Send to Splunk HEC
        payload = {
            "event": event.value,
            "subject": subject,
            "jti": jti,
            "metadata": metadata,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        try:
            requests.post(
                self.splunk_url,
                json=payload,
                headers={"Authorization": f"Splunk {self.token}"},
                timeout=5
            )
        except Exception as e:
            logger.error(f"Failed to send audit event: {e}")

# Use custom audit hook
audit_hook = SplunkAuditHook(
    splunk_url="https://splunk.example.com:8088/services/collector",
    token="your-splunk-hec-token"
)

jwt = EnhancedJWTWrapper(config, audit_hook)
```

### 2. Security Metrics Monitoring

```python
from enhanced_jwt_wrapper import create_production_wrapper

jwt = create_production_wrapper(enable_rate_limiting=True)

# After some operations...
metrics = jwt.get_metrics()

print(f"Tokens created: {metrics['tokens_created']}")
print(f"Tokens verified: {metrics['tokens_verified']}")
print(f"Tokens expired: {metrics['tokens_expired']}")
print(f"Rate limits hit: {metrics['rate_limits_hit']}")
print(f"Device mismatches: {metrics['device_mismatches']}")
print(f"Payload violations: {metrics['payload_violations']}")
```

### 3. Custom Security Configuration

```python
from enhanced_jwt_wrapper import (
    EnhancedJWTWrapper,
    EnhancedJWTConfig,
    SecurityConfig
)

# Create custom security config
security_config = SecurityConfig(
    # Payload security
    max_payload_size_bytes=2048,
    forbidden_payload_keys=[
        "password", "ssn", "credit_card", "api_key",
        "private_key", "secret_key", "bank_account"
    ],
    
    # Rate limiting
    enable_refresh_rate_limit=True,
    refresh_rate_limit_count=5,      # 5 refreshes
    refresh_rate_limit_window_seconds=1800,  # per 30 minutes
    
    # Device binding
    enable_device_binding=True,
    device_id_header_name="X-Device-ID",
    
    # Audit & monitoring
    enable_audit_hooks=True,
    enable_metrics=True
)

# Create JWT config
jwt_config = EnhancedJWTConfig(
    secret="your-secret-key",
    refresh_secret="your-refresh-secret",
    access_ttl=300,      # 5 minutes (aggressive)
    refresh_ttl=86400,   # 24 hours
    security=security_config
)

# Initialize wrapper
jwt = EnhancedJWTWrapper(jwt_config)
```

### 4. Async Support (FastAPI, aiohttp)

```python
from enhanced_jwt_wrapper import AsyncEnhancedJWTWrapper
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer

app = FastAPI()
security = HTTPBearer()
jwt = AsyncEnhancedJWTWrapper()

async def get_current_user(credentials = Depends(security)):
    token = credentials.credentials
    
    try:
        payload = await jwt.verify_async(token)
        return payload
    except TokenExpired:
        raise HTTPException(status_code=401, detail="Token expired")
    except InvalidToken:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.get("/protected")
async def protected_route(user = Depends(get_current_user)):
    return {"user_id": user["sub"], "data": user["data"]}
```

---

## Real-World Examples

### Example 1: E-Commerce API

```python
"""E-commerce authentication with role-based access."""

from enhanced_jwt_wrapper import create_production_wrapper

jwt = create_production_wrapper(enable_rate_limiting=True)

# Customer login
def customer_login(user_id: str, email: str):
    return jwt.create_token_pair(
        sub=user_id,
        data={
            "email": email,
            "role": "customer",
            "permissions": ["view_products", "create_order", "view_order_history"]
        }
    )

# Admin login
def admin_login(user_id: str, email: str):
    return jwt.create_token_pair(
        sub=user_id,
        data={
            "email": email,
            "role": "admin",
            "permissions": ["manage_products", "view_all_orders", "manage_users"]
        }
    )

# Verify admin access
def require_admin(token: str):
    payload = jwt.verify(token)
    
    if payload["data"]["role"] != "admin":
        raise PermissionError("Admin access required")
    
    return payload

# Example usage
tokens = customer_login("cust_123", "customer@example.com")
# ... later ...
payload = jwt.verify(tokens["access_token"])
if "create_order" in payload["data"]["permissions"]:
    # Allow order creation
    pass
```

### Example 2: Mobile Banking App

```python
"""Mobile banking with device binding and transaction tokens."""

from enhanced_jwt_wrapper import EnhancedJWTWrapper, EnhancedJWTConfig, SecurityConfig
import uuid

# Strict security for banking
security_config = SecurityConfig(
    enable_device_binding=True,
    enable_refresh_rate_limit=True,
    refresh_rate_limit_count=3,  # Only 3 refreshes per hour
    max_payload_size_bytes=512,   # Small payloads
    enable_audit_hooks=True
)

jwt_config = EnhancedJWTConfig(
    access_ttl=300,      # 5 minute sessions
    refresh_ttl=3600,    # 1 hour max
    strict_mode=True,    # Fail if Redis down
    security=security_config
)

jwt = EnhancedJWTWrapper(jwt_config)

# Device registration
def register_device(user_id: str, device_info: dict):
    device_id = str(uuid.uuid4())
    
    # Store device info in database
    save_device_to_db(user_id, device_id, device_info)
    
    return device_id

# Login with device binding
def mobile_login(user_id: str, device_id: str):
    # Verify device is registered
    if not is_device_registered(user_id, device_id):
        raise ValueError("Device not registered")
    
    tokens = {
        "access_token": jwt.create_access_token(
            sub=user_id,
            data={"account_type": "checking"},
            device_id=device_id
        ),
        "refresh_token": jwt.create_refresh_token(
            sub=user_id,
            data={"account_type": "checking"},
            device_id=device_id
        )
    }
    
    return tokens

# Transaction authorization token
def create_transaction_token(user_id: str, amount: float, recipient: str):
    """Short-lived token for single transaction."""
    return jwt.create_access_token(
        sub=user_id,
        data={
            "type": "transaction",
            "amount": amount,
            "recipient": recipient,
            "nonce": str(uuid.uuid4())
        }
    )

# Usage
device_id = register_device("user_123", {"model": "iPhone 15", "os": "iOS 17"})
tokens = mobile_login("user_123", device_id)

# Transaction
tx_token = create_transaction_token("user_123", 1000.00, "merchant_xyz")
payload = jwt.verify(tx_token, device_id=device_id)

# Verify transaction and revoke token immediately
if payload["data"]["type"] == "transaction":
    process_transaction(payload["data"])
    jwt.revoke_token(tx_token)  # Single-use token
```

### Example 3: Multi-Tenant SaaS

```python
"""Multi-tenant SaaS with organization isolation."""

from enhanced_jwt_wrapper import create_production_wrapper

jwt = create_production_wrapper()

def create_tenant_token(user_id: str, org_id: str, role: str):
    """Create token with organization context."""
    return jwt.create_token_pair(
        sub=user_id,
        data={
            "org_id": org_id,
            "role": role,
            "tenant": org_id,  # For data isolation
            "features": get_org_features(org_id)
        }
    )

def verify_tenant_access(token: str, required_org_id: str):
    """Verify user has access to specific organization."""
    payload = jwt.verify(token)
    
    token_org_id = payload["data"]["org_id"]
    
    if token_org_id != required_org_id:
        raise PermissionError(
            f"Access denied: token for org {token_org_id}, "
            f"requested resource in org {required_org_id}"
        )
    
    return payload

# Usage
tokens = create_tenant_token(
    user_id="user_456",
    org_id="org_abc",
    role="admin"
)

# Later, when accessing resources
def get_organization_data(org_id: str, token: str):
    # Verify tenant isolation
    payload = verify_tenant_access(token, org_id)
    
    # Check permissions
    if payload["data"]["role"] not in ["admin", "member"]:
        raise PermissionError("Insufficient permissions")
    
    # Return org data
    return fetch_org_data(org_id)
```

### Example 4: API Gateway Pattern

```python
"""API Gateway with service-to-service authentication."""

from enhanced_jwt_wrapper import create_production_wrapper
from datetime import datetime

jwt = create_production_wrapper()

# Service-to-service tokens (no user context)
def create_service_token(service_name: str, scopes: list):
    """Create token for service authentication."""
    return jwt.create_access_token(
        sub=f"service:{service_name}",
        data={
            "type": "service",
            "service": service_name,
            "scopes": scopes,
            "issued_at": datetime.utcnow().isoformat()
        }
    )

# User tokens with service access
def create_user_gateway_token(user_id: str, allowed_services: list):
    """Create token for user accessing via gateway."""
    return jwt.create_access_token(
        sub=user_id,
        data={
            "type": "user",
            "services": allowed_services,
            "rate_limit": "1000/hour"
        }
    )

# Gateway verification
def verify_gateway_access(token: str, target_service: str):
    """Verify token has access to target service."""
    payload = jwt.verify(token)
    
    token_type = payload["data"]["type"]
    
    if token_type == "service":
        # Service-to-service
        service_scopes = payload["data"]["scopes"]
        if target_service not in service_scopes:
            raise PermissionError(f"Service lacks scope for {target_service}")
            
    elif token_type == "user":
        # User access
        allowed_services = payload["data"]["services"]
        if target_service not in allowed_services:
            raise PermissionError(f"User lacks access to {target_service}")
    
    return payload

# Usage
# Service token for internal communication
service_token = create_service_token(
    "payment-service",
    scopes=["user-service", "notification-service", "audit-service"]
)

# User token
user_token = create_user_gateway_token(
    user_id="user_789",
    allowed_services=["payment-service", "profile-service"]
)

# Gateway checks
verify_gateway_access(service_token, "user-service")  # ✓ Allowed
verify_gateway_access(user_token, "payment-service")  # ✓ Allowed
verify_gateway_access(user_token, "admin-service")    # ✗ Denied
```

---

## Security Best Practices

### 1. Secret Management

```python
# ✅ GOOD: Load from environment
import os
from dotenv import load_dotenv

load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET")
JWT_REFRESH_SECRET = os.getenv("JWT_REFRESH_SECRET")

if not JWT_SECRET or len(JWT_SECRET) < 32:
    raise ValueError("JWT_SECRET must be at least 32 characters")

# ✅ GOOD: Use secrets manager in production
import boto3

def get_secret_from_aws():
    client = boto3.client('secretsmanager')
    response = client.get_secret_value(SecretId='prod/jwt/secrets')
    return json.loads(response['SecretString'])

# ❌ BAD: Hardcoded secrets
JWT_SECRET = "my-secret-key"  # NEVER DO THIS
```

### 2. Token Lifetime

```python
# ✅ GOOD: Short-lived access tokens
JWT_ACCESS_TTL = 900      # 15 minutes
JWT_REFRESH_TTL = 604800  # 7 days

# ✅ GOOD: Very short for high-security
JWT_ACCESS_TTL = 300      # 5 minutes
JWT_REFRESH_TTL = 3600    # 1 hour

# ❌ BAD: Long-lived access tokens
JWT_ACCESS_TTL = 86400    # 24 hours - TOO LONG
JWT_REFRESH_TTL = 2592000 # 30 days - TOO LONG
```

### 3. Payload Data

```python
# ✅ GOOD: Public, non-sensitive data
data = {
    "user_id": "123",
    "role": "user",
    "email": "user@example.com",
    "subscription": "premium"
}

# ❌ BAD: Sensitive data (JWTs are not encrypted!)
data = {
    "password": "secret123",        # NEVER
    "ssn": "123-45-6789",          # NEVER
    "credit_card": "4111111111111", # NEVER
    "api_key": "sk_live_...",      # NEVER
}

# ✅ GOOD: Reference IDs instead
data = {
    "user_id": "123",
    "payment_method_id": "pm_abc123",  # Reference, not actual card
}
```

### 4. Error Handling

```python
# ✅ GOOD: Specific error handling
from enhanced_jwt_wrapper import TokenExpired, TokenRevoked, InvalidToken

try:
    payload = jwt.verify(token)
except TokenExpired:
    return {"error": "token_expired", "action": "refresh"}
except TokenRevoked:
    return {"error": "token_revoked", "action": "login"}
except InvalidToken as e:
    # Log the error for security monitoring
    logger.warning(f"Invalid token: {e}")
    return {"error": "invalid_token"}

# ❌ BAD: Generic error handling
try:
    payload = jwt.verify(token)
except Exception:
    return {"error": "something went wrong"}  # Unhelpful
```

### 5. Redis Configuration

```python
# ✅ GOOD: Production Redis settings
JWT_USE_REDIS = True
JWT_STRICT_MODE = True  # Fail if Redis is down

# Configure Redis connection pool
REDIS_CONFIG = {
    "host": "redis.example.com",
    "port": 6379,
    "db": 0,
    "max_connections": 50,
    "socket_timeout": 5,
    "socket_connect_timeout": 5,
    "retry_on_timeout": True,
    "health_check_interval": 30
}

# ❌ BAD: No Redis in production
JWT_USE_REDIS = False  # Tokens can't be revoked!
```

---

## Troubleshooting

### Issue: "JWT_SECRET must be at least 32 characters"

**Solution:**
```bash
# Generate strong secret
python -c "import secrets; print(secrets.token_urlsafe(64))"

# Add to .env
JWT_SECRET=<generated-secret-here>
JWT_REFRESH_SECRET=<different-generated-secret-here>
```

### Issue: "Refresh rate limit exceeded"

**Solution:**
```python
# Reduce rate limit or increase window
security_config = SecurityConfig(
    refresh_rate_limit_count=20,  # Increase from 10
    refresh_rate_limit_window_seconds=7200  # 2 hours instead of 1
)

# Or disable rate limiting for testing
security_config = SecurityConfig(
    enable_refresh_rate_limit=False
)
```

### Issue: "Device binding failed"

**Solution:**
```python
# Ensure device_id is consistent
device_id = "mobile-app-uuid-12345"

# Use same device_id for all operations
token = jwt.create_access_token(sub="user123", device_id=device_id)
payload = jwt.verify(token, device_id=device_id)
new_tokens = jwt.refresh_access_token(refresh_token, device_id=device_id)

# Or disable device binding
security_config = SecurityConfig(enable_device_binding=False)
```

### Issue: "Payload size exceeds maximum"

**Solution:**
```python
# Reduce payload size
data = {
    "role": "user",
    "org": "abc"  # Use IDs instead of full objects
}

# Or increase limit (not recommended)
security_config = SecurityConfig(max_payload_size_bytes=4096)
```

### Issue: Redis connection errors

**Solution:**
```python
# Check Redis is running
# redis-cli ping

# Use graceful degradation for non-critical environments
JWT_STRICT_MODE=false  # In .env

# Or use fallback config
jwt_config = EnhancedJWTConfig(
    use_redis=True,
    strict_mode=False  # Continue without Redis
)
```

---

## Additional Resources

- **Base JWT Wrapper Documentation**: See `jwt_wrapper.py`
- **FastAPI Example**: See `example_fastapi_auth.py`
- **Security Review**: See `jwt_wrapper_security_review.md`
- **PyJWT Documentation**: https://pyjwt.readthedocs.io/

## Support

For issues or questions:
1. Check this guide's troubleshooting section
2. Review the security review document
3. Examine the FastAPI example for real-world patterns
4. Check audit logs for security events

## License

See LICENSE file for details.
