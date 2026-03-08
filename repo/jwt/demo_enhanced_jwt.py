"""
Demo script showing all enhanced JWT wrapper features.

This script demonstrates:
1. Basic token creation and verification
2. Payload security validation
3. Device binding
4. Refresh token flow with rate limiting
5. Token revocation
6. Audit hooks
7. Metrics collection

Run with: python demo_enhanced_jwt.py
"""

import time
from datetime import datetime

# Import enhanced wrapper
from enhanced_jwt_wrapper import (
    EnhancedJWTWrapper,
    EnhancedJWTConfig,
    SecurityConfig,
    AuditHook,
    AuditEvent,
    create_production_wrapper,
    TokenExpired,
    TokenRevoked,
    InvalidToken,
    JWTError
)


class DemoAuditHook(AuditHook):
    """Custom audit hook for demo."""
    
    def on_event(self, event, subject=None, jti=None, metadata=None):
        print(f"\n📋 AUDIT EVENT: {event.value}")
        if subject:
            print(f"   Subject: {subject}")
        if jti:
            print(f"   JTI: {jti}")
        if metadata:
            print(f"   Metadata: {metadata}")


def print_section(title):
    """Print section header."""
    print(f"\n{'='*70}")
    print(f"  {title}")
    print('='*70)


def demo_basic_usage():
    """Demonstrate basic token creation and verification."""
    print_section("1. Basic Token Creation and Verification")
    
    # Create wrapper with default settings
    jwt = create_production_wrapper(
        enable_device_binding=False,
        enable_rate_limiting=False
    )
    
    # Create tokens
    print("\n✓ Creating access token...")
    access_token = jwt.create_access_token(
        sub="user_12345",
        data={
            "email": "demo@example.com",
            "role": "user",
            "plan": "premium"
        }
    )
    print(f"  Token: {access_token[:50]}...")
    
    print("\n✓ Creating refresh token...")
    refresh_token = jwt.create_refresh_token(
        sub="user_12345",
        data={
            "email": "demo@example.com",
            "role": "user",
            "plan": "premium"
        }
    )
    print(f"  Token: {refresh_token[:50]}...")
    
    # Verify access token
    print("\n✓ Verifying access token...")
    payload = jwt.verify(access_token)
    print(f"  User ID: {payload['sub']}")
    print(f"  Email: {payload['data']['email']}")
    print(f"  Role: {payload['data']['role']}")
    print(f"  JTI: {payload['jti']}")
    
    return jwt, access_token, refresh_token


def demo_payload_security():
    """Demonstrate payload security validation."""
    print_section("2. Payload Security Validation")
    
    jwt = create_production_wrapper()
    
    # Test 1: Forbidden keys
    print("\n✓ Testing forbidden keys detection...")
    try:
        jwt.create_access_token(
            sub="user_123",
            data={
                "email": "user@example.com",
                "password": "secret123"  # FORBIDDEN
            }
        )
        print("  ❌ Should have failed!")
    except ValueError as e:
        print(f"  ✓ Correctly blocked: {e}")
    
    # Test 2: Payload size limit
    print("\n✓ Testing payload size limit...")
    try:
        large_data = {"key" + str(i): "value" * 100 for i in range(100)}
        jwt.create_access_token(
            sub="user_123",
            data=large_data
        )
        print("  ❌ Should have failed!")
    except ValueError as e:
        print(f"  ✓ Correctly blocked: {str(e)[:80]}...")
    
    # Test 3: Safe payload
    print("\n✓ Creating token with safe payload...")
    safe_token = jwt.create_access_token(
        sub="user_123",
        data={
            "email": "user@example.com",
            "role": "user",
            "user_id_ref": "uid_abc123"  # Reference, not sensitive data
        }
    )
    print("  ✓ Token created successfully")


def demo_device_binding():
    """Demonstrate device binding security."""
    print_section("3. Device Binding (Mobile Security)")
    
    # Enable device binding
    security_config = SecurityConfig(
        enable_device_binding=True,
        enable_refresh_rate_limit=False
    )
    
    config = EnhancedJWTConfig(
        secret="demo-secret-key-minimum-32-characters-required!",
        refresh_secret="demo-refresh-secret-minimum-32-characters!",
        security=security_config
    )
    
    jwt = EnhancedJWTWrapper(config)
    
    # Create token for specific device
    device_id = "mobile-device-uuid-abc123"
    print(f"\n✓ Creating token for device: {device_id}")
    
    token = jwt.create_access_token(
        sub="user_123",
        data={"email": "user@example.com"},
        device_id=device_id
    )
    print("  ✓ Token created with device binding")
    
    # Verify with correct device
    print("\n✓ Verifying with correct device ID...")
    try:
        payload = jwt.verify(token, device_id=device_id)
        print("  ✓ Verification successful")
    except InvalidToken:
        print("  ❌ Should have succeeded!")
    
    # Verify with wrong device
    print("\n✓ Verifying with wrong device ID...")
    try:
        jwt.verify(token, device_id="wrong-device-id")
        print("  ❌ Should have failed!")
    except InvalidToken as e:
        print(f"  ✓ Correctly blocked: {e}")


def demo_refresh_flow():
    """Demonstrate refresh token flow."""
    print_section("4. Refresh Token Flow")
    
    jwt = create_production_wrapper(enable_rate_limiting=False)
    
    # Create initial tokens
    print("\n✓ Creating initial token pair...")
    access_token = jwt.create_access_token(
        sub="user_123",
        data={"email": "user@example.com"}
    )
    refresh_token = jwt.create_refresh_token(
        sub="user_123",
        data={"email": "user@example.com"}
    )
    print("  ✓ Token pair created")
    
    # Refresh access token
    print("\n✓ Refreshing access token...")
    new_tokens = jwt.refresh_access_token(refresh_token)
    print(f"  ✓ New access token: {new_tokens['access_token'][:50]}...")
    
    if "refresh_token" in new_tokens:
        print(f"  ✓ New refresh token (rotated): {new_tokens['refresh_token'][:50]}...")
        print("  ℹ️  Old refresh token is now revoked")
    else:
        print("  ℹ️  Refresh token not rotated (rotation disabled)")


def demo_rate_limiting():
    """Demonstrate refresh rate limiting."""
    print_section("5. Refresh Rate Limiting")
    
    # Enable rate limiting with low limits for demo
    security_config = SecurityConfig(
        enable_refresh_rate_limit=True,
        refresh_rate_limit_count=3,  # Only 3 refreshes
        refresh_rate_limit_window_seconds=60,  # Per minute
        enable_device_binding=False
    )
    
    config = EnhancedJWTConfig(
        secret="demo-secret-key-minimum-32-characters-required!",
        refresh_secret="demo-refresh-secret-minimum-32-characters!",
        use_redis=False,  # Use in-memory for demo
        security=security_config
    )
    
    jwt = EnhancedJWTWrapper(config)
    
    print("\n✓ Creating refresh token...")
    refresh_token = jwt.create_refresh_token(
        sub="user_123",
        data={"email": "user@example.com"}
    )
    
    print("\n✓ Testing rate limit (max 3 refreshes per minute)...")
    for i in range(5):
        try:
            print(f"  Attempt {i+1}...", end=" ")
            new_tokens = jwt.refresh_access_token(refresh_token, rotate=False)
            print("✓ Success")
            
            if i >= 3:
                print("    ❌ Should have been rate limited!")
                
        except JWTError as e:
            if "rate limit" in str(e):
                print(f"✓ Rate limited (expected)")
            else:
                print(f"❌ Unexpected error: {e}")
    
    print("\nℹ️  Note: Rate limiting requires Redis in production")


def demo_revocation():
    """Demonstrate token revocation."""
    print_section("6. Token Revocation (Logout)")
    
    jwt = create_production_wrapper()
    
    # Create token
    print("\n✓ Creating access token...")
    token = jwt.create_access_token(
        sub="user_123",
        data={"email": "user@example.com"}
    )
    
    # Verify it works
    print("\n✓ Verifying token (before revocation)...")
    try:
        payload = jwt.verify(token)
        print(f"  ✓ Token valid for user: {payload['sub']}")
    except TokenRevoked:
        print("  ❌ Should not be revoked yet!")
    
    # Revoke token
    print("\n✓ Revoking token (logout)...")
    success = jwt.revoke_token(token)
    if success:
        print("  ✓ Token revoked successfully")
    else:
        print("  ⚠️  Revocation skipped (Redis not available)")
    
    # Try to verify revoked token
    print("\n✓ Attempting to verify revoked token...")
    try:
        jwt.verify(token)
        print("  ⚠️  Token still valid (Redis not configured)")
    except TokenRevoked:
        print("  ✓ Token correctly rejected as revoked")


def demo_audit_and_metrics():
    """Demonstrate audit hooks and metrics."""
    print_section("7. Audit Hooks and Metrics")
    
    # Create wrapper with audit hook
    audit_hook = DemoAuditHook()
    
    security_config = SecurityConfig(
        enable_audit_hooks=True,
        enable_metrics=True,
        enable_refresh_rate_limit=False,
        enable_device_binding=False
    )
    
    config = EnhancedJWTConfig(
        secret="demo-secret-key-minimum-32-characters-required!",
        refresh_secret="demo-refresh-secret-minimum-32-characters!",
        security=security_config
    )
    
    jwt = EnhancedJWTWrapper(config, audit_hook)
    
    print("\n✓ Performing operations with audit logging enabled...\n")
    
    # Create token (triggers audit event)
    token = jwt.create_access_token(
        sub="user_123",
        data={"email": "user@example.com"}
    )
    
    # Verify token (triggers audit event)
    time.sleep(0.1)  # Small delay for readability
    payload = jwt.verify(token)
    
    # Create refresh token
    time.sleep(0.1)
    refresh_token = jwt.create_refresh_token(
        sub="user_123",
        data={"email": "user@example.com"}
    )
    
    # Show metrics
    print("\n\n📊 Security Metrics:")
    metrics = jwt.get_metrics()
    if metrics:
        for key, value in metrics.items():
            print(f"   {key}: {value}")
    else:
        print("   Metrics not enabled")


def demo_error_handling():
    """Demonstrate proper error handling."""
    print_section("8. Error Handling Patterns")
    
    jwt = create_production_wrapper()
    
    # Create short-lived token for expiry demo
    config = EnhancedJWTConfig(
        secret="demo-secret-key-minimum-32-characters-required!",
        refresh_secret="demo-refresh-secret-minimum-32-characters!",
        access_ttl=1,  # 1 second
        security=SecurityConfig(enable_audit_hooks=False, enable_metrics=False)
    )
    short_jwt = EnhancedJWTWrapper(config)
    
    print("\n✓ Creating token with 1 second TTL...")
    token = short_jwt.create_access_token(
        sub="user_123",
        data={"email": "user@example.com"}
    )
    
    print("✓ Verifying immediately...")
    try:
        payload = short_jwt.verify(token)
        print(f"  ✓ Valid: {payload['sub']}")
    except TokenExpired:
        print("  ❌ Should not be expired yet!")
    
    print("\n✓ Waiting 2 seconds...")
    time.sleep(2)
    
    print("✓ Verifying expired token...")
    try:
        short_jwt.verify(token)
        print("  ❌ Should have expired!")
    except TokenExpired:
        print("  ✓ Correctly detected expiration")
    
    # Invalid token
    print("\n✓ Testing invalid token...")
    try:
        jwt.verify("invalid.token.here")
        print("  ❌ Should have failed!")
    except InvalidToken:
        print("  ✓ Correctly rejected invalid token")


def main():
    """Run all demos."""
    print("""
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║         Enhanced JWT Wrapper - Feature Demonstration          ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
    """)
    
    try:
        # Run demos
        demo_basic_usage()
        demo_payload_security()
        demo_device_binding()
        demo_refresh_flow()
        demo_rate_limiting()
        demo_revocation()
        demo_audit_and_metrics()
        demo_error_handling()
        
        print_section("✓ All Demos Completed Successfully!")
        
        print("""
Next Steps:
1. Review USAGE_GUIDE.md for detailed documentation
2. Run example_fastapi_auth.py for real-world FastAPI example
3. Configure environment variables for production use
4. Set up Redis for token revocation
5. Implement custom audit hooks for your SIEM

For production deployment:
- Generate strong secrets (32+ characters)
- Enable Redis with strict mode
- Configure appropriate token TTLs
- Set up monitoring and alerting
- Review jwt_wrapper_security_review.md
        """)
        
    except Exception as e:
        print(f"\n❌ Error during demo: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
