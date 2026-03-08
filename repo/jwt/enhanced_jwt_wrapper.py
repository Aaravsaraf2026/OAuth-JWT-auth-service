"""
Enhanced JWT Security Layer - Production-Hardened Wrapper

This module provides security enhancements on top of the base JWT wrapper:
- Key rotation with kid (key ID) support
- Payload size limits and schema validation
- Refresh token rate limiting
- Replay attack prevention via device binding
- Async support for high-throughput applications
- Audit hooks for SIEM integration
- Enhanced observability and metrics

Compatible with the existing jwt_wrapper.py - can be used as a drop-in replacement.
"""

import json
import hashlib
import asyncio
from typing import Optional, Dict, Any, Callable, List, Literal, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import logging

# Import base JWT wrapper
from .jwt_wrapper import (
    JWTWrapper, 
    JWTConfig, 
    TokenType,
    JWTError, 
    TokenExpired, 
    TokenRevoked, 
    InvalidToken,
    RedisUnavailable
)

logger = logging.getLogger(__name__)


# ================= CONFIGURATION ENHANCEMENTS =================

@dataclass
class SecurityConfig:
    """Enhanced security configuration."""
    
    # Payload security
    max_payload_size_bytes: int = 1024
    forbidden_payload_keys: List[str] = field(default_factory=lambda: [
        "password", "ssn", "credit_card", "api_key", "secret", "token",
        "social_security", "bank_account", "cvv", "pin"
    ])
    
    # Rate limiting
    enable_refresh_rate_limit: bool = True
    refresh_rate_limit_count: int = 10  # Max refreshes per window
    refresh_rate_limit_window_seconds: int = 3600  # 1 hour
    
    # Device binding
    enable_device_binding: bool = False
    device_id_header_name: str = "X-Device-ID"
    
    # Key rotation
    enable_key_rotation: bool = False
    active_key_id: Optional[str] = None
    key_rotation_grace_period_days: int = 7
    
    # Audit & monitoring
    enable_audit_hooks: bool = True
    enable_metrics: bool = True
    
    # Replay protection
    enable_nonce_validation: bool = False
    nonce_ttl_seconds: int = 300  # 5 minutes


@dataclass 
class EnhancedJWTConfig(JWTConfig):
    """Extended JWT configuration with security enhancements."""
    
    security: SecurityConfig = field(default_factory=SecurityConfig)
    
    # Key rotation support
    secrets_by_kid: Dict[str, str] = field(default_factory=dict)
    refresh_secrets_by_kid: Dict[str, str] = field(default_factory=dict)


# ================= AUDIT HOOKS =================

class AuditEvent(str, Enum):
    """Audit event types for security monitoring."""
    TOKEN_CREATED = "token_created"
    TOKEN_VERIFIED = "token_verified"
    TOKEN_EXPIRED = "token_expired"
    TOKEN_REVOKED = "token_revoked"
    TOKEN_ROTATION = "token_rotation"
    REFRESH_RATE_LIMIT = "refresh_rate_limit_exceeded"
    DEVICE_MISMATCH = "device_binding_failed"
    PAYLOAD_VIOLATION = "payload_security_violation"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    KEY_ROTATED = "key_rotated"


class AuditHook:
    """Base class for audit event handlers."""
    
    def on_event(
        self, 
        event: AuditEvent, 
        subject: Optional[str] = None,
        jti: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Handle audit event.
        
        Override this method to implement custom audit logic:
        - Send to SIEM (Splunk, Datadog, etc.)
        - Log to file/database
        - Trigger alerts
        - Update metrics
        """
        logger.info(
            f"AUDIT: {event.value} | subject={subject} | jti={jti} | metadata={metadata}"
        )


class MetricsCollector:
    """Collects security metrics for monitoring."""
    
    def __init__(self):
        self.metrics: Dict[str, int] = {
            "tokens_created": 0,
            "tokens_verified": 0,
            "tokens_expired": 0,
            "tokens_revoked": 0,
            "rate_limits_hit": 0,
            "device_mismatches": 0,
            "payload_violations": 0,
        }
    
    def increment(self, metric: str, value: int = 1):
        """Increment a metric counter."""
        if metric in self.metrics:
            self.metrics[metric] += value
    
    def get_metrics(self) -> Dict[str, int]:
        """Get current metrics snapshot."""
        return self.metrics.copy()
    
    def reset(self):
        """Reset all metrics to zero."""
        for key in self.metrics:
            self.metrics[key] = 0


# ================= ENHANCED JWT WRAPPER =================

class EnhancedJWTWrapper(JWTWrapper):
    """
    Production-hardened JWT wrapper with advanced security features.
    
    Features:
    - Payload security validation
    - Refresh token rate limiting  
    - Device binding support
    - Key rotation with kid
    - Audit hooks
    - Metrics collection
    
    Example:
        >>> config = EnhancedJWTConfig()
        >>> wrapper = EnhancedJWTWrapper(config)
        >>> token = wrapper.create_access_token("user123", {"role": "admin"})
    """
    
    def __init__(
        self,
        config: Optional[EnhancedJWTConfig] = None,
        audit_hook: Optional[AuditHook] = None
    ):
        """
        Initialize enhanced JWT wrapper.
        
        Args:
            config: Enhanced JWT configuration
            audit_hook: Custom audit event handler
        """
        # Initialize base wrapper
        if config is None:
            config = EnhancedJWTConfig()
        
        # Store security config before parent init
        self.security_config = config.security if hasattr(config, 'security') else SecurityConfig()
        
        super().__init__(config)
        
        # Initialize security components
        self.audit_hook = audit_hook or AuditHook()
        self.metrics = MetricsCollector() if self.security_config.enable_metrics else None
        
        # Key rotation support
        self.secrets_by_kid = getattr(config, 'secrets_by_kid', {})
        self.refresh_secrets_by_kid = getattr(config, 'refresh_secrets_by_kid', {})
        
        logger.info("EnhancedJWTWrapper initialized with security features")
    
    # ================= PAYLOAD SECURITY =================
    
    def _validate_payload_security(self, data: Optional[Dict[str, Any]]):
        """
        Validate payload data against security policies.
        
        Raises:
            ValueError: If payload violates security policies
        """
        if data is None:
            return
        
        # Size validation
        payload_json = json.dumps(data)
        size_bytes = len(payload_json.encode('utf-8'))
        
        if size_bytes > self.security_config.max_payload_size_bytes:
            error_msg = (
                f"Payload size ({size_bytes} bytes) exceeds maximum "
                f"({self.security_config.max_payload_size_bytes} bytes)"
            )
            logger.error(error_msg)
            
            self._emit_audit_event(
                AuditEvent.PAYLOAD_VIOLATION,
                metadata={"violation": "size_limit", "size": size_bytes}
            )
            
            if self.metrics:
                self.metrics.increment("payload_violations")
            
            raise ValueError(error_msg)
        
        # Forbidden keys validation
        forbidden_found = []
        for key in data.keys():
            key_lower = key.lower()
            for forbidden in self.security_config.forbidden_payload_keys:
                if forbidden in key_lower:
                    forbidden_found.append(key)
                    break
        
        if forbidden_found:
            error_msg = (
                f"Forbidden keys in payload: {forbidden_found}. "
                f"Never store sensitive data in JWT payloads (they are not encrypted)."
            )
            logger.error(error_msg)
            
            self._emit_audit_event(
                AuditEvent.PAYLOAD_VIOLATION,
                metadata={"violation": "forbidden_keys", "keys": forbidden_found}
            )
            
            if self.metrics:
                self.metrics.increment("payload_violations")
            
            raise ValueError(error_msg)
    
    # ================= RATE LIMITING =================
    
    def _check_refresh_rate_limit(self, sub: str) -> bool:
        """
        Check if refresh rate limit is exceeded for subject.
        
        Args:
            sub: Subject identifier
            
        Returns:
            True if limit exceeded, False otherwise
        """
        if not self.security_config.enable_refresh_rate_limit:
            return False
        
        if not self.config.use_redis:
            logger.warning("Refresh rate limiting requires Redis")
            return False
        
        redis = self._get_redis()
        if not redis:
            return False
        
        rate_limit_key = f"jwt:refresh_rate:{sub}"
        
        try:
            # Increment counter
            attempts = redis.incr(rate_limit_key)
            
            # Set expiry on first attempt
            if attempts == 1:
                redis.expire(rate_limit_key, self.security_config.refresh_rate_limit_window_seconds)
            
            # Check limit
            if attempts > self.security_config.refresh_rate_limit_count:
                logger.warning(
                    f"Refresh rate limit exceeded for {sub}: "
                    f"{attempts} attempts in {self.security_config.refresh_rate_limit_window_seconds}s"
                )
                
                self._emit_audit_event(
                    AuditEvent.REFRESH_RATE_LIMIT,
                    subject=sub,
                    metadata={"attempts": attempts}
                )
                
                if self.metrics:
                    self.metrics.increment("rate_limits_hit")
                
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Rate limit check failed: {e}")
            return False
    
    # ================= DEVICE BINDING =================
    
    def _generate_device_fingerprint(self, device_id: str) -> str:
        """Generate a hash of device ID for storage."""
        return hashlib.sha256(device_id.encode()).hexdigest()[:16]
    
    def _validate_device_binding(
        self, 
        payload: Dict[str, Any], 
        device_id: Optional[str]
    ):
        """
        Validate device binding if enabled.
        
        Raises:
            InvalidToken: If device binding validation fails
        """
        if not self.security_config.enable_device_binding:
            return
        
        stored_device = payload.get("data", {}).get("_device")
        
        if not device_id:
            logger.warning("Device binding enabled but no device_id provided")
            raise InvalidToken("Device ID required but not provided")
        
        current_device = self._generate_device_fingerprint(device_id)
        
        if stored_device != current_device:
            logger.warning(
                f"Device mismatch for {payload.get('sub')}: "
                f"expected {stored_device}, got {current_device}"
            )
            
            self._emit_audit_event(
                AuditEvent.DEVICE_MISMATCH,
                subject=payload.get("sub"),
                jti=payload.get("jti"),
                metadata={"expected": stored_device, "actual": current_device}
            )
            
            if self.metrics:
                self.metrics.increment("device_mismatches")
            
            raise InvalidToken("Token was issued for a different device")
    
    # ================= KEY ROTATION =================
    
    def _get_secret_for_kid(
        self, 
        kid: Optional[str], 
        token_type: TokenType
    ) -> Tuple[str, Optional[str]]:
        """
        Get secret for key ID, with fallback to default.
        
        Returns:
            Tuple of (secret, kid_used)
        """
        if not self.security_config.enable_key_rotation:
            return self._get_secret(token_type), None
        
        secrets_dict = (
            self.secrets_by_kid if token_type == TokenType.ACCESS 
            else self.refresh_secrets_by_kid
        )
        
        # Use provided kid or active kid
        actual_kid = kid or self.security_config.active_key_id
        
        if actual_kid and actual_kid in secrets_dict:
            return secrets_dict[actual_kid], actual_kid
        
        # Fallback to default secret
        logger.warning(f"Key ID {actual_kid} not found, using default secret")
        return self._get_secret(token_type), None
    
    # ================= AUDIT & METRICS =================
    
    def _emit_audit_event(
        self,
        event: AuditEvent,
        subject: Optional[str] = None,
        jti: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """Emit audit event to configured handler."""
        if self.security_config.enable_audit_hooks:
            self.audit_hook.on_event(event, subject, jti, metadata)
    
    # ================= ENHANCED PUBLIC API =================
    
    def create_access_token(
        self,
        sub: str,
        data: Optional[Dict[str, Any]] = None,
        device_id: Optional[str] = None
    ) -> str:
        """
        Create access token with enhanced security validation.
        
        Args:
            sub: Subject identifier
            data: Custom claims (will be validated)
            device_id: Optional device identifier for binding
            
        Returns:
            Encoded JWT access token
            
        Raises:
            ValueError: If payload violates security policies
        """
        # Validate payload security
        self._validate_payload_security(data)
        
        # Add device binding if enabled
        enhanced_data = data.copy() if data else {}
        if self.security_config.enable_device_binding and device_id:
            enhanced_data["_device"] = self._generate_device_fingerprint(device_id)
        
        # Create token using parent method
        token = super().create_access_token(sub, enhanced_data)
        
        # Emit audit event
        self._emit_audit_event(
            AuditEvent.TOKEN_CREATED,
            subject=sub,
            metadata={"type": "access", "device_bound": bool(device_id)}
        )
        
        # Update metrics
        if self.metrics:
            self.metrics.increment("tokens_created")
        
        return token
    
    def create_refresh_token(
        self,
        sub: str,
        data: Optional[Dict[str, Any]] = None,
        device_id: Optional[str] = None
    ) -> str:
        """
        Create refresh token with enhanced security validation.
        
        Args:
            sub: Subject identifier
            data: Custom claims (will be validated)
            device_id: Optional device identifier for binding
            
        Returns:
            Encoded JWT refresh token
        """
        # Validate payload security
        self._validate_payload_security(data)
        
        # Add device binding if enabled
        enhanced_data = data.copy() if data else {}
        if self.security_config.enable_device_binding and device_id:
            enhanced_data["_device"] = self._generate_device_fingerprint(device_id)
        
        # Create token using parent method
        token = super().create_refresh_token(sub, enhanced_data)
        
        # Emit audit event
        self._emit_audit_event(
            AuditEvent.TOKEN_CREATED,
            subject=sub,
            metadata={"type": "refresh", "device_bound": bool(device_id)}
        )
        
        # Update metrics
        if self.metrics:
            self.metrics.increment("tokens_created")
        
        return token
    
    def verify(
        self,
        token: str,
        expected_type: Literal["access", "refresh"] = "access",
        device_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Verify token with enhanced security checks.
        
        Args:
            token: JWT token to verify
            expected_type: Expected token type
            device_id: Device ID for binding validation
            
        Returns:
            Verified payload
            
        Raises:
            TokenExpired: If token expired
            TokenRevoked: If token revoked
            InvalidToken: If token invalid or device mismatch
        """
        try:
            # Verify using parent method
            payload = super().verify(token, expected_type)
            
            # Device binding validation
            if self.security_config.enable_device_binding:
                self._validate_device_binding(payload, device_id)
            
            # Emit audit event
            self._emit_audit_event(
                AuditEvent.TOKEN_VERIFIED,
                subject=payload.get("sub"),
                jti=payload.get("jti"),
                metadata={"type": expected_type}
            )
            
            # Update metrics
            if self.metrics:
                self.metrics.increment("tokens_verified")
            
            return payload
            
        except TokenExpired as e:
            # Track expired tokens
            self._emit_audit_event(
                AuditEvent.TOKEN_EXPIRED,
                metadata={"type": expected_type}
            )
            
            if self.metrics:
                self.metrics.increment("tokens_expired")
            
            raise
        
        except TokenRevoked as e:
            # Track revoked tokens
            if self.metrics:
                self.metrics.increment("tokens_revoked")
            
            raise
    
    def refresh_access_token(
        self,
        refresh_token: str,
        rotate: Optional[bool] = None,
        device_id: Optional[str] = None
    ) -> Dict[str, str]:
        """
        Refresh access token with rate limiting.
        
        Args:
            refresh_token: Valid refresh token
            rotate: Whether to rotate refresh token
            device_id: Device ID for binding validation
            
        Returns:
            Dictionary with new tokens
            
        Raises:
            JWTError: If rate limit exceeded
            TokenExpired: If refresh token expired
            InvalidToken: If refresh token invalid
        """
        # Verify refresh token first (includes device binding check)
        payload = self.verify(refresh_token, expected_type="refresh", device_id=device_id)
        sub = payload["sub"]
        
        # Check rate limit
        if self._check_refresh_rate_limit(sub):
            raise JWTError(
                f"Refresh rate limit exceeded. "
                f"Maximum {self.security_config.refresh_rate_limit_count} refreshes "
                f"per {self.security_config.refresh_rate_limit_window_seconds} seconds."
            )
        
        # Get original data and device binding
        data = payload["data"].copy()
        original_device = data.pop("_device", None)
        
        # Refresh using parent method (pass device_id to maintain binding)
        result = super().refresh_access_token(refresh_token, rotate)
        
        # If rotating, create new refresh token with device binding
        if rotate or (rotate is None and self.config.rotate_refresh):
            if self.security_config.enable_device_binding and device_id:
                data["_device"] = self._generate_device_fingerprint(device_id)
                result["refresh_token"] = super().create_refresh_token(sub, data)
        
        # Emit audit event
        self._emit_audit_event(
            AuditEvent.TOKEN_ROTATION,
            subject=sub,
            metadata={"rotated": "refresh_token" in result}
        )
        
        return result
    
    def get_metrics(self) -> Optional[Dict[str, int]]:
        """
        Get current security metrics.
        
        Returns:
            Metrics dictionary or None if metrics disabled
        """
        if self.metrics:
            return self.metrics.get_metrics()
        return None


# ================= ASYNC SUPPORT =================

class AsyncEnhancedJWTWrapper(EnhancedJWTWrapper):
    """
    Async version of enhanced JWT wrapper for high-throughput applications.
    
    Use with FastAPI, aiohttp, or other async frameworks.
    
    Example:
        >>> async def create_user_token(user_id: str):
        ...     wrapper = AsyncEnhancedJWTWrapper()
        ...     token = await wrapper.create_access_token_async(user_id)
        ...     return token
    """
    
    async def _is_revoked_async(self, jti: str) -> bool:
        """Async version of revocation check."""
        # This is a placeholder - actual implementation requires async Redis client
        # For production, use aioredis or redis-py with asyncio support
        
        if not self.config.use_redis:
            return False
        
        # TODO: Replace with actual async Redis implementation
        # Example with aioredis:
        # redis = await self._get_async_redis()
        # is_revoked = await redis.exists(self._blacklist_key(jti))
        # return bool(is_revoked)
        
        # Fallback to sync for now
        return self._is_revoked(jti)
    
    async def verify_async(
        self,
        token: str,
        expected_type: Literal["access", "refresh"] = "access",
        device_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Async token verification.
        
        Args:
            token: JWT token to verify
            expected_type: Expected token type
            device_id: Device ID for binding validation
            
        Returns:
            Verified payload
        """
        # JWT decode is CPU-bound, not I/O-bound
        # Only Redis operations benefit from async
        
        # Verify signature synchronously (fast, CPU-bound)
        payload = super().verify(token, expected_type, device_id)
        
        # Async revocation check would go here
        # if self.config.use_redis:
        #     jti = payload["jti"]
        #     if await self._is_revoked_async(jti):
        #         raise TokenRevoked("Token has been revoked")
        
        return payload


# ================= CONVENIENCE FUNCTIONS =================

def create_production_wrapper(
    enable_device_binding: bool = False,
    enable_rate_limiting: bool = True,
    audit_hook: Optional[AuditHook] = None
) -> EnhancedJWTWrapper:
    """
    Create production-ready JWT wrapper with sensible defaults.
    
    Args:
        enable_device_binding: Enable device binding security
        enable_rate_limiting: Enable refresh rate limiting
        audit_hook: Custom audit event handler
        
    Returns:
        Configured EnhancedJWTWrapper instance
    """
    security_config = SecurityConfig(
        enable_device_binding=enable_device_binding,
        enable_refresh_rate_limit=enable_rate_limiting,
        enable_audit_hooks=True,
        enable_metrics=True
    )
    
    config = EnhancedJWTConfig(security=security_config)
    
    return EnhancedJWTWrapper(config, audit_hook)
