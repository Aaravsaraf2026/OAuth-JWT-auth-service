"""
Production-grade JWT wrapper with Redis-backed token management.

This module provides secure JWT token creation, validation, and revocation
with optional Redis integration for token blacklisting and rotation.

Features:
- Access and refresh token generation
- Token validation with comprehensive error handling
- Redis-backed token revocation (optional)
- Configurable via environment variables
- Token rotation support
- Clock skew tolerance
- Comprehensive logging
- Type safety
"""

import os
import time
import uuid
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, Literal
from enum import Enum

try:
    import jwt
except ImportError:
    raise ImportError(
        "PyJWT is required. Install with: pip install PyJWT"
    )

# Optional Redis dependency
try:
    from repo.redis.worker import connection_manager
except ImportError:
    connection_manager = None


# ================= LOGGING SETUP =================

logger = logging.getLogger(__name__)
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


# ================= ENUMS =================

class TokenType(str, Enum):
    """Token type enumeration for type safety."""
    ACCESS = "access"
    REFRESH = "refresh"


# ================= CONFIG =================

@dataclass
class JWTConfig:
    """
    JWT configuration loaded from environment variables.
    
    All settings can be overridden via environment variables with JWT_ prefix.
    """
    
    # Redis settings
    use_redis: bool = field(
        default_factory=lambda: os.getenv("JWT_USE_REDIS", "true").lower() == "true"
    )
    
    # Secrets (CRITICAL: Must be set in production)
    secret: str = field(
        default_factory=lambda: os.getenv("JWT_SECRET", "")
    )
    refresh_secret: str = field(
        default_factory=lambda: os.getenv("JWT_REFRESH_SECRET", "")
    )
    
    # TTL settings (in seconds)
    access_ttl: int = field(
        default_factory=lambda: int(os.getenv("JWT_ACCESS_TTL", "900"))  # 15 minutes
    )
    refresh_ttl: int = field(
        default_factory=lambda: int(os.getenv("JWT_REFRESH_TTL", "604800"))  # 7 days
    )
    
    # JWT settings
    algorithm: str = field(
        default_factory=lambda: os.getenv("JWT_ALGORITHM", "HS384")
    )
    issuer: str = field(
        default_factory=lambda: os.getenv("JWT_ISSUER", "koko")
    )
    audience: str = field(
        default_factory=lambda: os.getenv("JWT_AUDIENCE", "app")
    )
    
    # Security settings
    clock_skew: int = field(
        default_factory=lambda: int(os.getenv("JWT_CLOCK_SKEW", "30"))  # 30 seconds
    )
    rotate_refresh: bool = field(
        default_factory=lambda: os.getenv("JWT_ROTATE_REFRESH", "true").lower() == "true"
    )
    strict_mode: bool = field(
        default_factory=lambda: os.getenv("JWT_STRICT_MODE", "true").lower() == "true"
    )
    
    # Redis settings
    blacklist_prefix: str = field(
        default_factory=lambda: os.getenv("JWT_BLACKLIST_PREFIX", "jwt:blacklist")
    )
    
    def __post_init__(self):
        """Validate configuration after initialization."""
        self._validate()
    
    def _validate(self):
        """Validate critical configuration values."""
        errors = []
        
        if not self.secret or len(self.secret) < 32:
            errors.append(
                "JWT_SECRET must be set and at least 32 characters for production use"
            )
        
        if not self.refresh_secret or len(self.refresh_secret) < 32:
            errors.append(
                "JWT_REFRESH_SECRET must be set and at least 32 characters for production use"
            )
        
        if self.secret == self.refresh_secret:
            errors.append(
                "JWT_SECRET and JWT_REFRESH_SECRET must be different"
            )
        
        if self.access_ttl <= 0:
            errors.append("JWT_ACCESS_TTL must be positive")
        
        if self.refresh_ttl <= 0:
            errors.append("JWT_REFRESH_TTL must be positive")
        
        if self.access_ttl >= self.refresh_ttl:
            errors.append(
                "JWT_ACCESS_TTL should be less than JWT_REFRESH_TTL"
            )
        
        if self.algorithm not in ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512"]:
            errors.append(
                f"JWT_ALGORITHM '{self.algorithm}' is not supported. "
                f"For single-service apps use HS384 or HS512. "
                f"For multi-service/microservice apps use RS256 or RS384 (asymmetric — safer)."
            )
        
        if errors:
            error_msg = "JWT Configuration errors:\n" + "\n".join(f"  - {e}" for e in errors)
            raise ValueError(error_msg)
        
        logger.info(
            f"JWT Config initialized: algorithm={self.algorithm}, "
            f"access_ttl={self.access_ttl}s, refresh_ttl={self.refresh_ttl}s, "
            f"use_redis={self.use_redis}, strict_mode={self.strict_mode}"
        )


# ================= EXCEPTIONS =================

class JWTError(Exception):
    """Base exception for JWT-related errors."""
    pass


class TokenExpired(JWTError):
    """Raised when a token has expired."""
    pass


class TokenRevoked(JWTError):
    """Raised when a token has been revoked."""
    pass


class InvalidToken(JWTError):
    """Raised when a token is invalid or malformed."""
    pass


class RedisUnavailable(JWTError):
    """Raised when Redis is unavailable in strict mode."""
    pass


class ConfigurationError(JWTError):
    """Raised when configuration is invalid."""
    pass


# ================= MAIN WRAPPER =================

class JWTWrapper:
    """
    Production-grade JWT wrapper with Redis-backed token management.
    
    Provides secure token creation, validation, and revocation with
    comprehensive error handling and logging.
    
    Example:
        >>> config = JWTConfig()
        >>> jwt_wrapper = JWTWrapper(config)
        >>> access_token = jwt_wrapper.create_access_token("user123", {"role": "admin"})
        >>> payload = jwt_wrapper.verify(access_token)
    """
    
    def __init__(self, config: Optional[JWTConfig] = None):
        """
        Initialize JWT wrapper with configuration.
        
        Args:
            config: JWT configuration. If None, loads from environment.
            
        Raises:
            ConfigurationError: If configuration is invalid.
            JWTError: If Redis is required but unavailable.
        """
        try:
            self.config = config or JWTConfig()
        except ValueError as e:
            raise ConfigurationError(str(e))
        
        # Validate Redis availability if required
        if self.config.use_redis and connection_manager is None:
            error_msg = (
                "Redis wrapper (connection_manager) not available. "
                "Either install Redis dependencies or set JWT_USE_REDIS=false"
            )
            logger.error(error_msg)
            raise JWTError(error_msg)
        
        logger.info("JWTWrapper initialized successfully")
    
    # ================= INTERNAL HELPERS =================
    
    def _now(self) -> int:
        """
        Get current Unix timestamp.
        
        Returns:
            Current timestamp as integer.
        """
        return int(time.time())
    
    def _blacklist_key(self, jti: str) -> str:
        """
        Generate Redis key for blacklisted token.
        
        Args:
            jti: JWT ID (unique token identifier).
            
        Returns:
            Redis key string.
        """
        return f"{self.config.blacklist_prefix}:{jti}"
    
    def _get_redis(self):
        """
        Get Redis client with error handling.
        
        Returns:
            Redis client or None if unavailable.
            
        Raises:
            RedisUnavailable: If Redis is unavailable in strict mode.
        """
        if not self.config.use_redis:
            return None
        
        try:
            redis_client = connection_manager.get_client()
            if redis_client is None:
                raise RedisUnavailable("Redis client returned None")
            return redis_client
        except Exception as e:
            logger.error(f"Redis connection error: {e}")
            if self.config.strict_mode:
                raise RedisUnavailable(f"Redis unavailable: {e}")
            logger.warning("Redis unavailable, continuing without token blacklist")
            return None
    
    def _blacklist(self, jti: str, exp: int) -> bool:
        """
        Add token to blacklist in Redis.
        
        Args:
            jti: JWT ID to blacklist.
            exp: Token expiration timestamp.
            
        Returns:
            True if successfully blacklisted, False otherwise.
        """
        redis = self._get_redis()
        if not redis:
            logger.warning(f"Cannot blacklist token {jti}: Redis unavailable")
            return False
        
        ttl = exp - self._now()
        if ttl <= 0:
            logger.debug(f"Token {jti} already expired, skipping blacklist")
            return False
        
        try:
            redis.set(self._blacklist_key(jti), "1", ex=ttl)
            logger.info(f"Token {jti} blacklisted for {ttl}s")
            return True
        except Exception as e:
            logger.error(f"Failed to blacklist token {jti}: {e}")
            if self.config.strict_mode:
                raise RedisUnavailable(f"Failed to blacklist token: {e}")
            return False
    
    def _is_revoked(self, jti: str) -> bool:
        """
        Check if token is in the blacklist.
        
        Args:
            jti: JWT ID to check.
            
        Returns:
            True if token is revoked, False otherwise.
        """
        redis = self._get_redis()
        if not redis:
            return False
        
        try:
            is_revoked = bool(redis.exists(self._blacklist_key(jti)))
            if is_revoked:
                logger.warning(f"Token {jti} is revoked")
            return is_revoked
        except Exception as e:
            logger.error(f"Error checking revocation status for {jti}: {e}")
            if self.config.strict_mode:
                raise RedisUnavailable(f"Failed to check revocation: {e}")
            return False
    
    def _build_payload(
        self,
        sub: str,
        typ: TokenType,
        ttl: int,
        data: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Build JWT payload with standard claims.
        
        Args:
            sub: Subject (user identifier).
            typ: Token type (access or refresh).
            ttl: Time-to-live in seconds.
            data: Additional custom claims.
            
        Returns:
            Complete JWT payload dictionary.
        """
        now = self._now()
        jti = str(uuid.uuid4())
        
        payload = {
            "sub": sub,
            "typ": typ.value,
            "jti": jti,
            "iat": now,
            "exp": now + ttl,
            "iss": self.config.issuer,
            "aud": self.config.audience,
            "data": data or {}
        }
        
        logger.debug(f"Created payload for {sub} (type={typ.value}, jti={jti})")
        return payload
    
    def _get_secret(self, token_type: TokenType) -> str:
        """
        Get the appropriate secret for token type.
        
        Args:
            token_type: Type of token (access or refresh).
            
        Returns:
            Secret key for the token type.
        """
        return (
            self.config.secret 
            if token_type == TokenType.ACCESS 
            else self.config.refresh_secret
        )
    
    # ================= PUBLIC API =================
    
    def create_access_token(
        self,
        sub: str,
        data: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Create a new access token.
        
        Args:
            sub: Subject identifier (typically user ID).
            data: Optional custom claims to include in token.
            
        Returns:
            Encoded JWT access token string.
            
        Raises:
            JWTError: If token creation fails.
            
        Example:
            >>> token = jwt_wrapper.create_access_token("user123", {"role": "admin"})
        """
        if not sub or not isinstance(sub, str):
            raise ValueError("Subject (sub) must be a non-empty string")
        
        try:
            payload = self._build_payload(
                sub, 
                TokenType.ACCESS, 
                self.config.access_ttl, 
                data
            )
            token = jwt.encode(
                payload, 
                self.config.secret, 
                algorithm=self.config.algorithm
            )
            logger.info(f"Access token created for {sub}")
            return token
        except Exception as e:
            logger.error(f"Failed to create access token: {e}")
            raise JWTError(f"Token creation failed: {e}")
    
    def create_refresh_token(
        self,
        sub: str,
        data: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Create a new refresh token.
        
        Args:
            sub: Subject identifier (typically user ID).
            data: Optional custom claims to include in token.
            
        Returns:
            Encoded JWT refresh token string.
            
        Raises:
            JWTError: If token creation fails.
            
        Example:
            >>> token = jwt_wrapper.create_refresh_token("user123")
        """
        if not sub or not isinstance(sub, str):
            raise ValueError("Subject (sub) must be a non-empty string")
        
        try:
            payload = self._build_payload(
                sub,
                TokenType.REFRESH,
                self.config.refresh_ttl,
                data
            )
            token = jwt.encode(
                payload,
                self.config.refresh_secret,
                algorithm=self.config.algorithm
            )
            logger.info(f"Refresh token created for {sub}")
            return token
        except Exception as e:
            logger.error(f"Failed to create refresh token: {e}")
            raise JWTError(f"Token creation failed: {e}")
    
    def create_token_pair(
        self,
        sub: str,
        data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, str]:
        """
        Create both access and refresh tokens.
        
        Args:
            sub: Subject identifier (typically user ID).
            data: Optional custom claims to include in both tokens.
            
        Returns:
            Dictionary with 'access_token' and 'refresh_token' keys.
            
        Example:
            >>> tokens = jwt_wrapper.create_token_pair("user123", {"role": "admin"})
            >>> access = tokens['access_token']
            >>> refresh = tokens['refresh_token']
        """
        return {
            "access_token": self.create_access_token(sub, data),
            "refresh_token": self.create_refresh_token(sub, data)
        }
    
    def verify(
        self,
        token: str,
        expected_type: Literal["access", "refresh"] = "access"
    ) -> Dict[str, Any]:
        """
        Verify and decode a JWT token.
        
        Args:
            token: JWT token string to verify.
            expected_type: Expected token type ("access" or "refresh").
            
        Returns:
            Dictionary containing:
                - sub: Subject identifier
                - data: Custom claims dictionary
                - jti: JWT ID
                - iat: Issued at timestamp
                - exp: Expiration timestamp
            
        Raises:
            TokenExpired: If token has expired.
            TokenRevoked: If token has been revoked.
            InvalidToken: If token is invalid or wrong type.
            
        Example:
            >>> payload = jwt_wrapper.verify(token)
            >>> user_id = payload['sub']
            >>> user_data = payload['data']
        """
        if not token or not isinstance(token, str):
            raise InvalidToken("Token must be a non-empty string")
        
        # First decode without verification to check token type
        # This prevents using wrong secret for verification
        try:
            unverified_payload = jwt.decode(
                token,
                options={"verify_signature": False}
            )
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token format: {e}")
            raise InvalidToken(f"Token decode failed: {e}")
        
        # Check token type matches expected BEFORE verification
        token_type_claim = unverified_payload.get("typ")
        if token_type_claim != expected_type:
            logger.warning(
                f"Token type mismatch: expected {expected_type}, got {token_type_claim}"
            )
            raise InvalidToken(
                f"Wrong token type: expected {expected_type}, got {token_type_claim}"
            )
        
        # Now verify with the correct secret based on actual token type
        token_type = TokenType(expected_type)
        secret = self._get_secret(token_type)
        
        try:
            payload = jwt.decode(
                token,
                secret,
                algorithms=[self.config.algorithm],
                audience=self.config.audience,
                issuer=self.config.issuer,
                leeway=self.config.clock_skew,
            )
        except jwt.ExpiredSignatureError as e:
            logger.warning(f"Token expired: {e}")
            raise TokenExpired("Token has expired")
        except jwt.InvalidAudienceError as e:
            logger.warning(f"Invalid audience: {e}")
            raise InvalidToken("Token audience mismatch")
        except jwt.InvalidIssuerError as e:
            logger.warning(f"Invalid issuer: {e}")
            raise InvalidToken("Token issuer mismatch")
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            raise InvalidToken(f"Token validation failed: {e}")
        
        jti = payload.get("jti")
        if not jti:
            raise InvalidToken("Token missing JTI claim")
        
        # Check if token is revoked
        if self.config.use_redis and self._is_revoked(jti):
            raise TokenRevoked("Token has been revoked")
        
        logger.debug(f"Token verified successfully: {jti}")
        
        return {
            "sub": payload["sub"],
            "data": payload.get("data", {}),
            "jti": jti,
            "iat": payload.get("iat"),
            "exp": payload.get("exp")
        }
    
    def refresh_access_token(
        self,
        refresh_token: str,
        rotate: Optional[bool] = None
    ) -> Dict[str, str]:
        """
        Generate new access token (and optionally new refresh token) from refresh token.
        
        Args:
            refresh_token: Valid refresh token.
            rotate: Whether to rotate refresh token. If None, uses config setting.
            
        Returns:
            Dictionary with 'access_token' and optionally 'refresh_token' keys.
            
        Raises:
            TokenExpired: If refresh token has expired.
            TokenRevoked: If refresh token has been revoked.
            InvalidToken: If refresh token is invalid.
            
        Example:
            >>> tokens = jwt_wrapper.refresh_access_token(old_refresh_token)
            >>> new_access = tokens['access_token']
            >>> new_refresh = tokens.get('refresh_token')  # If rotation enabled
        """
        # Verify the refresh token
        payload = self.verify(refresh_token, expected_type="refresh")
        
        sub = payload["sub"]
        data = payload["data"]
        
        # Create new access token
        new_access = self.create_access_token(sub, data)
        
        result = {"access_token": new_access}
        
        # Rotate refresh token if configured
        should_rotate = rotate if rotate is not None else self.config.rotate_refresh
        if should_rotate:
            # Revoke old refresh token
            old_jti = payload["jti"]
            old_exp = payload["exp"]
            self.revoke(old_jti, old_exp)
            
            # Create new refresh token
            new_refresh = self.create_refresh_token(sub, data)
            result["refresh_token"] = new_refresh
            logger.info(f"Refresh token rotated for {sub}")
        
        logger.info(f"Access token refreshed for {sub}")
        return result
    
    def revoke(self, jti: str, exp: int) -> bool:
        """
        Revoke a token by adding it to the blacklist.
        
        Args:
            jti: JWT ID of token to revoke.
            exp: Token expiration timestamp.
            
        Returns:
            True if successfully revoked, False otherwise.
            
        Example:
            >>> payload = jwt_wrapper.decode(token)
            >>> jwt_wrapper.revoke(payload['jti'], payload['exp'])
        """
        if not self.config.use_redis:
            if self.config.strict_mode:
                raise RedisUnavailable(
                    "Token revocation requires Redis. "
                    "Set JWT_USE_REDIS=true or disable JWT_STRICT_MODE."
                )
            logger.warning("Token revocation skipped: Redis not enabled")
            return False
        
        return self._blacklist(jti, exp)
    
    def revoke_token(self, token: str) -> bool:
        """
        Revoke a token by decoding it first.
        
        Args:
            token: JWT token string to revoke.
            
        Returns:
            True if successfully revoked, False otherwise.
            
        Example:
            >>> jwt_wrapper.revoke_token(access_token)
        """
        try:
            payload = self.decode_unverified(token)
            return self.revoke(payload["jti"], payload["exp"])
        except Exception as e:
            logger.error(f"Failed to revoke token: {e}")
            return False
    
    def decode_unverified(self, token: str) -> Dict[str, Any]:
        """
        Decode token without verification (use with caution).
        
        This method does NOT validate the signature or check expiration.
        Only use when you need to inspect token contents without validation.
        
        Args:
            token: JWT token string to decode.
            
        Returns:
            Token payload dictionary.
            
        Raises:
            InvalidToken: If token cannot be decoded.
            
        Example:
            >>> payload = jwt_wrapper.decode(token)
            >>> user_id = payload['sub']
        """
        try:
            return jwt.decode(token, options={"verify_signature": False})
        except jwt.InvalidTokenError as e:
            logger.error(f"Failed to decode token: {e}")
            raise InvalidToken(f"Token decode failed: {e}")
    
    def get_token_info(self, token: str) -> Dict[str, Any]:
        """
        Get information about a token without full verification.
        
        Args:
            token: JWT token string.
            
        Returns:
            Dictionary with token metadata including sub, exp, iat, typ, etc.
            
        Example:
            >>> info = jwt_wrapper.get_token_info(token)
            >>> print(f"Token expires at: {info['exp']}")
        """
        payload = self.decode_unverified(token)
        
        return {
            "sub": payload.get("sub"),
            "jti": payload.get("jti"),
            "typ": payload.get("typ"),
            "iat": payload.get("iat"),
            "exp": payload.get("exp"),
            "iss": payload.get("iss"),
            "aud": payload.get("aud"),
            "is_expired": payload.get("exp", 0) < self._now(),
            "data": payload.get("data", {})
        }


# ================= CONVENIENCE FUNCTIONS =================

# Module-level singleton instance (optional convenience)
_default_wrapper: Optional[JWTWrapper] = None


def get_default_wrapper() -> JWTWrapper:
    """
    Get or create the default JWT wrapper instance.
    
    Returns:
        Shared JWTWrapper instance.
        
    Example:
        >>> wrapper = get_default_wrapper()
        >>> token = wrapper.create_access_token("user123")
    """
    global _default_wrapper
    if _default_wrapper is None:
        _default_wrapper = JWTWrapper()
    return _default_wrapper


def create_access_token(sub: str, data: Optional[Dict[str, Any]] = None) -> str:
    """Convenience function using default wrapper."""
    return get_default_wrapper().create_access_token(sub, data)


def create_refresh_token(sub: str, data: Optional[Dict[str, Any]] = None) -> str:
    """Convenience function using default wrapper."""
    return get_default_wrapper().create_refresh_token(sub, data)


def verify_token(
    token: str,
    expected_type: Literal["access", "refresh"] = "access"
) -> Dict[str, Any]:
    """Convenience function using default wrapper."""
    return get_default_wrapper().verify(token, expected_type)
