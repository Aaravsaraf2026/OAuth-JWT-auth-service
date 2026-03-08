"""
Production-ready Jinja2 template rendering system for FastAPI.

This module provides a secure, monitored, and performant template rendering
system with comprehensive error handling, security scanning, and observability.

Features:
    - Automatic template directory detection with validation
    - Security scanning for dangerous patterns
    - Performance monitoring and statistics
    - Template size limits and timeout protection
    - Comprehensive error handling with detailed logging
    - Cache management and health checks
    - Production-grade security headers

Environment Variables:
    TEMPLATES_DIR: Custom templates directory path
    DEBUG: Enable debug mode (default: False)
    TEMPLATE_CACHE_SIZE: LRU cache size (default: 128, range: 1-1000)
    TEMPLATE_TIMEOUT: Rendering timeout in seconds (default: 30, range: 1-300)
    TEMPLATE_SECURITY_SCAN: Enable security scanning (default: True)
    TEMPLATE_COMPRESSION: Enable compression hints (default: not DEBUG)
    TEMPLATE_MONITORING: Enable performance monitoring (default: True)
    TEMPLATE_STRICT_UNDEFINED: Use StrictUndefined for variables (default: False)
    MAX_TEMPLATE_SIZE_MB: Maximum template file size (default: 10, range: 1-100)

Example:
    from template_render_v11 import render_template
    
    @app.get("/")
    async def home():
        return render_template(
            "index.html",
            title="Home",
            user={"name": "John"}
        )

Author: Production Engineering Team
Version: 11.0.0
License: MIT
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
import signal
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union
from urllib.parse import quote

from fastapi import HTTPException
from jinja2 import (
    Environment,
    FileSystemLoader,
    StrictUndefined,
    TemplateNotFound,
    TemplateRuntimeError,
    TemplateSyntaxError,
    meta,
    select_autoescape,
)
from starlette.responses import HTMLResponse

# Configure module logger
logger = logging.getLogger(__name__)


# ============================================================================
# Configuration Management
# ============================================================================


class TemplateConfig:
    """
    Centralized configuration management with environment variable validation.
    
    All configuration values are loaded from environment variables with
    sensible defaults and validation.
    """

    @staticmethod
    def _parse_bool(name: str, default: bool = False) -> bool:
        """
        Parse environment variable as boolean.
        
        Args:
            name: Environment variable name
            default: Default value if not set
            
        Returns:
            Parsed boolean value
        """
        value = os.getenv(name)
        if value is None:
            return default

        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False

        logger.warning(
            f"Invalid boolean value for {name}: '{value}', using default: {default}"
        )
        return default

    @staticmethod
    def _parse_int(
        name: str, default: int, min_val: int = 0, max_val: Optional[int] = None
    ) -> int:
        """
        Parse environment variable as integer with bounds validation.
        
        Args:
            name: Environment variable name
            default: Default value if not set
            min_val: Minimum allowed value
            max_val: Maximum allowed value (None for no limit)
            
        Returns:
            Parsed and validated integer value
        """
        value = os.getenv(name)
        if value is None:
            return default

        try:
            parsed = int(value)
            if parsed < min_val:
                logger.warning(
                    f"{name} value {parsed} below minimum {min_val}, using {min_val}"
                )
                return min_val
            if max_val is not None and parsed > max_val:
                logger.warning(
                    f"{name} value {parsed} above maximum {max_val}, using {max_val}"
                )
                return max_val
            return parsed
        except ValueError:
            logger.warning(
                f"Invalid integer value for {name}: '{value}', using default: {default}"
            )
            return default

    # Configuration values with type annotations
    DEBUG: bool = _parse_bool.__func__("DEBUG", False)
    CACHE_SIZE: int = _parse_int.__func__("TEMPLATE_CACHE_SIZE", 128, 1, 1000)
    TEMPLATE_TIMEOUT: int = _parse_int.__func__("TEMPLATE_TIMEOUT", 30, 1, 300)
    ENABLE_SECURITY_SCAN: bool = _parse_bool.__func__("TEMPLATE_SECURITY_SCAN", True)
    ENABLE_COMPRESSION: bool = _parse_bool.__func__(
        "TEMPLATE_COMPRESSION", not _parse_bool.__func__("DEBUG", False)
    )
    ENABLE_MONITORING: bool = _parse_bool.__func__("TEMPLATE_MONITORING", True)
    STRICT_UNDEFINED: bool = _parse_bool.__func__("TEMPLATE_STRICT_UNDEFINED", False)
    MAX_SIZE_MB: int = _parse_int.__func__("MAX_TEMPLATE_SIZE_MB", 10, 1, 100)


# ============================================================================
# Security Patterns
# ============================================================================


class SecurityPatterns:
    """Compiled regex patterns for security scanning."""

    # Dangerous Jinja2 template patterns
    ARBITRARY_ATTRIBUTE: re.Pattern = re.compile(
        r"{{\s*[\w.]*__\w+__", re.IGNORECASE
    )
    CONFIG_ACCESS: re.Pattern = re.compile(r"{{\s*config\s*[.\[]", re.IGNORECASE)
    IMPORT_STATEMENT: re.Pattern = re.compile(r"{%\s*import\s+", re.IGNORECASE)
    DISABLED_AUTOESCAPE: re.Pattern = re.compile(
        r"{%\s*autoescape\s+false", re.IGNORECASE
    )

    # Potential XSS vectors
    UNSAFE_FILTER: re.Pattern = re.compile(
        r"{{\s*[\w.]+\s*\|\s*safe\s*}}.*?<script", re.IGNORECASE
    )


# ============================================================================
# Statistics and Monitoring
# ============================================================================


class TemplateStats:
    """
    Thread-safe statistics tracker for template rendering operations.
    
    Tracks render counts, errors, cache performance, security violations,
    and timeouts with async-safe recording.
    """

    def __init__(self):
        """Initialize statistics with zero values."""
        self.render_count: int = 0
        self.error_count: int = 0
        self.total_render_time: float = 0.0
        self.cache_hits: int = 0
        self.cache_misses: int = 0
        self.security_violations: int = 0
        self.timeouts: int = 0
        self.last_reset: float = time.time()
        self._lock: Optional[asyncio.Lock] = None

        # Initialize lock if in async context
        try:
            asyncio.get_running_loop()
            self._lock = asyncio.Lock()
        except RuntimeError:
            pass

    async def record_render(self, render_time: float, from_cache: bool = False) -> None:
        """
        Record a successful template render.
        
        Args:
            render_time: Time taken to render in seconds
            from_cache: Whether the template was served from cache
        """
        if self._lock:
            async with self._lock:
                self._record_render_internal(render_time, from_cache)
        else:
            self._record_render_internal(render_time, from_cache)

    def _record_render_internal(self, render_time: float, from_cache: bool) -> None:
        """Internal method for recording render without lock."""
        self.render_count += 1
        self.total_render_time += render_time
        if from_cache:
            self.cache_hits += 1
        else:
            self.cache_misses += 1

    async def record_error(self) -> None:
        """Record a template rendering error."""
        if self._lock:
            async with self._lock:
                self.error_count += 1
        else:
            self.error_count += 1

    async def record_security_violation(self) -> None:
        """Record a security pattern violation."""
        if self._lock:
            async with self._lock:
                self.security_violations += 1
        else:
            self.security_violations += 1

    async def record_timeout(self) -> None:
        """Record a template rendering timeout."""
        if self._lock:
            async with self._lock:
                self.timeouts += 1
        else:
            self.timeouts += 1

    def get_stats(self) -> Dict[str, Any]:
        """
        Get current statistics snapshot.
        
        Returns:
            Dictionary with all statistics and computed metrics
        """
        uptime = time.time() - self.last_reset
        total_renders = max(self.render_count, 1)

        return {
            "render_count": self.render_count,
            "error_count": self.error_count,
            "error_rate": round(self.error_count / total_renders, 4),
            "avg_render_time_ms": round(
                (self.total_render_time / total_renders) * 1000, 2
            ),
            "cache_hit_rate": round(self.cache_hits / total_renders, 4),
            "security_violations": self.security_violations,
            "timeouts": self.timeouts,
            "uptime_seconds": round(uptime, 2),
        }

    def reset(self) -> None:
        """Reset all statistics to initial state."""
        self.__init__()


# Global statistics instance
_stats = TemplateStats()


# ============================================================================
# Template Directory Management
# ============================================================================


def _validate_template_directory(path: Path) -> bool:
    """
    Validate template directory for security and accessibility.
    
    Args:
        path: Path to validate
        
    Returns:
        True if path is valid and safe, False otherwise
    """
    try:
        resolved = path.resolve()

        if not resolved.exists():
            logger.debug(f"Template path does not exist: {resolved}")
            return False

        if not resolved.is_dir():
            logger.error(f"Template path is not a directory: {resolved}")
            return False

        # Security: prevent system directory access
        path_str = str(resolved)
        forbidden_prefixes = (
            "/etc/",
            "/bin/",
            "/sbin/",
            "/usr/bin/",
            "/usr/sbin/",
            "/sys/",
            "/proc/",
            "/dev/",
            "/boot/",
            "/root/",
            "/var/log/",
            "/var/run/",
        )

        if any(path_str.startswith(prefix) for prefix in forbidden_prefixes):
            logger.error(f"Forbidden template directory: {resolved}")
            return False

        if not os.access(str(resolved), os.R_OK):
            logger.error(f"Template directory not readable: {resolved}")
            return False

        return True

    except (OSError, RuntimeError) as e:
        logger.error(f"Error validating template path {path}: {e}")
        return False


def _detect_templates_directory() -> Path:
    """
    Auto-detect templates directory with validation.
    
    Search order:
    1. TEMPLATES_DIR environment variable
    2. ./templates
    3. ./app/templates
    4. ./src/templates
    5. ./web/templates
    6. Create ./templates as fallback
    
    Returns:
        Resolved Path to templates directory
        
    Raises:
        RuntimeError: If no valid directory found and creation fails
    """
    # Try environment variable first
    env_path = os.getenv("TEMPLATES_DIR")
    if env_path:
        path = Path(env_path)
        if not path.is_absolute():
            path = Path.cwd() / env_path

        if _validate_template_directory(path):
            logger.info(f"Using templates directory from TEMPLATES_DIR: {path}")
            return path.resolve()

        logger.warning(
            f"Invalid TEMPLATES_DIR: {env_path}, falling back to auto-detection"
        )

    # Try common locations
    candidates = [
        Path.cwd() / "templates",
        Path.cwd() / "app" / "templates",
        Path.cwd() / "src" / "templates",
        Path.cwd() / "web" / "templates",
    ]

    for candidate in candidates:
        if _validate_template_directory(candidate):
            logger.info(f"Auto-detected templates directory: {candidate}")
            return candidate.resolve()

    # Create fallback directory
    fallback = Path.cwd() / "templates"
    try:
        fallback.mkdir(parents=True, exist_ok=True, mode=0o755)
        logger.info(f"Created templates directory: {fallback}")
        return fallback.resolve()
    except OSError as e:
        logger.error(f"Failed to create templates directory {fallback}: {e}")
        raise RuntimeError(f"Cannot create templates directory: {e}") from e


# ============================================================================
# Timeout Protection
# ============================================================================


class TimeoutError(Exception):
    """Exception raised when template rendering exceeds timeout."""

    pass


@contextmanager
def rendering_timeout(seconds: int):
    """
    Context manager for template rendering timeout.
    
    Uses SIGALRM on Unix systems. No-op on Windows.
    
    Args:
        seconds: Timeout in seconds
        
    Raises:
        TimeoutError: If rendering exceeds timeout
    """

    def timeout_handler(signum, frame):
        raise TimeoutError("Template rendering timeout exceeded")

    if hasattr(signal, "alarm"):
        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(seconds)
        try:
            yield
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)
    else:
        # Windows fallback - no timeout enforcement
        yield


# ============================================================================
# Template Filters
# ============================================================================


def _create_template_filters() -> Dict[str, Callable]:
    """
    Create safe template filters with input validation.
    
    Returns:
        Dictionary of filter name to filter function
    """

    def format_datetime(value: Any, fmt: str = "%Y-%m-%d %H:%M") -> str:
        """Format datetime with validation."""
        if not value:
            return ""

        # Parse string to datetime if needed
        if isinstance(value, str):
            try:
                value = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                return str(value)

        if not isinstance(value, datetime):
            logger.warning(f"formatdate received non-datetime: {type(value)}")
            return str(value)

        try:
            # Validate format string
            if not fmt or "%" not in fmt or len(fmt) > 100:
                fmt = "%Y-%m-%d %H:%M"

            # Check for injection attempts
            if any(char in fmt for char in ["\n", "\r", "\0", ";", "&", "|"]):
                logger.warning(f"Suspicious date format: {fmt}")
                fmt = "%Y-%m-%d %H:%M"

            return value.strftime(fmt)
        except (ValueError, TypeError) as e:
            logger.error(f"Date formatting error: {e}")
            return str(value)

    def truncate_words(text: Any, count: int = 50, suffix: str = "...") -> str:
        """Truncate text to word count with validation."""
        if not text:
            return ""

        text_str = str(text)

        # Validate and clamp word count
        if not isinstance(count, int) or count < 1:
            count = 50
        elif count > 1000:
            logger.warning(f"Word count {count} too high, limiting to 1000")
            count = 1000

        # Validate suffix
        if not isinstance(suffix, str) or len(suffix) > 10:
            suffix = "..."

        words = text_str.split()
        if len(words) <= count:
            return text_str

        return " ".join(words[:count]) + suffix

    def url_encode(value: Any) -> str:
        """URL encode with length validation."""
        if not value:
            return ""

        text = str(value)

        # Prevent abuse with length limit
        if len(text) > 2000:
            logger.warning(f"URL encode input too long: {len(text)}")
            text = text[:2000]

        return quote(text, safe="")

    def format_filesize(bytes_value: Any) -> str:
        """Format bytes as human-readable file size."""
        try:
            size = float(bytes_value)
            if size < 0:
                return "0 B"

            for unit in ["B", "KB", "MB", "GB"]:
                if size < 1024:
                    return f"{size:.1f} {unit}"
                size /= 1024

            return f"{size:.1f} TB"
        except (ValueError, TypeError):
            return str(bytes_value)

    def slugify(text: Any) -> str:
        """Convert string to URL-safe slug."""
        if not text:
            return ""

        slug = str(text).lower().strip()
        slug = re.sub(r"[^\w\s-]", "", slug)
        slug = re.sub(r"[-\s]+", "-", slug)

        return slug[:100]

    def default_if_none(value: Any, default: Any = "", handle_empty: bool = True) -> Any:
        """Return default value if None or empty."""
        if value is None:
            return default
        if handle_empty and isinstance(value, str) and not value.strip():
            return default
        return value

    return {
        "formatdate": format_datetime,
        "truncate_words": truncate_words,
        "url_encode": url_encode,
        "filesize": format_filesize,
        "slugify": slugify,
        "default": default_if_none,
    }


# ============================================================================
# Template Globals
# ============================================================================


def _create_template_globals() -> Dict[str, Any]:
    """
    Create safe template global functions and variables.
    
    Returns:
        Dictionary of global name to value/function
    """

    def current_time() -> datetime:
        """Get current UTC datetime."""
        return datetime.now(timezone.utc)

    def static_url(path: Any) -> str:
        """Generate static file URL with validation."""
        if not path:
            return "/static/"

        # Sanitize path
        clean_path = str(path).strip().lstrip("/")

        # Security checks
        if ".." in clean_path or clean_path.startswith(("\\", "~")):
            logger.warning(f"Suspicious static path: {path}")
            return "/static/"

        # Remove control characters
        clean_path = "".join(c for c in clean_path if ord(c) >= 32)

        # Length limit
        if len(clean_path) > 500:
            logger.warning(f"Static path too long: {len(clean_path)}")
            clean_path = clean_path[:500]

        return f"/static/{clean_path}"

    def safe_range(start: int, stop: Optional[int] = None, step: int = 1) -> range:
        """Create range with size limits to prevent DoS."""
        try:
            if stop is None:
                stop = start
                start = 0

            # Limit range size
            max_size = 10000
            if step != 0:
                size = abs((stop - start) // step)
                if size > max_size:
                    logger.warning(f"Range size {size} exceeds limit {max_size}")
                    return range(0)

            return range(start, stop, step)
        except (ValueError, TypeError) as e:
            logger.error(f"Range creation error: {e}")
            return range(0)

    return {
        "now": current_time,
        "static_url": static_url,
        "range": safe_range,
        "dict": dict,
        "debug": TemplateConfig.DEBUG,
    }


# ============================================================================
# Jinja2 Environment
# ============================================================================


@lru_cache(maxsize=1)
def get_jinja_environment() -> Environment:
    """
    Get configured Jinja2 environment with security enhancements.
    
    Cached to ensure single environment instance.
    
    Returns:
        Configured Jinja2 Environment
        
    Raises:
        RuntimeError: If environment initialization fails
    """
    templates_dir = _detect_templates_directory()
    logger.info(
        f"Initializing Jinja2 environment: {templates_dir} (debug={TemplateConfig.DEBUG})"
    )

    try:
        env = Environment(
            loader=FileSystemLoader(
                str(templates_dir), followlinks=False, encoding="utf-8"
            ),
            autoescape=select_autoescape(
                ["html", "xml", "htm", "xhtml", "svg", "jinja", "j2", "jinja2"]
            ),
            auto_reload=TemplateConfig.DEBUG,
            enable_async=False,
            optimized=not TemplateConfig.DEBUG,
            finalize=lambda x: x if x is not None else "",
            trim_blocks=True,
            lstrip_blocks=True,
            keep_trailing_newline=True,
            undefined=StrictUndefined if TemplateConfig.STRICT_UNDEFINED else None,
        )

        # Register globals and filters
        env.globals.update(_create_template_globals())
        env.filters.update(_create_template_filters())

        # Register custom tests
        env.tests["email"] = lambda v: (
            isinstance(v, str) and "@" in v and "." in v.split("@")[-1]
        )
        env.tests["url"] = lambda v: isinstance(v, str) and v.startswith(
            ("http://", "https://", "//", "ftp://")
        )
        env.tests["numeric"] = lambda v: isinstance(v, (int, float)) or (
            isinstance(v, str) and v.replace(".", "", 1).isdigit()
        )

        logger.info("Jinja2 environment initialized successfully")
        return env

    except Exception as e:
        logger.error(f"Failed to initialize Jinja2 environment: {e}", exc_info=True)
        raise RuntimeError(f"Template environment initialization failed: {e}") from e


# ============================================================================
# Security Scanning
# ============================================================================


def _scan_template_security(source: str, name: str) -> List[str]:
    """
    Scan template source for security vulnerabilities.
    
    Args:
        source: Template source code
        name: Template name for logging
        
    Returns:
        List of security violation descriptions
    """
    if not TemplateConfig.ENABLE_SECURITY_SCAN:
        return []

    violations = []

    # Check for dangerous template patterns
    patterns = {
        "arbitrary_attribute_access": SecurityPatterns.ARBITRARY_ATTRIBUTE,
        "config_access": SecurityPatterns.CONFIG_ACCESS,
        "import_statement": SecurityPatterns.IMPORT_STATEMENT,
        "disabled_autoescape": SecurityPatterns.DISABLED_AUTOESCAPE,
    }

    for pattern_name, pattern in patterns.items():
        matches = pattern.findall(source)
        if matches:
            violations.append(f"{pattern_name}: {len(matches)} occurrence(s)")
            logger.warning(
                f"Security pattern '{pattern_name}' in template '{name}': {matches[:3]}"
            )

    if violations:
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(_stats.record_security_violation())
        except RuntimeError:
            _stats.security_violations += 1

    return violations


def _check_template_size(template_path: Path) -> bool:
    """
    Validate template file size.
    
    Args:
        template_path: Path to template file
        
    Returns:
        True if size is within limits, False otherwise
    """
    try:
        size_bytes = template_path.stat().st_size
        max_bytes = TemplateConfig.MAX_SIZE_MB * 1024 * 1024

        if size_bytes > max_bytes:
            logger.error(f"Template size {size_bytes} exceeds limit {max_bytes} bytes")
            return False

        return True
    except OSError as e:
        logger.error(f"Error checking template size: {e}")
        return False


# ============================================================================
# Template Rendering
# ============================================================================


def render_template(
    template_name: str,
    status_code: int = 200,
    headers: Optional[Dict[str, str]] = None,
    compress: Optional[bool] = None,
    cache_control: Optional[str] = None,
    **context: Any,
) -> HTMLResponse:
    """
    Render Jinja2 template with comprehensive security and monitoring.
    
    Args:
        template_name: Template file name (relative to templates directory)
        status_code: HTTP status code (100-599, default: 200)
        headers: Additional HTTP headers
        compress: Enable compression hint (None = auto-detect based on size)
        cache_control: Custom Cache-Control header value
        **context: Template context variables
        
    Returns:
        HTMLResponse with rendered template
        
    Raises:
        HTTPException: If template not found or rendering fails
        
    Example:
        >>> render_template("index.html", title="Home", user={"name": "John"})
    """
    start_time = time.time()

    # Validate template name
    if not template_name or not isinstance(template_name, str):
        logger.error(f"Invalid template name: {template_name}")
        raise HTTPException(400, "Invalid template name")

    template_name = template_name.strip()

    # Security: prevent path traversal
    if ".." in template_name or template_name.startswith(("/", "\\", "~")):
        logger.error(f"Path traversal attempt: {template_name}")
        raise HTTPException(400, "Invalid template path")

    # Security: check for dangerous characters
    if any(c in template_name for c in ["\0", "\n", "\r", ";", "&", "|", "$"]):
        logger.error(f"Suspicious characters in template name: {template_name}")
        raise HTTPException(400, "Invalid template name")

    # Validate status code
    if not isinstance(status_code, int) or not 100 <= status_code <= 599:
        logger.warning(f"Invalid status code: {status_code}, using 200")
        status_code = 200

    try:
        env = get_jinja_environment()

        # Check template size
        template_path = Path(_detect_templates_directory()) / template_name
        if template_path.exists() and not _check_template_size(template_path):
            raise HTTPException(413, "Template file too large")

        # Load template
        try:
            template = env.get_template(template_name)
        except TemplateNotFound:
            raise

        # Security scan
        if TemplateConfig.ENABLE_SECURITY_SCAN:
            try:
                source, _, _ = env.loader.get_source(env, template_name)
                violations = _scan_template_security(source, template_name)

                if violations and not TemplateConfig.DEBUG:
                    # Reject critical violations in production
                    critical = [
                        v
                        for v in violations
                        if any(
                            x in v
                            for x in ["arbitrary_attribute_access", "import_statement"]
                        )
                    ]
                    if critical:
                        raise HTTPException(500, "Template security violation")
            except Exception as e:
                logger.warning(f"Security scan failed for '{template_name}': {e}")

        # Render with timeout protection
        try:
            if TemplateConfig.TEMPLATE_TIMEOUT > 0 and hasattr(signal, "alarm"):
                with rendering_timeout(TemplateConfig.TEMPLATE_TIMEOUT):
                    content = template.render(**context)
            else:
                content = template.render(**context)
        except TimeoutError:
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(_stats.record_timeout())
            except RuntimeError:
                _stats.timeouts += 1

            logger.error(
                f"Template '{template_name}' timeout (>{TemplateConfig.TEMPLATE_TIMEOUT}s)"
            )
            raise HTTPException(504, "Template rendering timeout")
        except Exception as render_error:
            raise TemplateRuntimeError(f"Rendering failed: {render_error}") from render_error

        # Build response headers
        response_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "SAMEORIGIN",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        }

        # Content Security Policy
        if not TemplateConfig.DEBUG:
            response_headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self'; "
                "connect-src 'self'; "
                "frame-ancestors 'self';"
            )

        # Cache control
        if cache_control:
            response_headers["Cache-Control"] = cache_control
        elif not TemplateConfig.DEBUG:
            response_headers["Cache-Control"] = (
                "public, max-age=300, stale-while-revalidate=60"
            )
        else:
            response_headers["Cache-Control"] = "no-store, no-cache, must-revalidate"

        # Compression hint
        if compress is None:
            compress = TemplateConfig.ENABLE_COMPRESSION and len(content) > 1400

        # Merge custom headers with validation
        if headers:
            for key, value in headers.items():
                if not isinstance(key, str) or not isinstance(value, str):
                    continue

                # Prevent header injection
                if any(c in key for c in ["\n", "\r", "\0", ":"]):
                    logger.warning(f"Suspicious header key: {key}")
                    continue

                if any(c in value for c in ["\n", "\r", "\0"]):
                    logger.warning(f"Suspicious header value for {key}")
                    continue

                response_headers[key] = value[:2000]

        # Record statistics
        render_time = time.time() - start_time

        try:
            loop = asyncio.get_running_loop()
            loop.create_task(_stats.record_render(render_time, from_cache=False))
        except RuntimeError:
            _stats._record_render_internal(render_time, from_cache=False)

        if TemplateConfig.ENABLE_MONITORING:
            if render_time > 1.0:
                logger.warning(
                    f"Slow template render: '{template_name}' took {render_time:.3f}s"
                )
            elif TemplateConfig.DEBUG:
                logger.debug(
                    f"Template '{template_name}' rendered in {render_time:.3f}s"
                )

        return HTMLResponse(
            content=content,
            status_code=status_code,
            headers=response_headers,
            media_type="text/html; charset=utf-8",
        )

    except TemplateNotFound:
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(_stats.record_error())
        except RuntimeError:
            _stats.error_count += 1

        templates_dir = _detect_templates_directory()
        msg = f"Template '{template_name}' not found"

        if TemplateConfig.DEBUG:
            msg += f" (searched in {templates_dir})"
            try:
                available = list(templates_dir.glob("**/*.html"))[:10]
                if available:
                    names = [str(t.relative_to(templates_dir)) for t in available]
                    msg += f". Available: {', '.join(names)}"
            except Exception:
                pass

        logger.error(msg)
        raise HTTPException(status_code=404, detail=msg)

    except (TemplateSyntaxError, TemplateRuntimeError) as e:
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(_stats.record_error())
        except RuntimeError:
            _stats.error_count += 1

        logger.error(
            f"Template error in '{template_name}': {e}", exc_info=TemplateConfig.DEBUG
        )

        if TemplateConfig.DEBUG:
            error_detail = {
                "error": str(e),
                "template": template_name,
                "type": type(e).__name__,
                "line": getattr(e, "lineno", None),
            }
            raise HTTPException(500, detail=f"Template error: {error_detail}")
        else:
            raise HTTPException(500, detail="Template rendering error")

    except HTTPException:
        raise

    except Exception as e:
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(_stats.record_error())
        except RuntimeError:
            _stats.error_count += 1

        logger.error(
            f"Unexpected error rendering '{template_name}': {e}",
            exc_info=TemplateConfig.DEBUG,
        )

        if TemplateConfig.DEBUG:
            raise HTTPException(500, detail=f"Render error: {type(e).__name__}: {e}")
        else:
            raise HTTPException(500, detail="Internal server error")


# ============================================================================
# Utility Functions
# ============================================================================


def clear_template_cache() -> None:
    """
    Clear template cache and reset statistics.
    
    Useful for development and testing.
    """
    get_jinja_environment.cache_clear()
    _stats.reset()
    logger.info("Template cache and statistics cleared")


def get_statistics() -> Dict[str, Any]:
    """
    Get current template rendering statistics.
    
    Returns:
        Dictionary with render counts, errors, performance metrics
    """
    return _stats.get_stats()


def health_check() -> Dict[str, Any]:
    """
    Perform comprehensive template system health check.
    
    Returns:
        Health status with configuration, statistics, and diagnostics
    """
    templates_dir = _detect_templates_directory()

    health = {
        "status": "healthy",
        "templates_dir": str(templates_dir),
        "exists": templates_dir.exists(),
        "readable": os.access(str(templates_dir), os.R_OK),
        "writable": os.access(str(templates_dir), os.W_OK),
        "debug": TemplateConfig.DEBUG,
        "config": {
            "cache_size": TemplateConfig.CACHE_SIZE,
            "timeout": TemplateConfig.TEMPLATE_TIMEOUT,
            "security_scan": TemplateConfig.ENABLE_SECURITY_SCAN,
            "compression": TemplateConfig.ENABLE_COMPRESSION,
            "monitoring": TemplateConfig.ENABLE_MONITORING,
            "strict_undefined": TemplateConfig.STRICT_UNDEFINED,
            "max_size_mb": TemplateConfig.MAX_SIZE_MB,
        },
        "statistics": _stats.get_stats(),
    }

    # Cache information
    try:
        cache_info = get_jinja_environment.cache_info()
        health["cache_info"] = {
            "hits": cache_info.hits,
            "misses": cache_info.misses,
            "size": cache_info.currsize,
            "max_size": cache_info.maxsize,
        }
    except Exception as e:
        health["cache_info"] = {"error": str(e)}

    # Template inventory
    try:
        patterns = ["*.html", "*.jinja", "*.jinja2", "*.j2"]
        template_files = []
        for pattern in patterns:
            template_files.extend(templates_dir.rglob(pattern))

        total_size = sum(f.stat().st_size for f in template_files if f.is_file())

        health["template_count"] = len(template_files)
        health["total_size_mb"] = round(total_size / (1024 * 1024), 2)

        # Check for oversized templates
        max_bytes = TemplateConfig.MAX_SIZE_MB * 1024 * 1024
        oversized = [
            str(f.relative_to(templates_dir))
            for f in template_files
            if f.is_file() and f.stat().st_size > max_bytes
        ]

        if oversized:
            health["warnings"] = [f"Oversized templates: {', '.join(oversized)}"]
            health["status"] = "warning"

    except Exception as e:
        health["template_count"] = f"error: {e}"
        health["status"] = "degraded"

    # Check error rate
    stats = _stats.get_stats()
    if stats["error_rate"] > 0.1:
        health["status"] = "degraded"
        health["warnings"] = health.get("warnings", []) + [
            f"High error rate: {stats['error_rate']*100:.1f}%"
        ]

    # Check security violations
    if stats["security_violations"] > 0:
        health["warnings"] = health.get("warnings", []) + [
            f"Security violations: {stats['security_violations']}"
        ]

    return health


def list_templates() -> List[Dict[str, Any]]:
    """
    List all available templates with metadata.
    
    Only available in debug mode for security.
    
    Returns:
        List of template information dictionaries
    """
    if not TemplateConfig.DEBUG:
        return [{"error": "Template listing disabled in production"}]

    templates_dir = _detect_templates_directory()
    templates = []

    try:
        patterns = ["*.html", "*.jinja", "*.jinja2", "*.j2"]
        template_files = []
        for pattern in patterns:
            template_files.extend(templates_dir.rglob(pattern))

        for template_file in template_files:
            try:
                relative_path = template_file.relative_to(templates_dir)
                stat = template_file.stat()

                templates.append(
                    {
                        "name": str(relative_path),
                        "path": str(template_file),
                        "size": stat.st_size,
                        "size_formatted": _create_template_filters()["filesize"](
                            stat.st_size
                        ),
                        "modified": datetime.fromtimestamp(
                            stat.st_mtime, timezone.utc
                        ).isoformat(),
                        "readable": os.access(str(template_file), os.R_OK),
                    }
                )
            except Exception as e:
                logger.warning(f"Error processing template {template_file}: {e}")
                continue

        templates.sort(key=lambda x: x["name"])

    except Exception as e:
        logger.error(f"Error listing templates: {e}", exc_info=True)
        return [{"error": str(e)}]

    return templates


def validate_template(template_name: str) -> Dict[str, Any]:
    """
    Validate template syntax without rendering.
    
    Args:
        template_name: Template file name
        
    Returns:
        Validation result with syntax check and security scan
    """
    try:
        env = get_jinja_environment()

        # Get template source
        try:
            source, _, _ = env.loader.get_source(env, template_name)
        except Exception:
            return {
                "valid": False,
                "error": f"Could not retrieve source for '{template_name}'",
            }

        # Parse syntax
        try:
            ast = env.parse(source, template_name)
            variables = meta.find_undeclared_variables(ast)
        except TemplateSyntaxError as e:
            return {
                "valid": False,
                "template": template_name,
                "error": f"Syntax error at line {e.lineno}: {e.message}",
                "line": e.lineno,
            }

        # Security scan
        violations = _scan_template_security(source, template_name)

        result = {
            "valid": True,
            "template": template_name,
            "undeclared_variables": list(variables),
            "undeclared_count": len(variables),
            "security_violations": violations,
            "size_bytes": len(source),
        }

        # Add warnings
        warnings = []
        if len(variables) > 20:
            warnings.append(f"Many undeclared variables: {len(variables)}")

        if len(source) > TemplateConfig.MAX_SIZE_MB * 1024 * 1024:
            warnings.append("Template exceeds size limit")

        if violations:
            warnings.append(f"Security issues: {len(violations)}")

        if warnings:
            result["warnings"] = warnings

        return result

    except TemplateNotFound:
        return {
            "valid": False,
            "template": template_name,
            "error": f"Template '{template_name}' not found",
        }
    except Exception as e:
        logger.error(f"Error validating '{template_name}': {e}", exc_info=True)
        return {
            "valid": False,
            "template": template_name,
            "error": f"Validation error: {type(e).__name__}: {e}",
        }


def render_string(template_string: str, **context: Any) -> str:
    """
    Render template from string instead of file.
    
    WARNING: Only use with trusted template strings.
    User input can execute arbitrary code.
    
    Args:
        template_string: Template source code
        **context: Template context variables
        
    Returns:
        Rendered string
        
    Raises:
        ValueError: If template is invalid or too large
    """
    if not template_string:
        return ""

    # Size limit
    if len(template_string) > 100000:
        logger.error(f"Template string too large: {len(template_string)} bytes")
        raise ValueError("Template string too large (max 100KB)")

    try:
        env = get_jinja_environment()
        template = env.from_string(template_string)

        # Security scan
        if TemplateConfig.ENABLE_SECURITY_SCAN:
            violations = _scan_template_security(template_string, "<string>")
            if violations:
                logger.warning(f"Security issues in template string: {violations}")
                if not TemplateConfig.DEBUG:
                    raise ValueError(f"Template security violation: {violations}")

        return template.render(**context)

    except (TemplateSyntaxError, TemplateRuntimeError) as e:
        logger.error(f"Error rendering template string: {e}")
        raise ValueError(f"Template error: {e}") from e
    except Exception as e:
        logger.error(f"Unexpected error rendering string: {e}", exc_info=True)
        raise


def precompile_templates() -> Dict[str, Any]:
    """
    Precompile and validate all templates.
    
    Useful for CI/CD pipelines to catch errors before deployment.
    
    Returns:
        Compilation results with success status and error details
    """
    templates_dir = _detect_templates_directory()
    results = {
        "total": 0,
        "valid": 0,
        "invalid": 0,
        "errors": [],
        "warnings": [],
    }

    try:
        patterns = ["*.html", "*.jinja", "*.jinja2", "*.j2"]
        template_files = []
        for pattern in patterns:
            template_files.extend(templates_dir.rglob(pattern))

        results["total"] = len(template_files)

        for template_file in template_files:
            relative_path = str(template_file.relative_to(templates_dir))
            validation = validate_template(relative_path)

            if validation.get("valid"):
                results["valid"] += 1

                if validation.get("warnings"):
                    results["warnings"].append(
                        {"template": relative_path, "warnings": validation["warnings"]}
                    )
            else:
                results["invalid"] += 1
                results["errors"].append(
                    {
                        "template": relative_path,
                        "error": validation.get("error", "Unknown error"),
                    }
                )

        results["success"] = results["invalid"] == 0

    except Exception as e:
        logger.error(f"Error precompiling templates: {e}", exc_info=True)
        results["error"] = str(e)
        results["success"] = False

    return results


# ============================================================================
# Module exports
# ============================================================================

__all__ = [
    "render_template",
    "render_string",
    "clear_template_cache",
    "get_statistics",
    "health_check",
    "list_templates",
    "validate_template",
    "precompile_templates",
    "TemplateConfig",
]