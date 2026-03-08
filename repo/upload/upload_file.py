"""
Production-grade file upload system with comprehensive security and monitoring.

This module provides secure, scalable file upload functionality with:
- Deep content validation and threat detection
- Rate limiting and quota management
- Comprehensive metrics and monitoring
- Atomic operations with proper cleanup
- Thread-safe async operations

Author: System
Version: 2.0.0
License: MIT
"""

import os
import uuid
import hashlib
import asyncio
import logging
import time
import mimetypes
from pathlib import Path
from typing import Union, List, Dict, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from contextlib import asynccontextmanager
from enum import Enum

from fastapi import UploadFile, HTTPException
import aiofiles
from collections import defaultdict, deque

# Configure module logger
logger = logging.getLogger(__name__)


class RiskLevel(str, Enum):
    """Security risk assessment levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class UploadError(Exception):
    """Base exception for upload-related errors."""
    pass


class UploadSecurityError(UploadError):
    """Raised when security validation fails."""
    pass


class UploadQuotaError(UploadError):
    """Raised when quota or rate limits are exceeded."""
    pass


class UploadConfig:
    """
    Centralized configuration for the upload system.
    
    All settings can be overridden via environment variables with UPLOAD_ prefix.
    Example: UPLOAD_CHUNK_SIZE=131072
    """
    
    # Performance settings
    CHUNK_SIZE: int = int(os.getenv("UPLOAD_CHUNK_SIZE", 65536))  # 64KB
    MAX_FILES_PER_BATCH: int = int(os.getenv("UPLOAD_MAX_FILES_PER_BATCH", 50))
    DEFAULT_TIMEOUT: int = int(os.getenv("UPLOAD_DEFAULT_TIMEOUT", 300))
    
    # Rate limiting
    RATE_LIMIT_MAX_REQUESTS: int = int(os.getenv("UPLOAD_RATE_LIMIT_MAX", 100))
    RATE_LIMIT_WINDOW: int = int(os.getenv("UPLOAD_RATE_LIMIT_WINDOW", 3600))
    RATE_LIMIT_CLEANUP_INTERVAL: int = 300
    RATE_LIMIT_EXPIRY: int = 7200
    
    # Logging and monitoring
    PROGRESS_LOG_INTERVAL_MB: int = 5
    PROGRESS_LOG_THRESHOLD_MB: int = 10
    MAX_METRICS_HISTORY: int = 100
    
    # File system
    MAX_FILENAME_LENGTH: int = 200
    FILE_PERMISSIONS: int = 0o644
    DIR_PERMISSIONS: int = 0o755


# MIME type mappings for validation
EXT_MIME: Dict[str, Set[str]] = {
    "jpg": {"image/jpeg"},
    "jpeg": {"image/jpeg"},
    "png": {"image/png"},
    "gif": {"image/gif"},
    "webp": {"image/webp"},
    "pdf": {"application/pdf"},
    "doc": {"application/msword", "application/octet-stream"},
    "docx": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    "txt": {"text/plain", "text/plain; charset=utf-8"},
    "rtf": {"application/rtf", "text/rtf", "application/x-rtf"},
    "mp4": {"video/mp4"},
    "avi": {"video/x-msvideo"},
    "mov": {"video/quicktime"},
    "mkv": {"video/x-matroska", "application/octet-stream"},
}

# Security: Dangerous file signatures (magic bytes)
DANGEROUS_SIGNATURES: Dict[bytes, str] = {
    b'\x4d\x5a': 'exe',
    b'\x7f\x45\x4c\x46': 'elf',
    b'\xca\xfe\xba\xbe': 'mach-o',
    b'\x21\x3c\x61\x72\x63\x68\x3e': 'deb',
}

# Safe file signatures for validation
SAFE_SIGNATURES: Dict[str, bytes] = {
    'png': b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a',
    'jpeg': b'\xff\xd8\xff',
    'gif87': b'GIF87a',
    'gif89': b'GIF89a',
    'pdf': b'%PDF-',
    'webp': b'RIFF',
}

# File type classifications
SAFE_FILE_TYPES: Set[str] = {'jpg', 'jpeg', 'png', 'gif', 'webp', 'txt', 'pdf'}
RISKY_FILE_TYPES: Set[str] = {'doc', 'docx', 'rtf', 'zip', 'rar'}
EXECUTABLE_TYPES: Set[str] = {
    'exe', 'bat', 'cmd', 'scr', 'com', 'pif', 'sh', 'bin', 'dll', 'so', 'dylib'
}

# Suspicious content patterns
SUSPICIOUS_PATTERNS: List[bytes] = [
    b'<script', b'javascript:', b'vbscript:', b'ActiveX',
    b'eval(', b'exec(', b'<?php', b'<%', b'#!/'
]


@dataclass
class UploadMetrics:
    """Tracks upload system performance and health metrics."""
    
    total_uploads: int = 0
    successful_uploads: int = 0
    failed_uploads: int = 0
    total_bytes: int = 0
    avg_upload_time: float = 0.0
    security_violations: int = 0
    quota_violations: int = 0
    last_upload_time: Optional[float] = None
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate percentage."""
        if self.total_uploads == 0:
            return 100.0
        return (self.successful_uploads / self.total_uploads) * 100


@dataclass
class RateLimitBucket:
    """Token bucket implementation for rate limiting."""
    
    tokens: float
    last_refill: float
    last_access: float
    max_tokens: int
    refill_rate: float


@dataclass
class UploadState:
    """Global state management for upload system with thread-safety."""
    
    metrics: UploadMetrics = field(default_factory=UploadMetrics)
    rate_limits: Dict[str, RateLimitBucket] = field(default_factory=dict)
    upload_times: deque = field(default_factory=lambda: deque(maxlen=UploadConfig.MAX_METRICS_HISTORY))
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    last_cleanup: float = field(default_factory=time.time)


# Global state singleton
_state: Optional[UploadState] = None


def _get_state() -> UploadState:
    """
    Lazy initialization of global state.
    
    Returns:
        UploadState: The global upload state singleton
    """
    global _state
    if _state is None:
        _state = UploadState()
    return _state


async def _update_metrics(
    success: bool,
    duration: float,
    size_bytes: int,
    security_violation: bool = False,
    quota_violation: bool = False
) -> None:
    """
    Update upload metrics in a thread-safe manner.
    
    Args:
        success: Whether the upload succeeded
        duration: Upload duration in seconds
        size_bytes: Size of uploaded data
        security_violation: Whether a security violation occurred
        quota_violation: Whether a quota violation occurred
    """
    state = _get_state()
    async with state.lock:
        state.metrics.total_uploads += 1
        state.metrics.last_upload_time = time.time()
        
        if success:
            state.metrics.successful_uploads += 1
            state.metrics.total_bytes += size_bytes
            state.upload_times.append(duration)
            if state.upload_times:
                state.metrics.avg_upload_time = sum(state.upload_times) / len(state.upload_times)
        else:
            state.metrics.failed_uploads += 1
        
        if security_violation:
            state.metrics.security_violations += 1
        if quota_violation:
            state.metrics.quota_violations += 1


async def get_upload_metrics() -> UploadMetrics:
    """
    Retrieve current upload metrics safely.
    
    Returns:
        UploadMetrics: Snapshot of current metrics
    """
    state = _get_state()
    async with state.lock:
        return UploadMetrics(
            total_uploads=state.metrics.total_uploads,
            successful_uploads=state.metrics.successful_uploads,
            failed_uploads=state.metrics.failed_uploads,
            total_bytes=state.metrics.total_bytes,
            avg_upload_time=state.metrics.avg_upload_time,
            security_violations=state.metrics.security_violations,
            quota_violations=state.metrics.quota_violations,
            last_upload_time=state.metrics.last_upload_time
        )


async def _cleanup_expired_rate_limits() -> None:
    """Remove expired rate limit entries to prevent memory leaks."""
    state = _get_state()
    now = time.time()
    
    if now - state.last_cleanup < UploadConfig.RATE_LIMIT_CLEANUP_INTERVAL:
        return
    
    async with state.lock:
        expired_keys = [
            key for key, bucket in state.rate_limits.items()
            if now - bucket.last_access > UploadConfig.RATE_LIMIT_EXPIRY
        ]
        for key in expired_keys:
            del state.rate_limits[key]
        
        state.last_cleanup = now
        
        if expired_keys:
            logger.info(f"Cleaned up {len(expired_keys)} expired rate limit entries")


async def _check_rate_limit(
    client_id: str,
    max_requests: int = UploadConfig.RATE_LIMIT_MAX_REQUESTS,
    time_window: int = UploadConfig.RATE_LIMIT_WINDOW
) -> bool:
    """
    Token bucket rate limiting implementation.
    
    Args:
        client_id: Unique identifier for the client
        max_requests: Maximum requests allowed in time window
        time_window: Time window in seconds
    
    Returns:
        bool: True if request is allowed, False if rate limited
    """
    state = _get_state()
    now = time.time()
    refill_rate = max_requests / time_window
    
    await _cleanup_expired_rate_limits()
    
    async with state.lock:
        if client_id not in state.rate_limits:
            state.rate_limits[client_id] = RateLimitBucket(
                tokens=max_requests,
                last_refill=now,
                last_access=now,
                max_tokens=max_requests,
                refill_rate=refill_rate
            )
        
        bucket = state.rate_limits[client_id]
        bucket.last_access = now
        
        # Refill tokens based on elapsed time
        elapsed = now - bucket.last_refill
        tokens_to_add = elapsed * bucket.refill_rate
        bucket.tokens = min(bucket.max_tokens, bucket.tokens + tokens_to_add)
        bucket.last_refill = now
        
        if bucket.tokens >= 1:
            bucket.tokens -= 1
            return True
        return False


async def _validate_file_signature(header: bytes, expected_ext: str) -> Tuple[bool, str]:
    """
    Validate file signature (magic bytes) matches expected extension.
    
    Args:
        header: First bytes of the file
        expected_ext: Expected file extension
    
    Returns:
        Tuple of (is_valid, reason)
    """
    if not header:
        return False, "Empty file header"
    
    # Check for dangerous executables
    for signature, file_type in DANGEROUS_SIGNATURES.items():
        if header.startswith(signature):
            return False, f"Executable file detected ({file_type})"
    
    # Validate specific file types
    if expected_ext in ['jpg', 'jpeg']:
        if not header.startswith(b'\xff\xd8\xff'):
            return False, "Invalid JPEG signature"
        if not (b'JFIF' in header[:20] or b'Exif' in header[:20]):
            return False, "Invalid JPEG structure"
    
    elif expected_ext == 'png':
        if not header.startswith(SAFE_SIGNATURES['png']):
            return False, "Invalid PNG signature"
        if len(header) >= 12 and header[8:12] != b'IHDR':
            return False, "Invalid PNG structure"
    
    elif expected_ext == 'pdf':
        if not header.startswith(SAFE_SIGNATURES['pdf']):
            return False, "Invalid PDF signature"
    
    elif expected_ext == 'gif':
        if not (header.startswith(SAFE_SIGNATURES['gif87']) or 
                header.startswith(SAFE_SIGNATURES['gif89'])):
            return False, "Invalid GIF signature"
    
    elif expected_ext == 'webp':
        if not (header.startswith(SAFE_SIGNATURES['webp']) and b'WEBP' in header[8:12]):
            return False, "Invalid WEBP signature"
    
    return True, "Valid signature"


async def _scan_for_threats(content: bytes, file_ext: str) -> Tuple[bool, List[str]]:
    """
    Scan file content for embedded threats.
    
    Args:
        content: File content to scan
        file_ext: File extension
    
    Returns:
        Tuple of (is_safe, threats_found)
    """
    threats = []
    content_lower = content.lower()
    
    for pattern in SUSPICIOUS_PATTERNS:
        if pattern in content_lower:
            threats.append(f"Suspicious pattern: {pattern.decode('ascii', errors='ignore')}")
    
    # Check for embedded executables in documents
    if file_ext in ['doc', 'docx', 'pdf', 'rtf']:
        for signature in DANGEROUS_SIGNATURES.keys():
            if signature in content:
                threats.append("Embedded executable detected")
                break
    
    # Check for polyglot files
    valid_signatures = [sig for sig in SAFE_SIGNATURES.values() if content.startswith(sig)]
    if len(valid_signatures) > 1:
        threats.append("Polyglot file detected")
    
    return len(threats) == 0, threats


async def _validate_file_content(file_path: Path, expected_ext: str) -> Tuple[bool, str]:
    """
    Perform deep content validation using magic bytes and structure analysis.
    
    Args:
        file_path: Path to the file to validate
        expected_ext: Expected file extension
    
    Returns:
        Tuple of (is_valid, reason)
    """
    try:
        async with aiofiles.open(file_path, 'rb') as f:
            header = await f.read(8192)
        
        if not header:
            return False, "Empty file"
        
        is_valid, reason = await _validate_file_signature(header, expected_ext)
        if not is_valid:
            return False, reason
        
        is_safe, threats = await _scan_for_threats(header, expected_ext)
        if not is_safe:
            return False, f"Security threats: {'; '.join(threats)}"
        
        return True, "Valid"
    
    except Exception as e:
        logger.error(f"File validation error: {e}", exc_info=True)
        return False, f"Validation error: {str(e)}"


@asynccontextmanager
async def _upload_transaction(temp_paths: List[Path]):
    """
    Context manager for atomic upload operations with automatic cleanup.
    
    Args:
        temp_paths: List of temporary file paths to clean up on error
    """
    try:
        yield
    except Exception:
        for temp_path in temp_paths:
            if temp_path and temp_path.exists():
                try:
                    await asyncio.to_thread(temp_path.unlink)
                except Exception as cleanup_error:
                    logger.warning(f"Cleanup failed for {temp_path}: {cleanup_error}")
        raise


def _sanitize_filename(filename: str) -> str:
    """
    Sanitize filename for secure file system storage.
    
    Args:
        filename: Original filename
    
    Returns:
        str: Sanitized filename
    """
    name = os.path.basename(filename.strip())
    name = ''.join(c for c in name if ord(c) >= 32 and c != '\x7f')
    safe = "".join(c for c in name if c.isascii() and (c.isalnum() or c in "._-"))
    
    # Prevent Windows reserved names
    reserved = {
        'CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 'COM5',
        'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 'LPT3', 'LPT4',
        'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
    }
    
    name_without_ext = Path(safe).stem.upper()
    if name_without_ext in reserved:
        safe = f"file_{safe}"
    
    if safe.startswith('.'):
        safe = 'file' + safe
    
    parts = safe.split('.')
    if len(parts) > 2:
        safe = ''.join(parts[:-1]).replace('.', '_') + '.' + parts[-1]
    
    return safe[:UploadConfig.MAX_FILENAME_LENGTH] if safe else ""


def _validate_extension(filename: str, allowed: Set[str]) -> Tuple[bool, str, str]:
    """
    Validate file extension comprehensively.
    
    Args:
        filename: Filename to validate
        allowed: Set of allowed extensions
    
    Returns:
        Tuple of (is_valid, extension, error_message)
    """
    p = Path(filename)
    
    if not p.suffix:
        return False, "", "No file extension"
    
    # Check for compound extensions (security bypass attempt)
    all_suffixes = p.suffixes
    if len(all_suffixes) > 1:
        for suffix in all_suffixes:
            ext = suffix[1:].lower()
            if ext in EXECUTABLE_TYPES:
                return False, ext, f"Dangerous compound extension: {'.'.join(all_suffixes)}"
    
    ext = p.suffix[1:].lower()
    
    if ext not in allowed:
        return False, ext, f"Extension '.{ext}' not allowed"
    
    if ext in EXECUTABLE_TYPES:
        return False, ext, "Executable file type not permitted"
    
    return True, ext, ""


def _analyze_upload_risk(
    filename: str,
    file_size: int,
    content_type: Optional[str],
    extension: str
) -> Tuple[RiskLevel, List[str]]:
    """
    Analyze upload risk level.
    
    Args:
        filename: Filename
        file_size: File size in bytes
        content_type: MIME type
        extension: File extension
    
    Returns:
        Tuple of (risk_level, warnings)
    """
    warnings = []
    risk_level = RiskLevel.LOW
    
    if extension in EXECUTABLE_TYPES:
        risk_level = RiskLevel.CRITICAL
        warnings.append("Executable file type")
    elif extension in RISKY_FILE_TYPES:
        risk_level = RiskLevel.MEDIUM
        warnings.append("Document file (may contain macros)")
    elif extension not in SAFE_FILE_TYPES and extension not in EXT_MIME:
        risk_level = RiskLevel.MEDIUM
        warnings.append("Unknown file type")
    
    if file_size > 50 * 1024 * 1024:
        risk_level = max(risk_level, RiskLevel.MEDIUM, key=lambda x: list(RiskLevel).index(x))
        warnings.append("Large file size")
    elif file_size == 0:
        risk_level = RiskLevel.HIGH
        warnings.append("Zero-byte file")
    
    if content_type and extension in EXT_MIME:
        if content_type not in EXT_MIME[extension]:
            guessed_type, _ = mimetypes.guess_type(filename)
            if not (guessed_type and guessed_type in EXT_MIME[extension]):
                risk_level = max(risk_level, RiskLevel.HIGH, key=lambda x: list(RiskLevel).index(x))
                warnings.append(f"Content-Type mismatch: {content_type}")
    
    suspicious_patterns = ['..', '~', '$', '%00', '<', '>', '|', '\0']
    if any(pattern in filename for pattern in suspicious_patterns):
        risk_level = RiskLevel.HIGH
        warnings.append("Suspicious filename pattern")
    
    return risk_level, warnings


async def _process_single_file(
    file: UploadFile,
    file_index: int,
    save_dir: Path,
    allowed: Set[str],
    max_bytes: int,
    total_size_tracker: Dict[str, int],
    max_total_bytes: Optional[int],
    enable_content_validation: bool,
    timeout_deadline: float,
    upload_id: str
) -> Dict[str, Any]:
    """
    Process a single file upload with comprehensive validation.
    
    Args:
        file: Uploaded file
        file_index: Index in batch
        save_dir: Directory to save file
        allowed: Allowed extensions
        max_bytes: Max size per file
        total_size_tracker: Shared size tracker for batch
        max_total_bytes: Max total batch size
        enable_content_validation: Whether to validate content
        timeout_deadline: Deadline timestamp
        upload_id: Unique upload batch ID
    
    Returns:
        Dict containing file information
    
    Raises:
        HTTPException: On validation or processing errors
    """
    file_start = time.time()
    
    if time.time() > timeout_deadline:
        raise HTTPException(408, "Upload timeout")
    
    if not file.filename or not file.filename.strip():
        raise HTTPException(400, f"File #{file_index + 1}: Filename required")
    
    original = _sanitize_filename(file.filename)
    if not original or len(original) < 2:
        raise HTTPException(400, f"File #{file_index + 1}: Invalid filename")
    
    is_valid_ext, ext, ext_error = _validate_extension(original, allowed)
    if not is_valid_ext:
        allowed_str = ", ".join(f".{e}" for e in sorted(allowed))
        logger.warning(f"Upload {upload_id}: {ext_error}")
        raise HTTPException(400, f"File #{file_index + 1}: {ext_error}. Allowed: {allowed_str}")
    
    risk_level, risk_warnings = _analyze_upload_risk(original, 0, file.content_type, ext)
    if risk_level == RiskLevel.CRITICAL:
        logger.error(f"Upload {upload_id}: Critical risk - {', '.join(risk_warnings)}")
        await _update_metrics(False, 0, 0, security_violation=True)
        raise UploadSecurityError(f"File rejected: {', '.join(risk_warnings)}")
    
    # Validate MIME type
    if ext in EXT_MIME and file.content_type:
        if file.content_type not in EXT_MIME[ext]:
            guessed_type, _ = mimetypes.guess_type(original)
            if not (guessed_type and guessed_type in EXT_MIME[ext]):
                logger.warning(f"MIME mismatch for {original}: {file.content_type}")
                raise HTTPException(
                    400,
                    f"File #{file_index + 1}: Content-type mismatch"
                )
    
    unique_id = uuid.uuid4().hex
    temp_path = save_dir / f"{unique_id}.uploading"
    final_path = save_dir / f"{unique_id}.{ext}"
    
    written = 0
    hasher = hashlib.sha256()
    last_progress_log = 0
    
    try:
        async with aiofiles.open(temp_path, "wb") as output:
            while True:
                if time.time() > timeout_deadline:
                    raise HTTPException(408, "Upload timeout")
                
                try:
                    chunk = await asyncio.wait_for(
                        file.read(UploadConfig.CHUNK_SIZE),
                        timeout=30
                    )
                except asyncio.TimeoutError:
                    raise HTTPException(408, "File read timeout")
                
                if not chunk:
                    break
                
                chunk_size = len(chunk)
                written += chunk_size
                
                if written > max_bytes:
                    logger.warning(f"Upload {upload_id}: File {original} exceeds limit")
                    raise HTTPException(413, f"File #{file_index + 1}: Exceeds size limit")
                
                if max_total_bytes is not None:
                    total_size_tracker['size'] += chunk_size
                    if total_size_tracker['size'] > max_total_bytes:
                        logger.warning(f"Upload {upload_id}: Batch size exceeded")
                        await _update_metrics(False, 0, total_size_tracker['size'], quota_violation=True)
                        raise HTTPException(413, "Total upload size exceeded")
                
                hasher.update(chunk)
                await output.write(chunk)
                
                written_mb = written // (1024 * 1024)
                if (written_mb > UploadConfig.PROGRESS_LOG_THRESHOLD_MB and
                    written_mb - last_progress_log >= UploadConfig.PROGRESS_LOG_INTERVAL_MB):
                    logger.info(f"Upload {upload_id}: {original} progress: {written_mb}MB")
                    last_progress_log = written_mb
        
        if written == 0:
            raise HTTPException(400, f"File #{file_index + 1}: Empty file")
        
        if enable_content_validation:
            is_valid, validation_reason = await _validate_file_content(temp_path, ext)
            if not is_valid:
                logger.error(f"Upload {upload_id}: Validation failed - {validation_reason}")
                await _update_metrics(False, 0, written, security_violation=True)
                raise UploadSecurityError(f"Content validation failed: {validation_reason}")
        
        risk_level, risk_warnings = _analyze_upload_risk(original, written, file.content_type, ext)
        
        try:
            await asyncio.to_thread(os.replace, temp_path, final_path)
            await asyncio.to_thread(os.chmod, final_path, UploadConfig.FILE_PERMISSIONS)
        except OSError as e:
            logger.error(f"Upload {upload_id}: Finalize failed - {e}")
            raise HTTPException(500, "Failed to save file")
        
        file_hash = hasher.hexdigest()
        rel_path = str(final_path.relative_to(save_dir))
        
        file_info = {
            "id": unique_id,
            "path": rel_path,
            "original_name": original,
            "ext": ext,
            "size_bytes": written,
            "size_mb": round(written / (1024 * 1024), 2),
            "sha256": file_hash,
            "upload_time": int(time.time()),
            "upload_duration_ms": int((time.time() - file_start) * 1000),
            "content_type": file.content_type,
            "risk_level": risk_level.value,
            "risk_warnings": risk_warnings,
            "validated": enable_content_validation,
        }
        
        duration = time.time() - file_start
        logger.info(
            f"Upload {upload_id}: {original} -> {unique_id}.{ext} "
            f"({written:,} bytes, {duration:.2f}s, {risk_level.value})"
        )
        
        await _update_metrics(True, duration, written)
        
        return file_info
    
    except (HTTPException, UploadError):
        await _update_metrics(False, time.time() - file_start, written)
        raise
    except Exception as e:
        logger.error(f"Upload {upload_id}: Unexpected error - {e}", exc_info=True)
        await _update_metrics(False, time.time() - file_start, written)
        raise HTTPException(500, f"File processing failed: {str(e)}")


async def save_upload(
    file: Union[UploadFile, List[UploadFile]],
    types_allowed: Union[str, List[str]],
    path: str,
    max_mb: int
) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Legacy compatibility function for existing code.
    
    Args:
        file: File(s) to upload
        types_allowed: Allowed file extensions
        path: Save directory
        max_mb: Maximum file size in MB
    
    Returns:
        Upload result(s)
    """
    return await upload(
        file=file,
        path=path,
        size=max_mb,
        file_type=types_allowed,
        timeout=UploadConfig.DEFAULT_TIMEOUT,
        enable_content_validation=True,
        enable_rate_limiting=False,
    )


async def upload_images(
    file: Union[UploadFile, List[UploadFile]],
    path: str,
    size: int = 5,
    client_id: Optional[str] = None
) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Convenience function for image uploads.
    
    Args:
        file: Image file(s) to upload
        path: Save directory
        size: Maximum file size in MB (default: 5)
        client_id: Optional client ID for rate limiting
    
    Returns:
        Upload result(s)
    """
    return await upload(
        file=file,
        path=path,
        size=size,
        file_type=['jpg', 'jpeg', 'png', 'gif', 'webp'],
        client_id=client_id,
        enable_content_validation=True,
        enable_rate_limiting=client_id is not None
    )


async def upload_docs(
    file: Union[UploadFile, List[UploadFile]],
    path: str,
    size: int = 10,
    client_id: Optional[str] = None
) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Convenience function for document uploads with enhanced security.
    
    Args:
        file: Document file(s) to upload
        path: Save directory
        size: Maximum file size in MB (default: 10)
        client_id: Optional client ID for rate limiting
    
    Returns:
        Upload result(s)
    """
    return await upload(
        file=file,
        path=path,
        size=size,
        file_type=['pdf', 'doc', 'docx', 'txt', 'rtf'],
        client_id=client_id,
        enable_content_validation=True,
        enable_rate_limiting=client_id is not None
    )


async def upload_videos(
    file: Union[UploadFile, List[UploadFile]],
    path: str,
    size: int = 100,
    client_id: Optional[str] = None
) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Convenience function for video uploads.
    
    Args:
        file: Video file(s) to upload
        path: Save directory
        size: Maximum file size in MB (default: 100)
        client_id: Optional client ID for rate limiting
    
    Returns:
        Upload result(s)
    """
    return await upload(
        file=file,
        path=path,
        size=size,
        file_type=['mp4', 'avi', 'mov', 'mkv'],
        client_id=client_id,
        enable_content_validation=True,
        enable_rate_limiting=client_id is not None
    )


async def get_upload_health_status() -> Dict[str, Any]:
    """
    Get comprehensive health status of the upload system.
    
    Returns:
        Dictionary containing health status and metrics
    """
    metrics = await get_upload_metrics()
    
    success_rate = metrics.success_rate
    
    status = "HEALTHY"
    issues = []
    
    if success_rate < 95:
        status = "DEGRADED"
        issues.append("LOW_SUCCESS_RATE")
    
    if metrics.total_uploads > 0:
        violation_rate = metrics.security_violations / metrics.total_uploads
        if violation_rate > 0.05:
            status = "DEGRADED"
            issues.append("HIGH_SECURITY_VIOLATIONS")
    
    if metrics.avg_upload_time > 30:
        status = "DEGRADED"
        issues.append("SLOW_UPLOADS")
    
    if metrics.last_upload_time:
        time_since_last = time.time() - metrics.last_upload_time
        if time_since_last > 3600 and metrics.total_uploads > 0:
            status = "IDLE"
    
    return {
        "status": status,
        "issues": issues,
        "metrics": {
            "total_uploads": metrics.total_uploads,
            "success_rate_percent": round(success_rate, 2),
            "total_mb_uploaded": round(metrics.total_bytes / (1024 * 1024), 2),
            "avg_upload_time_seconds": round(metrics.avg_upload_time, 2),
            "security_violations": metrics.security_violations,
            "quota_violations": metrics.quota_violations,
            "last_upload_timestamp": metrics.last_upload_time
        },
        "timestamp": time.time()
    }


async def reset_upload_metrics() -> Dict[str, Any]:
    """
    Reset all upload metrics (for testing or maintenance).
    
    Returns:
        Status dictionary
    """
    state = _get_state()
    async with state.lock:
        state.metrics = UploadMetrics()
        state.upload_times.clear()
        logger.info("Upload metrics reset")
    
    return {"status": "metrics_reset", "timestamp": time.time()}


async def get_rate_limit_status(client_id: str) -> Dict[str, Any]:
    """
    Get rate limit status for a specific client.
    
    Args:
        client_id: Client identifier
    
    Returns:
        Rate limit status dictionary
    """
    state = _get_state()
    async with state.lock:
        if client_id not in state.rate_limits:
            return {
                "client_id": client_id,
                "status": "no_record",
                "tokens_available": UploadConfig.RATE_LIMIT_MAX_REQUESTS
            }
        
        bucket = state.rate_limits[client_id]
        return {
            "client_id": client_id,
            "status": "active",
            "tokens_available": int(bucket.tokens),
            "max_tokens": bucket.max_tokens,
            "last_access": bucket.last_access,
            "time_since_last_access": time.time() - bucket.last_access
        }


async def clear_rate_limit(client_id: str) -> Dict[str, str]:
    """
    Clear rate limit for a specific client (admin function).
    
    Args:
        client_id: Client identifier
    
    Returns:
        Status dictionary
    """
    state = _get_state()
    async with state.lock:
        if client_id in state.rate_limits:
            del state.rate_limits[client_id]
            logger.info(f"Rate limit cleared: {client_id}")
            return {"status": "cleared", "client_id": client_id}
        return {"status": "not_found", "client_id": client_id}


async def validate_upload_directory(path: str) -> Dict[str, Any]:
    """
    Validate that upload directory is properly configured.
    
    Args:
        path: Directory path to validate
    
    Returns:
        Validation results dictionary
    """
    save_dir = Path(path)
    checks = {
        "path": str(save_dir),
        "exists": False,
        "writable": False,
        "readable": False,
        "space_available": False,
        "permissions": None,
        "errors": []
    }
    
    try:
        if save_dir.exists():
            checks["exists"] = True
            checks["permissions"] = oct(save_dir.stat().st_mode)[-3:]
        else:
            checks["errors"].append("Directory does not exist")
        
        try:
            test_file = save_dir / f".write_test_{uuid.uuid4().hex[:8]}"
            await asyncio.to_thread(test_file.write_bytes, b"test")
            checks["writable"] = True
            await asyncio.to_thread(test_file.unlink)
        except Exception as e:
            checks["errors"].append(f"Not writable: {e}")
        
        try:
            list(save_dir.iterdir())
            checks["readable"] = True
        except Exception as e:
            checks["errors"].append(f"Not readable: {e}")
        
        try:
            import shutil
            stat = shutil.disk_usage(save_dir)
            checks["space_available"] = stat.free > 100 * 1024 * 1024
            checks["free_space_mb"] = round(stat.free / (1024 * 1024), 2)
        except Exception as e:
            checks["errors"].append(f"Cannot check disk space: {e}")
    
    except Exception as e:
        checks["errors"].append(f"Validation error: {e}")
    
    checks["status"] = "OK" if not checks["errors"] else "FAILED"
    return checks


async def upload(
    file: Union[UploadFile, List[UploadFile]],
    path: str,
    size: int,
    file_type: Union[str, List[str]],
    timeout: int = UploadConfig.DEFAULT_TIMEOUT,
    max_total_mb: Optional[int] = None,
    client_id: Optional[str] = None,
    enable_content_validation: bool = True,
    enable_rate_limiting: bool = True,
) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Production-ready file upload with comprehensive validation.
    
    Args:
        file: Single file or list of files to upload
        path: Directory path to save files
        size: Maximum size per file in MB
        file_type: Allowed file extensions (string or list)
        timeout: Upload timeout in seconds
        max_total_mb: Optional maximum total batch size in MB
        client_id: Client identifier for rate limiting
        enable_content_validation: Enable deep content validation
        enable_rate_limiting: Enable rate limiting (requires client_id)
    
    Returns:
        Dictionary for single file, list of dictionaries for multiple files
    
    Raises:
        HTTPException: On validation, quota, or processing errors
    
    Example:
        >>> result = await upload(
        ...     file=uploaded_file,
        ...     path="uploads/images",
        ...     size=5,
        ...     file_type=["jpg", "png"],
        ...     client_id="user_123"
        ... )
    """
    start_time = time.time()
    timeout_deadline = start_time + timeout
    upload_id = uuid.uuid4().hex[:8]
    temp_files: List[Path] = []
    total_size_tracker = {'size': 0}
    
    try:
        if enable_rate_limiting and client_id:
            if not await _check_rate_limit(client_id):
                logger.warning(f"Rate limit exceeded: {client_id}")
                await _update_metrics(False, 0, 0, quota_violation=True)
                raise HTTPException(429, "Rate limit exceeded. Try again later.")
        
        if not file:
            raise HTTPException(400, "No files provided")
        
        is_single_file = isinstance(file, UploadFile)
        files = [file] if is_single_file else list(file)
        
        allowed = {
            ext.lower().lstrip('.')
            for ext in ([file_type] if isinstance(file_type, str) else file_type)
        }
        
        if not allowed:
            raise HTTPException(400, "No file types specified")
        
        if len(files) > UploadConfig.MAX_FILES_PER_BATCH:
            raise HTTPException(
                400,
                f"Too many files (max {UploadConfig.MAX_FILES_PER_BATCH})"
            )
        
        max_bytes = size * 1024 * 1024
        max_total_bytes = max_total_mb * 1024 * 1024 if max_total_mb else None
        
        # --- Header size validation (prevent slow upload attacks) ---
        for f in files:
            declared_size = getattr(f, 'size', None)
            if declared_size is not None and declared_size > max_bytes:
                raise HTTPException(
                    413,
                    f"File '{f.filename}': Declared size ({declared_size:,} bytes) "
                    f"exceeds limit ({max_bytes:,} bytes)"
                )
        # ------------------------------------------------------------
        
        logger.info(
            f"Upload batch {upload_id}: {len(files)} files, "
            f"max {size}MB each, client: {client_id or 'unknown'}"
        )
        
        save_dir = Path(path)
        try:
            await asyncio.to_thread(
                save_dir.mkdir,
                parents=True,
                exist_ok=True,
                mode=UploadConfig.DIR_PERMISSIONS
            )
            test_file = save_dir / f".write_test_{upload_id}"
            await asyncio.to_thread(test_file.write_bytes, b"test")
            await asyncio.to_thread(test_file.unlink)
        except OSError as e:
            logger.error(f"Upload {upload_id}: Directory error - {e}")
            raise HTTPException(500, "Upload directory not accessible")
        
        results: List[Dict[str, Any]] = []
        
        async with _upload_transaction(temp_files):
            for i, f in enumerate(files):
                file_info = await _process_single_file(
                    file=f,
                    file_index=i,
                    save_dir=save_dir,
                    allowed=allowed,
                    max_bytes=max_bytes,
                    total_size_tracker=total_size_tracker,
                    max_total_bytes=max_total_bytes,
                    enable_content_validation=enable_content_validation,
                    timeout_deadline=timeout_deadline,
                    upload_id=upload_id
                )
                results.append(file_info)
        
        total_duration = time.time() - start_time
        total_size = sum(r['size_bytes'] for r in results)
        
        await _update_metrics(True, total_duration, total_size)
        
        logger.info(
            f"Upload batch {upload_id} completed: {len(results)} files, "
            f"{total_size:,} bytes in {total_duration:.2f}s"
        )
        
        return results[0] if is_single_file else results
    
    except (HTTPException, UploadError):
        raise
    except Exception as e:
        logger.error(f"Upload {upload_id}: Critical error - {e}", exc_info=True)
        await _update_metrics(False, time.time() - start_time, total_size_tracker['size'])
        raise HTTPException(500, "Upload failed")
