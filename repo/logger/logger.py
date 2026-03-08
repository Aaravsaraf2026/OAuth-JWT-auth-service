"""
Simple Global Logger - Call Anywhere, No Setup!
================================================

Just import and use:
    from logger import bug, info, warn, error, success

Usage:
    bug("Testing feature X")
    info("User logged in", user_id=123)
    warn("Low memory detected")
    error("Database connection failed", exc_info=True)
    success("Payment processed successfully")

Features:
- ✅ Automatic file/line detection
- ✅ Color-coded console output
- ✅ JSON structured logging
- ✅ Production-ready
- ✅ No configuration needed
- ✅ Works in any file

Author: Production Logger Team
Version: 1.0.0
"""

import logging
import sys
import json
import inspect
import os
from datetime import datetime
from typing import Any, Dict, Optional
from pathlib import Path

try:
    from .context import get_request_id
except ImportError:
    try:
        from context import get_request_id
    except ImportError:
        def get_request_id():
            return None


# ============================================================================
# COLOR CODES (for terminal output)
# ============================================================================

class Colors:
    """ANSI color codes for terminal output."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    
    # Regular colors
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    
    # Bright colors
    BRIGHT_BLACK = "\033[90m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"
    
    # Background colors
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"


# ============================================================================
# CUSTOM FORMATTER
# ============================================================================

class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors and emojis."""
    
    LEVEL_COLORS = {
        'DEBUG': Colors.BRIGHT_BLACK,
        'INFO': Colors.BLUE,
        'WARNING': Colors.YELLOW,
        'ERROR': Colors.RED,
        'CRITICAL': Colors.BG_RED + Colors.WHITE,
        'SUCCESS': Colors.GREEN,
    }
    
    LEVEL_EMOJIS = {
        'DEBUG': '🐛',
        'INFO': 'ℹ️ ',
        'WARNING': '⚠️ ',
        'ERROR': '❌',
        'CRITICAL': '🔥',
        'SUCCESS': '✅',
    }
    
    def format(self, record):
        # Add color
        level_color = self.LEVEL_COLORS.get(record.levelname, Colors.WHITE)
        emoji = self.LEVEL_EMOJIS.get(record.levelname, '  ')
        
        # Format timestamp
        timestamp = datetime.fromtimestamp(record.created).strftime('%H:%M:%S.%f')[:-3]
        
        # Get caller info
        filename = Path(record.pathname).name
        location = f"{filename}:{record.lineno}"
        
        # Get request_id if present
        request_id = getattr(record, "request_id", None)

        # Build message
        parts = [
            f"{Colors.BRIGHT_BLACK}{timestamp}{Colors.RESET}",
            f"{emoji}",
            f"{level_color}{record.levelname:8s}{Colors.RESET}",
            f"{Colors.CYAN}{location:20s}{Colors.RESET}",
            f"{record.getMessage()}"
        ]

        if request_id:
            parts.insert(1, f"{Colors.BRIGHT_MAGENTA}[{request_id[:8]}]{Colors.RESET}")
        
        # Add extra fields if present
        if hasattr(record, 'extra_data') and record.extra_data:
            extra_str = json.dumps(record.extra_data, indent=2)
            parts.append(f"\n{Colors.BRIGHT_BLACK}{extra_str}{Colors.RESET}")
        
        return " │ ".join(parts)


class JSONFormatter(logging.Formatter):
    """JSON formatter for production logs."""
    
    def format(self, record):
        log_data = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'message': record.getMessage(),
            'file': Path(record.pathname).name,
            'line': record.lineno,
            'function': record.funcName,
        }
        
        # Add request_id if present
        if hasattr(record, 'request_id'):
            log_data['request_id'] = record.request_id

        # Add extra fields
        if hasattr(record, 'extra_data') and record.extra_data:
            log_data['data'] = record.extra_data
        
        # Add exception info if present
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)
        
        return json.dumps(log_data)


# ============================================================================
# LOGGER SETUP
# ============================================================================

def setup_logger():
    """Setup the global logger."""
    # Create logger
    logger = logging.getLogger('app')
    logger.setLevel(logging.DEBUG)
    
    # Remove existing handlers
    logger.handlers = []
    
    # Determine environment
    env = os.getenv('ENVIRONMENT', 'development').lower()
    
    # Console handler (always present)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG)
    
    if env == 'production':
        # Production: JSON format
        console_handler.setFormatter(JSONFormatter())
    else:
        # Development: Colored format
        console_handler.setFormatter(ColoredFormatter())
    
    logger.addHandler(console_handler)
    
    # File handler (optional)
    log_file = os.getenv('LOG_FILE')
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(JSONFormatter())
        logger.addHandler(file_handler)
    
    return logger


# Global logger instance
_logger = setup_logger()


# Add custom SUCCESS level
SUCCESS_LEVEL = 25  # Between INFO (20) and WARNING (30)
logging.addLevelName(SUCCESS_LEVEL, 'SUCCESS')


# ============================================================================
# SIMPLE API FUNCTIONS
# ============================================================================

def _log_with_caller(level: int, message: str, **kwargs):
    """
    Internal function to log with automatic caller detection.
    
    Args:
        level: Logging level
        message: Log message
        **kwargs: Additional data to log
    """
    # Get caller information (2 frames up: this function -> wrapper -> actual caller)
    frame = inspect.currentframe()
    try:
        caller_frame = frame.f_back.f_back
        caller_info = inspect.getframeinfo(caller_frame)
        
        # Create log record
        record = _logger.makeRecord(
            _logger.name,
            level,
            caller_info.filename,
            caller_info.lineno,
            message,
            (),
            None,
            caller_info.function
        )
        
        # Add extra data
        if kwargs:
            record.extra_data = kwargs
        else:
            record.extra_data = {}

        # Attach request_id if one is active
        request_id = get_request_id()
        if request_id:
            record.request_id = request_id

        _logger.handle(record)
        
    finally:
        del frame


def bug(message: str, **kwargs):
    """
    Debug logging (development only).
    
    Usage:
        bug("User data", user_id=123, email="user@example.com")
        bug("Processing request", request_id=req.id)
    """
    _log_with_caller(logging.DEBUG, message, **kwargs)


def info(message: str, **kwargs):
    """
    Informational logging.
    
    Usage:
        info("Server started", port=8000)
        info("User logged in", user_id=123)
    """
    _log_with_caller(logging.INFO, message, **kwargs)


def warn(message: str, **kwargs):
    """
    Warning logging.
    
    Usage:
        warn("High CPU usage", cpu_percent=95)
        warn("Token expiring soon", expires_in=120)
    """
    _log_with_caller(logging.WARNING, message, **kwargs)


def error(message: str, exc_info: bool = False, **kwargs):
    """
    Error logging.
    
    Usage:
        error("Database connection failed", host="localhost")
        error("Exception caught", exc_info=True)  # Includes stack trace
    """
    # Add exception info to the record
    if exc_info:
        record = _logger.makeRecord(
            _logger.name,
            logging.ERROR,
            "",
            0,
            message,
            (),
            sys.exc_info() if exc_info else None
        )
        record.extra_data = kwargs
        _logger.handle(record)
    else:
        _log_with_caller(logging.ERROR, message, **kwargs)


def critical(message: str, exc_info: bool = False, **kwargs):
    """
    Critical error logging.
    
    Usage:
        critical("System out of memory")
        critical("Fatal error", exc_info=True)
    """
    if exc_info:
        record = _logger.makeRecord(
            _logger.name,
            logging.CRITICAL,
            "",
            0,
            message,
            (),
            sys.exc_info() if exc_info else None
        )
        record.extra_data = kwargs
        _logger.handle(record)
    else:
        _log_with_caller(logging.CRITICAL, message, **kwargs)


def success(message: str, **kwargs):
    """
    Success logging (custom level).
    
    Usage:
        success("Payment processed", amount=100, order_id="ORD123")
        success("User registered", user_id=456)
    """
    _log_with_caller(SUCCESS_LEVEL, message, **kwargs)


# ============================================================================
# CONTEXT MANAGERS
# ============================================================================

class log_block:
    """
    Context manager for logging code blocks.
    
    Usage:
        with log_block("Processing payment"):
            # Your code here
            process_payment()
        # Automatically logs start/end with timing
    """
    
    def __init__(self, name: str, level: str = 'info'):
        self.name = name
        self.level = level
        self.start_time = None
    
    def __enter__(self):
        self.start_time = datetime.now()
        info(f"⏳ Started: {self.name}")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = (datetime.now() - self.start_time).total_seconds()
        
        if exc_type is None:
            success(f"✅ Completed: {self.name}", duration_seconds=duration)
        else:
            error(f"❌ Failed: {self.name}", duration_seconds=duration, exc_info=True)
        
        return False  # Don't suppress exceptions


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def set_level(level: str):
    """
    Change logging level dynamically.
    
    Usage:
        set_level('DEBUG')   # Show all logs
        set_level('INFO')    # Hide debug logs
        set_level('WARNING') # Show only warnings and errors
    """
    _logger.setLevel(getattr(logging, level.upper()))
    info(f"Log level changed to {level.upper()}")


def log_function_call(func):
    """
    Decorator to automatically log function calls.
    
    Usage:
        @log_function_call
        def my_function(x, y):
            return x + y
    """
    def wrapper(*args, **kwargs):
        func_name = func.__name__
        info(f"→ Calling {func_name}", args=args, kwargs=kwargs)
        
        try:
            result = func(*args, **kwargs)
            success(f"← {func_name} returned", result=result)
            return result
        except Exception as e:
            error(f"✗ {func_name} raised exception", exc_info=True)
            raise
    
    return wrapper


def log_request(request_type: str = "API"):
    """
    Decorator for logging HTTP requests.
    
    Usage:
        @log_request("API")
        async def my_endpoint(request: Request):
            return {"status": "ok"}
    """
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Try to extract request object
            request = None
            for arg in args:
                if hasattr(arg, 'method') and hasattr(arg, 'url'):
                    request = arg
                    break
            
            if request:
                info(
                    f"→ {request_type} Request",
                    method=request.method,
                    path=str(request.url.path),
                    client=request.client.host if request.client else None
                )
            
            try:
                result = await func(*args, **kwargs)
                success(f"← {request_type} Response", status="ok")
                return result
            except Exception as e:
                error(f"✗ {request_type} Error", exc_info=True)
                raise
        
        return wrapper
    return decorator


# ============================================================================
# PERFORMANCE LOGGING
# ============================================================================

class Timer:
    """
    Simple timer for performance logging.
    
    Usage:
        timer = Timer()
        # ... do something ...
        timer.log("Database query")  # Logs elapsed time
    """
    
    def __init__(self):
        self.start_time = datetime.now()
    
    def elapsed(self) -> float:
        """Get elapsed time in seconds."""
        return (datetime.now() - self.start_time).total_seconds()
    
    def log(self, message: str, **kwargs):
        """Log with elapsed time."""
        info(message, elapsed_seconds=self.elapsed(), **kwargs)
    
    def reset(self):
        """Reset the timer."""
        self.start_time = datetime.now()


# ============================================================================
# EXPORT
# ============================================================================

__all__ = [
    # Main functions
    'bug',
    'info', 
    'warn',
    'error',
    'critical',
    'success',
    
    # Utilities
    'set_level',
    'log_block',
    'log_function_call',
    'log_request',
    'Timer',
]


# ============================================================================
# USAGE EXAMPLES
# ============================================================================

if __name__ == "__main__":
    # Example usage
    print("\n" + "="*60)
    print("Logger Examples")
    print("="*60 + "\n")
    
    # Basic logging
    bug("This is a debug message", variable="test")
    info("Application started", version="1.0.0", port=8000)
    warn("Memory usage high", usage_percent=85)
    error("Connection failed", host="database.com", port=5432)
    critical("System crash imminent!")
    success("Payment processed successfully", amount=99.99, order_id="ORD-123")
    
    print("\n" + "-"*60 + "\n")
    
    # With context manager
    with log_block("Processing user data"):
        import time
        time.sleep(0.5)
        info("Step 1 complete")
        time.sleep(0.5)
        info("Step 2 complete")
    
    print("\n" + "-"*60 + "\n")
    
    # Timer example
    timer = Timer()
    import time
    time.sleep(0.3)
    timer.log("Operation completed")
    
    print("\n" + "="*60 + "\n")
