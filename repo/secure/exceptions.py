"""
Security Framework - Exception Hierarchy

All security exceptions inherit from SecurityException.
Each exception type is designed for specific failure scenarios.
"""


class SecurityException(Exception):
    """
    Base exception for all security failures.
    
    Attributes:
        message: Human-readable error description
        recoverable: Can the system continue with degraded security?
        metadata: Additional context about the failure
    """
    
    def __init__(
        self,
        message: str,
        recoverable: bool = False,
        **metadata
    ):
        super().__init__(message)
        self.message = message
        self.recoverable = recoverable
        self.metadata = metadata
    
    def __str__(self):
        return self.message
    
    def to_dict(self):
        """Convert exception to dict for serialization."""
        return {
            "type": self.__class__.__name__,
            "message": self.message,
            "recoverable": self.recoverable,
            "metadata": self.metadata
        }


class AuthenticationError(SecurityException):
    """User authentication failed."""
    
    def __init__(self, message: str = "Authentication failed", **metadata):
        super().__init__(message, recoverable=False, **metadata)


class AuthorizationError(SecurityException):
    """User lacks required permissions."""
    
    def __init__(self, message: str = "Authorization failed", **metadata):
        super().__init__(message, recoverable=False, **metadata)


class RateLimitError(SecurityException):
    """Rate limit exceeded."""
    
    def __init__(
        self,
        message: str = "Rate limit exceeded",
        retry_after: int = 60,
        **metadata
    ):
        super().__init__(message, recoverable=True, retry_after=retry_after, **metadata)
        self.retry_after = retry_after


class AuditError(SecurityException):
    """Audit logging failed."""
    
    def __init__(self, message: str = "Audit logging failed", **metadata):
        # Audit failures are often recoverable
        super().__init__(message, recoverable=True, **metadata)


class FraudError(SecurityException):
    """Fraud detection triggered."""
    
    def __init__(
        self,
        message: str = "Suspicious activity detected",
        fraud_score: int = 0,
        **metadata
    ):
        super().__init__(message, recoverable=False, fraud_score=fraud_score, **metadata)
        self.fraud_score = fraud_score


class CircuitOpenError(SecurityException):
    """Circuit breaker is open."""
    
    def __init__(
        self,
        message: str = "Circuit breaker open",
        retry_after: int = 30,
        **metadata
    ):
        super().__init__(message, recoverable=True, retry_after=retry_after, **metadata)
        self.retry_after = retry_after


class PolicyNotFoundError(SecurityException):
    """Policy not registered in registry."""
    
    def __init__(self, policy_name: str, **metadata):
        message = f"Policy '{policy_name}' not found in registry"
        super().__init__(message, recoverable=False, policy_name=policy_name, **metadata)
        self.policy_name = policy_name


class StepConfigurationError(SecurityException):
    """Security step is misconfigured."""
    
    def __init__(self, step_name: str, reason: str, **metadata):
        message = f"Step '{step_name}' configuration error: {reason}"
        super().__init__(message, recoverable=False, step_name=step_name, reason=reason, **metadata)
        self.step_name = step_name
        self.reason = reason


class PolicyValidationError(SecurityException):
    """Policy failed validation checks."""
    
    def __init__(self, policy_name: str, errors: list, **metadata):
        message = f"Policy '{policy_name}' validation failed: {'; '.join(errors)}"
        super().__init__(message, recoverable=False, policy_name=policy_name, errors=errors, **metadata)
        self.policy_name = policy_name
        self.errors = errors


class AdapterError(SecurityException):
    """External adapter (Redis, DB, etc.) failed."""
    
    def __init__(
        self,
        adapter_name: str,
        message: str = "Adapter operation failed",
        recoverable: bool = True,
        **metadata
    ):
        full_message = f"{adapter_name}: {message}"
        super().__init__(full_message, recoverable=recoverable, adapter_name=adapter_name, **metadata)
        self.adapter_name = adapter_name


class ExecutionTimeoutError(SecurityException):
    """Security step execution exceeded time limit."""
    
    def __init__(
        self,
        step_name: str,
        timeout_seconds: float,
        **metadata
    ):
        message = f"Step '{step_name}' exceeded timeout of {timeout_seconds}s"
        super().__init__(message, recoverable=True, step_name=step_name, timeout_seconds=timeout_seconds, **metadata)
        self.step_name = step_name
        self.timeout_seconds = timeout_seconds


class StartupValidationError(SecurityException):
    """System failed startup validation checks."""
    
    def __init__(self, errors: list, **metadata):
        message = f"Startup validation failed: {'; '.join(errors)}"
        super().__init__(message, recoverable=False, errors=errors, **metadata)
        self.errors = errors
