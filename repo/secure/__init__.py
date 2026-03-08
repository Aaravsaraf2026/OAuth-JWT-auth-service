"""
Security Framework - Production-Grade Security System

A complete, production-ready security framework implementing all 11 critical requirements.

REQUIREMENTS IMPLEMENTED:
✓ R1:  Mandatory Observability Guarantees
✓ R2:  Fail-Open Guardrails
✓ R3:  Policy Validation Engine
✓ R4:  Critical Step Protection
✓ R5:  Adapter Failure Isolation
✓ R6:  Deterministic Execution Ordering
✓ R7:  Startup Integrity Checks
✓ R8:  Audit Trail Requirements
✓ R9:  Policy Versioning
✓ R10: Concurrency Safety
✓ R11: Performance Safety Limits

Architecture:
    Request
       ↓
    Security Engine          (This module)
       ↓
    Policy Validation        (Compile-time checks)
       ↓
    Ordered Step Pipeline    (Deterministic execution)
       ↓
    Circuit Breakers         (Adapter protection)
       ↓
    Telemetry & Audit        (Observability)

Example Usage:
    from security_framework import (
        SecurityEngine,
        PolicyRegistry,
        Policy,
        StepConfig,
        StepPriority,
        RouteClassification,
        FailureMode,
        CircuitBreakerRegistry
    )
    
    # 1. Create registry
    registry = PolicyRegistry(strict_mode=True)
    
    # 2. Define policy with versioning
    my_policy = Policy(
        name="api_policy",
        version_id="1.0.0",
        route_classification=RouteClassification.AUTHENTICATED,
        requires_auth=True,
        failure_mode=FailureMode.FAIL_CLOSED,
        step_configs=(
            StepConfig("auth", StepPriority.CRITICAL, 0),
            StepConfig("rate_limit", StepPriority.REQUIRED, 1),
        )
    )
    
    # 3. Register policy
    registry.register(my_policy)
    
    # 4. Create engine
    engine = SecurityEngine(registry)
    
    # 5. CRITICAL: Run startup validation
    engine.startup_validation()  # Refuses to start if misconfigured
    
    # 6. Use in request handler
    event = engine.run(my_policy, request)
    if event.decision == DecisionType.DENY:
        raise HTTPException(403, "Access denied")
"""

__version__ = "2.0.0"  # Production-ready version

# ============================================================================
# CORE COMPONENTS
# ============================================================================

from .policy import (
    Policy,
    FailureMode,
    StepPriority,
    RouteClassification,
    StepConfig,
    PUBLIC_POLICY,
    AUTHENTICATED_POLICY,
    CRITICAL_POLICY,
    ADMIN_POLICY,
    OBSERVE_POLICY,
    DEFAULT_POLICY
)

from .registry import PolicyRegistry

from .engine import SecurityEngine, ExecutionLimits

from .telemetry import (
    TelemetryCollector,
    AuditLogger,
    SecurityEvent,
    DecisionType,
    FailureReason
)

from .circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerRegistry,
    CircuitConfig,
    CircuitState
)

# ============================================================================
# EXCEPTIONS
# ============================================================================

from .exceptions import (
    SecurityException,
    AuthenticationError,
    AuthorizationError,
    RateLimitError,
    AuditError,
    FraudError,
    CircuitOpenError,
    PolicyNotFoundError,
    StepConfigurationError,
    PolicyValidationError,
    AdapterError,
    ExecutionTimeoutError,
    StartupValidationError
)

# ============================================================================
# STEPS
# ============================================================================

from .steps.base import (
    SecurityStep,
    NoOpStep,
    SkipRemainingSteps
)

# ============================================================================
# PUBLIC API
# ============================================================================

__all__ = [
    # Version
    "__version__",
    
    # Core Components
    "SecurityEngine",
    "PolicyRegistry",
    "Policy",
    "ExecutionLimits",
    
    # Policy Configuration
    "FailureMode",
    "StepPriority",
    "RouteClassification",
    "StepConfig",
    
    # Predefined Policies
    "PUBLIC_POLICY",
    "AUTHENTICATED_POLICY",
    "CRITICAL_POLICY",
    "ADMIN_POLICY",
    "OBSERVE_POLICY",
    "DEFAULT_POLICY",
    
    # Telemetry & Observability
    "TelemetryCollector",
    "AuditLogger",
    "SecurityEvent",
    "DecisionType",
    "FailureReason",
    
    # Circuit Breakers
    "CircuitBreaker",
    "CircuitBreakerRegistry",
    "CircuitConfig",
    "CircuitState",
    
    # Exceptions
    "SecurityException",
    "AuthenticationError",
    "AuthorizationError",
    "RateLimitError",
    "AuditError",
    "FraudError",
    "CircuitOpenError",
    "PolicyNotFoundError",
    "StepConfigurationError",
    "PolicyValidationError",
    "AdapterError",
    "ExecutionTimeoutError",
    "StartupValidationError",
    
    # Steps
    "SecurityStep",
    "NoOpStep",
    "SkipRemainingSteps",
]


# ============================================================================
# QUICK START HELPER
# ============================================================================

def create_production_engine(
    policies: list[Policy] = None,
    strict_mode: bool = True
) -> SecurityEngine:
    """
    Quick-start helper for creating a production-ready engine.
    
    This helper:
    1. Creates registry with strict validation
    2. Registers provided policies (or defaults)
    3. Creates engine with full telemetry
    4. Runs startup validation
    5. Returns ready-to-use engine
    
    Args:
        policies: List of policies to register (uses defaults if None)
        strict_mode: Enforce strict validation (always True in production)
    
    Returns:
        Production-ready SecurityEngine
    
    Raises:
        StartupValidationError: If validation fails
    
    Example:
        engine = create_production_engine()
        # Engine is validated and ready to use
        event = engine.run(AUTHENTICATED_POLICY, request)
    """
    # Create registry
    registry = PolicyRegistry(strict_mode=strict_mode)
    
    # Register policies
    policies_to_register = policies or [
        PUBLIC_POLICY,
        AUTHENTICATED_POLICY,
        CRITICAL_POLICY,
        ADMIN_POLICY,
        OBSERVE_POLICY
    ]
    
    for policy in policies_to_register:
        registry.register(policy)
    
    # Create engine with full telemetry
    telemetry = TelemetryCollector(
        enable_logging=True,
        enable_metrics=True,
        enable_alerts=True
    )
    
    audit_logger = AuditLogger()
    circuit_registry = CircuitBreakerRegistry()
    
    engine = SecurityEngine(
        registry=registry,
        telemetry=telemetry,
        audit_logger=audit_logger,
        circuit_registry=circuit_registry,
        enforce_limits=True
    )
    
    # Run startup validation (CRITICAL)
    engine.startup_validation()
    
    return engine
