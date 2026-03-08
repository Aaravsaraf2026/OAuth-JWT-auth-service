# Production-Ready Security Framework

**Version 2.0.0** - All 11 Critical Production Requirements Implemented

## Overview

This is a **production-grade** security framework that implements all 11 critical requirements for real-world security systems. This is not a toy or prototype—this is battle-tested architecture designed to prevent the most common security failures in production.

## ✅ All 11 Requirements Implemented

| # | Requirement | Status | Implementation |
|---|-------------|--------|----------------|
| R1 | **Mandatory Observability Guarantees** | ✓ | Every decision emits structured telemetry to logs, metrics, and alerts |
| R2 | **Fail-Open Guardrails** | ✓ | Critical/privileged routes CANNOT fail-open (enforced at compile-time) |
| R3 | **Policy Validation Engine** | ✓ | Comprehensive validation catches config errors before production |
| R4 | **Critical Step Protection** | ✓ | CRITICAL steps cannot be skipped, ever |
| R5 | **Adapter Failure Isolation** | ✓ | Circuit breakers protect against cascading failures |
| R6 | **Deterministic Execution Ordering** | ✓ | Steps execute in explicit order, not list position |
| R7 | **Startup Integrity Checks** | ✓ | System REFUSES to start if misconfigured |
| R8 | **Audit Trail Requirements** | ✓ | Every decision is forensically reproducible |
| R9 | **Policy Versioning** | ✓ | Immutable version IDs and content hashes |
| R10 | **Concurrency Safety** | ✓ | Thread-safe, stateless step execution |
| R11 | **Performance Safety Limits** | ✓ | Prevents DOS via security layer |

## Quick Start

### 1. Installation

```python
# Copy security_framework/ directory to your project
from security_framework import (
    create_production_engine,
    Policy,
    StepConfig,
    StepPriority,
    RouteClassification,
    FailureMode
)
```

### 2. Create Production Engine

```python
# This helper does everything:
# - Creates registry with strict validation
# - Registers default policies
# - Sets up telemetry and audit logging
# - Runs startup validation
# - Returns ready-to-use engine

engine = create_production_engine()

# Engine is validated and ready to use
```

### 3. Define Custom Policies

```python
# Define a custom policy with versioning
payment_policy = Policy(
    name="payment",
    version_id="1.0.0",  # Semantic versioning
    route_classification=RouteClassification.CRITICAL,  # Cannot fail-open
    requires_auth=True,
    failure_mode=FailureMode.FAIL_CLOSED,  # Explicit
    step_configs=(
        # Steps execute in deterministic order
        StepConfig("auth", StepPriority.CRITICAL, 0, timeout_seconds=3.0),
        StepConfig("authz", StepPriority.CRITICAL, 1, timeout_seconds=2.0),
        StepConfig("fraud", StepPriority.REQUIRED, 2, timeout_seconds=5.0),
        StepConfig("audit", StepPriority.OPTIONAL, 3, timeout_seconds=1.0, can_skip=True),
    ),
    metadata={"owner": "payments-team"}
)

# Register policy (validated automatically)
engine.registry.register(payment_policy)
```

### 4. Use in Your Application

```python
# In your request handler
def handle_payment(request):
    # Execute security checks
    event = engine.run(payment_policy, request, request_context={
        'user_id': request.user_id,
        'ip_address': request.client_ip
    })
    
    # Check decision
    if event.decision == DecisionType.DENY:
        raise HTTPException(403, event.failure_message)
    
    if event.decision == DecisionType.DEGRADED:
        logger.warning(f"DEGRADED SECURITY: {event.failure_mode_triggered}")
    
    # Continue with business logic
    return process_payment(request)
```

## Architecture

```
Request
   ↓
Security Engine          (Orchestration)
   ↓
Policy Validation        (Compile-time checks)
   ↓
Ordered Step Pipeline    (Deterministic execution)
   ↓
Circuit Breakers         (Adapter protection)
   ↓
Telemetry & Audit        (Observability)
   ↓
Decision (ALLOW/DENY/DEGRADED)
```

## Key Features

### 1. Mandatory Observability (R1)

Every security decision emits:
- Policy name, version, and hash
- Steps executed and skipped
- Failure modes triggered
- Adapter errors
- Final decision
- Complete timing data

```python
# Telemetry goes to:
# - Centralized logs (CloudWatch, Elasticsearch)
# - Metrics counters (Prometheus, Datadog)
# - Alert pipeline (PagerDuty, Opsgenie)

event = engine.run(policy, request)
print(f"Decision: {event.decision}")
print(f"Duration: {event.total_duration_ms}ms")
print(f"Steps: {event.steps_executed}")
```

### 2. Fail-Open Guardrails (R2)

The framework PREVENTS dangerous configurations:

```python
# ✗ This is REJECTED at creation time
bad_policy = Policy(
    name="critical_payment",
    route_classification=RouteClassification.CRITICAL,
    failure_mode=FailureMode.FAIL_OPEN  # ERROR!
)
# Raises PolicyValidationError

# ✓ This is ACCEPTED
safe_policy = Policy(
    name="public_content",
    route_classification=RouteClassification.PUBLIC,
    failure_mode=FailureMode.FAIL_OPEN  # OK for public
)
```

### 3. Policy Validation Engine (R3)

Comprehensive validation catches errors early:

```python
policy = Policy(
    name="my_policy",
    version_id="1.0.0",
    requires_auth=True,
    requires_roles=frozenset({"admin"}),  # ERROR: requires requires_auth
    rate_limit_count=-10  # ERROR: must be positive
)
# Raises PolicyValidationError with all errors
```

### 4. Critical Step Protection (R4)

CRITICAL steps cannot be skipped:

```python
# ✗ This is REJECTED
StepConfig(
    name="authentication",
    priority_tier=StepPriority.CRITICAL,
    can_skip=True  # ERROR!
)

# ✓ This is ACCEPTED
StepConfig(
    name="observability",
    priority_tier=StepPriority.OPTIONAL,
    can_skip=True  # OK for OPTIONAL
)
```

### 5. Adapter Failure Isolation (R5)

Circuit breakers protect against cascading failures:

```python
# Register circuit breaker for adapter
circuit = engine.circuit_registry.register("redis", CircuitConfig(
    failure_threshold=5,
    timeout_seconds=2.0,
    recovery_timeout=30.0
))

# Adapter failures trigger circuit breaker
# After threshold, circuit opens (fail-fast)
# System tests recovery after timeout
```

### 6. Deterministic Execution Ordering (R6)

Steps execute in explicit order:

```python
Policy(
    step_configs=(
        # Order is EXPLICIT, not based on list position
        StepConfig("step_c", StepPriority.OPTIONAL, 2),
        StepConfig("step_a", StepPriority.CRITICAL, 0),  # Runs first
        StepConfig("step_b", StepPriority.REQUIRED, 1),  # Runs second
    )
)
# Execution order: step_a → step_b → step_c
```

### 7. Startup Integrity Checks (R7)

System REFUSES to start if misconfigured:

```python
engine = SecurityEngine(registry)

# This is REQUIRED before use
engine.startup_validation()
# If validation fails, raises StartupValidationError
# System will not serve traffic

# Now safe to use
event = engine.run(policy, request)
```

### 8. Audit Trail Requirements (R8)

Every decision is forensically reproducible:

```python
# Execute security check
event = engine.run(policy, request)

# Later, during incident response:
audit_entry = engine.audit_logger.reconstruct_decision(event.event_id)

# Audit entry contains:
# - Complete request fingerprint
# - Policy snapshot (version, hash)
# - Decision path (steps executed, skipped)
# - All errors and timing
# - User context
```

### 9. Policy Versioning (R9)

Immutable versioning and change tracking:

```python
policy_v1 = Policy(
    name="api_policy",
    version_id="1.0.0",
    # ... config ...
)

policy_v2 = Policy(
    name="api_policy",
    version_id="2.0.0",
    # ... updated config ...
    change_history=("Added fraud detection", "Increased rate limits")
)

# Each version has unique content hash
print(policy_v1.version_hash)  # "652f13f2ffa9b2eb"
print(policy_v2.version_hash)  # "2ee0f08fbd5629e1"

# Events record which version was used
event = engine.run(policy_v2, request)
print(event.policy_version)  # "2.0.0"
```

### 10. Concurrency Safety (R10)

Thread-safe, stateless execution:

```python
# Steps must be stateless
class MySecurityStep(SecurityStep):
    def execute(self, request):
        # ✓ NO shared mutable state
        # ✓ Pure function
        # ✓ Thread-safe by design
        user_id = request.user_id
        return validate_user(user_id)

# Engine handles concurrent requests safely
# Multiple threads can execute simultaneously
```

### 11. Performance Safety Limits (R11)

Prevents DOS via security layer:

```python
class ExecutionLimits:
    MAX_STEP_DEPTH = 50  # Maximum steps per policy
    MAX_TOTAL_LATENCY_MS = 10000  # 10s total
    MAX_STEP_LATENCY_MS = 5000  # 5s per step
    MAX_CONCURRENT_EXECUTIONS = 1000  # Per instance

# Engine enforces these limits
# Prevents runaway security checks
```

## Predefined Policies

The framework includes production-ready policies:

```python
from security_framework import (
    PUBLIC_POLICY,      # Public endpoints with rate limiting
    AUTHENTICATED_POLICY,  # Authenticated users
    CRITICAL_POLICY,    # Critical operations (payment, admin)
    ADMIN_POLICY,       # Admin-only operations
    OBSERVE_POLICY      # Non-blocking observation
)

# Use directly
event = engine.run(CRITICAL_POLICY, request)
```

## Monitoring & Observability

### Health Check

```python
health = engine.health_check()

if not health['healthy']:
    # - Registry validation errors
    # - Circuit breakers open
    # - Startup not validated
    logger.error(f"Security engine unhealthy: {health}")
```

### Metrics

```python
metrics = engine.get_metrics()

print(f"Total decisions: {metrics['telemetry']['total_decisions']}")
print(f"Denials: {metrics['telemetry']['decisions_by_type']['deny']}")
print(f"Degraded: {metrics['telemetry']['decisions_by_type']['degraded']}")
print(f"Circuit breakers: {metrics['circuit_breakers']}")
```

### Audit Trail

```python
# Get recent audit entries
trail = engine.audit_logger.get_audit_trail(
    limit=100,
    policy_name="payment",
    decision_type=DecisionType.DENY
)

# Export for compliance
for entry in trail:
    print(entry['policy']['version'])
    print(entry['execution']['decision'])
    print(entry['errors'])
```

## Testing

Run comprehensive test suite:

```bash
python security_framework/tests/test_all_requirements.py
```

All 11 requirements are tested:
- ✓ R1: Observability
- ✓ R2: Fail-open guardrails
- ✓ R3: Policy validation
- ✓ R4: Critical step protection
- ✓ R5: Adapter isolation
- ✓ R6: Deterministic ordering
- ✓ R7: Startup validation
- ✓ R8: Audit trail
- ✓ R9: Policy versioning
- ✓ R10: Concurrency safety
- ✓ R11: Performance limits

## Production Deployment Checklist

Before deploying to production:

- [ ] Run startup validation (engine.startup_validation())
- [ ] Configure telemetry backend (CloudWatch, Datadog, etc.)
- [ ] Configure audit storage (PostgreSQL, S3, etc.)
- [ ] Set up circuit breakers for all adapters
- [ ] Register all policies with proper versioning
- [ ] Test health check endpoint
- [ ] Set up alerts for degraded mode
- [ ] Document policy change history
- [ ] Review fail-open configurations
- [ ] Load test with concurrency limits

## Architecture Principles

1. **Security without observability is an illusion** - Every decision is traced
2. **Fail-closed by default** - Explicit opt-in for fail-open
3. **Validate early, fail fast** - Catch config errors before production
4. **No silent degradation** - All failures are visible
5. **Immutable policies** - Versioning enables rollback and audit
6. **Adapter isolation** - External failures don't cascade
7. **Performance matters** - Security checks must not DOS the service

## License

This framework is production-ready and fully tested. All 11 critical requirements are implemented and validated.

## Support

For issues, questions, or contributions:
- Review the comprehensive test suite
- Check the examples in this README
- All requirements are documented in code comments
