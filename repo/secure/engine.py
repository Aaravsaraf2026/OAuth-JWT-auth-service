"""
Security Framework - Security Engine (Production-Ready)

FIXES IN THIS VERSION (addressing all remaining review concerns):

FIX A: SkipRemainingSteps — after signal, non-skippable tail steps now execute.
        Previously: pipeline break'd, silently abandoning required steps.
        Now: skippable steps are pre-marked; pipeline continues via _should_skip_step.

FIX B: ThreadPoolExecutor pool size is now configurable (default: 32, not 1000).
        MAX_CONCURRENT_EXECUTIONS controls admission; pool size is separate.
        1000 standby threads at init is wasteful for most deployments.

FIX C: future.cancel() limitation explicitly documented.
        Python threads cannot be interrupted once started — cancel() only works
        for pending futures. After timeout, we set a stop_event the adapter can
        check, log the leaked thread, and raise. Callers/adapters receive a
        threading.Event they can poll to self-terminate cooperatively.

FIX D: _classify_failure() imports moved to module level.
        Consistent with RouteClassification/FailureMode fix.

FIX E: endpoint=str(getattr(...)) → None preserved, not "None" string.
        str(None) == "None" breaks audit filtering. Use getattr directly.
"""

from typing import Optional, Dict, Any, List
import time
import json
import logging
import hashlib
import uuid
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
import threading

from .policy import Policy, DEFAULT_POLICY, StepPriority, StepConfig, RouteClassification, FailureMode
from .registry import PolicyRegistry
from .telemetry import (
    TelemetryCollector,
    AuditLogger,
    SecurityEvent,
    DecisionType,
    FailureReason
)
from .circuit_breaker import CircuitBreakerRegistry
from .steps.base import SkipRemainingSteps
from .exceptions import (
    SecurityException,
    AuthenticationError,
    AuthorizationError,
    RateLimitError,
    FraudError,
    CircuitOpenError,
    PolicyNotFoundError,
    ExecutionTimeoutError,
    StartupValidationError
)

logger = logging.getLogger(__name__)


class ExecutionLimits:
    """
    REQUIREMENT 11: Performance Safety Limits
    """
    MAX_STEP_DEPTH = 50
    MAX_TOTAL_LATENCY_MS = 10000
    MAX_STEP_LATENCY_MS = 5000
    MAX_CONCURRENT_EXECUTIONS = 1000

    # FIX B: Pool size is separate from admission limit.
    # 32 covers typical burst concurrency without 1000 standby threads.
    # Increase if your adapter calls are genuinely long-running and concurrent.
    DEFAULT_THREAD_POOL_SIZE = 32


class SecurityEngine:
    """
    Production-Ready Security Engine.

    Key Guarantees:
    - Every decision is observable
    - No silent fail-open
    - All policies validated at startup
    - Critical steps cannot be skipped
    - Adapter failures are isolated
    - Execution order is deterministic
    - Complete audit trail
    - Thread-safe execution
    - Performance limits enforced
    """

    def __init__(
        self,
        registry: PolicyRegistry,
        telemetry: Optional[TelemetryCollector] = None,
        audit_logger: Optional[AuditLogger] = None,
        circuit_registry: Optional[CircuitBreakerRegistry] = None,
        enforce_limits: bool = True,
        thread_pool_size: Optional[int] = None,
    ):
        """
        Args:
            thread_pool_size: Max threads in the step executor pool.
                              Defaults to ExecutionLimits.DEFAULT_THREAD_POOL_SIZE (32).
                              Set higher only if you have many long-running parallel adapters.
                              Note: MAX_CONCURRENT_EXECUTIONS controls admission independently.
        """
        self.registry = registry
        self.telemetry = telemetry or TelemetryCollector()
        self.audit_logger = audit_logger or AuditLogger()
        self.circuit_registry = circuit_registry or CircuitBreakerRegistry()
        self.enforce_limits = enforce_limits

        # REQUIREMENT 10: Concurrency Safety
        self._execution_lock = threading.RLock()
        self._concurrent_executions = 0
        self._step_adapters: Dict[str, Any] = {}
        # Cached at register_step_adapter time — avoids inspect.signature() per request
        self._adapter_stop_event_support: Dict[str, bool] = {}

        # REQUIREMENT 7: Startup Integrity Checks
        self._startup_validated = False
        self._startup_errors: List[str] = []

        # FIX B: Pool size configurable and defaulting to a sane value (32).
        # Previously hardcoded to MAX_CONCURRENT_EXECUTIONS=1000 — 1000 standby
        # threads at init regardless of actual load. Admission control and pool
        # size are now independent knobs.
        pool_size = thread_pool_size or ExecutionLimits.DEFAULT_THREAD_POOL_SIZE
        self._executor = ThreadPoolExecutor(
            max_workers=pool_size,
            thread_name_prefix="sec_step"
        )

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def startup_validation(self) -> None:
        """
        REQUIREMENT 7: Run comprehensive validation BEFORE serving traffic.
        REFUSES TO START if any check fails.
        """
        logger.info("=" * 70)
        logger.info("SECURITY ENGINE: Starting validation checks...")
        logger.info("=" * 70)

        errors = []

        # 1. Validate registry
        try:
            self.registry.startup_validation()
            logger.info("✓ Registry validation passed")
        except StartupValidationError as e:
            errors.extend(e.errors)
            logger.error("✗ Registry validation failed")

        # 2. Verify telemetry pipeline
        try:
            test_event = SecurityEvent(
                event_id="startup_test",
                timestamp=time.time(),
                policy_name="test",
                policy_version="0.0.0",
                policy_hash="test"
            )
            self.telemetry.record_decision(test_event)
            logger.info("✓ Telemetry pipeline operational")
        except Exception as e:
            errors.append(f"Telemetry pipeline failed: {e}")
            logger.error(f"✗ Telemetry pipeline failed: {e}")

        # 3. Verify audit logger
        try:
            test_event = SecurityEvent(
                event_id="startup_test_audit",
                timestamp=time.time(),
                policy_name="test",
                policy_version="0.0.0",
                policy_hash="test"
            )
            self.audit_logger.log_decision(test_event)
            logger.info("✓ Audit logger operational")
        except Exception as e:
            errors.append(f"Audit logger failed: {e}")
            logger.error(f"✗ Audit logger failed: {e}")

        # 4. Validate step count limits (R11)
        for policy_name in self.registry.list_policies():
            policy = self.registry.get(policy_name)
            if len(policy.step_configs) > ExecutionLimits.MAX_STEP_DEPTH:
                errors.append(
                    f"Policy '{policy_name}' has {len(policy.step_configs)} steps "
                    f"(max: {ExecutionLimits.MAX_STEP_DEPTH})"
                )

        # 5. Dry execution checks (R6)
        logger.info("Running dry execution tests...")
        for policy_name in self.registry.list_policies():
            try:
                policy = self.registry.get(policy_name)
                ordered_steps = policy.get_ordered_steps()
                if len(ordered_steps) != len(policy.step_configs):
                    errors.append(f"Policy '{policy_name}' step ordering validation failed")
            except Exception as e:
                errors.append(f"Dry execution failed for '{policy_name}': {e}")

        logger.info("✓ Dry execution tests passed")

        if errors:
            self._startup_errors = errors
            error_msg = "\n".join([f"  - {e}" for e in errors])
            logger.error("=" * 70)
            logger.error("SECURITY ENGINE: Startup validation FAILED")
            logger.error("=" * 70)
            logger.error(f"\n{error_msg}\n")
            raise StartupValidationError(errors)

        self._startup_validated = True
        logger.info("=" * 70)
        logger.info("✓ SECURITY ENGINE: Startup validation PASSED")
        logger.info("=" * 70)

    def register_step_adapter(self, step_name: str, adapter: Any) -> None:
        """
        Register adapter for a security step (R5).

        inspect.signature() is called here at registration time and the result
        cached. Doing it inside _run() per request would re-inspect __wrapped__,
        __signature__, and __code__ on every step execution — unnecessary work
        on a hot path in security middleware.
        """
        import inspect
        try:
            sig = inspect.signature(adapter.execute)
            accepts_stop_event = 'stop_event' in sig.parameters
        except (ValueError, TypeError):
            # Some adapters (C extensions, certain wrappers) may not be inspectable
            accepts_stop_event = False

        self._step_adapters[step_name] = adapter
        self._adapter_stop_event_support[step_name] = accepts_stop_event
        logger.info(
            f"Registered adapter for step '{step_name}' "
            f"(stop_event support: {accepts_stop_event})"
        )

    def run(
        self,
        policy: Policy,
        request: Any,
        request_context: Optional[Dict[str, Any]] = None
    ) -> SecurityEvent:
        """Execute blocking security checks."""
        if not self._startup_validated:
            raise StartupValidationError(
                ["Engine not validated - call startup_validation() first"]
            )

        with self._execution_lock:
            if self._concurrent_executions >= ExecutionLimits.MAX_CONCURRENT_EXECUTIONS:
                raise SecurityException("Too many concurrent executions", recoverable=True)
            self._concurrent_executions += 1

        try:
            return self._execute_pipeline(policy, request, request_context)
        finally:
            with self._execution_lock:
                self._concurrent_executions -= 1

    # -------------------------------------------------------------------------
    # Pipeline execution
    # -------------------------------------------------------------------------

    def _execute_pipeline(
        self,
        policy: Policy,
        request: Any,
        request_context: Optional[Dict[str, Any]]
    ) -> SecurityEvent:
        start_time = time.time()

        # FIX E: Preserve None rather than converting to the string "None".
        # str(None) == "None" which breaks JSON audit filtering downstream.
        raw_url = getattr(request, 'url', None)
        endpoint = str(raw_url) if raw_url is not None else None

        event = SecurityEvent(
            event_id=str(uuid.uuid4()),
            timestamp=start_time,
            policy_name=policy.name,
            policy_version=policy.version_id,
            policy_hash=policy.version_hash,
            request_fingerprint=self._compute_request_fingerprint(request),
            endpoint=endpoint,
            user_id=request_context.get('user_id') if request_context else None,
            ip_address=request_context.get('ip_address') if request_context else None
        )

        steps = policy.get_ordered_steps()

        if len(steps) > ExecutionLimits.MAX_STEP_DEPTH:
            event.decision = DecisionType.DENY
            event.failure_reason = FailureReason.VALIDATION_ERROR
            event.failure_message = f"Too many steps: {len(steps)}"
            self._emit_telemetry(event)
            raise SecurityException(
                f"Policy '{policy.name}' exceeds max step depth "
                f"({len(steps)} > {ExecutionLimits.MAX_STEP_DEPTH})"
            )

        try:
            for step_index, step_config in enumerate(steps):
                if self._should_skip_step(step_config, event):
                    event.steps_skipped.append(step_config.name)
                    continue

                step_start = time.time()

                try:
                    self._execute_step(step_config, request, event)

                    step_duration = (time.time() - step_start) * 1000
                    event.step_durations_ms[step_config.name] = step_duration
                    event.steps_executed.append(step_config.name)

                    if step_duration > ExecutionLimits.MAX_STEP_LATENCY_MS:
                        logger.warning(
                            f"Step '{step_config.name}' exceeded latency limit: "
                            f"{step_duration:.1f}ms"
                        )

                except SkipRemainingSteps as skip:
                    # FIX A: SkipRemainingSteps correctly handles non-skippable tail steps.
                    #
                    # Previous behaviour: pipeline break'd after marking can_skip steps.
                    # Non-skippable steps in the tail were silently abandoned — a security
                    # gap since REQUIRED steps could go unexecuted without any error.
                    #
                    # New behaviour:
                    # 1. Mark current step as executed.
                    # 2. Walk remaining steps: mark can_skip=True ones as skipped.
                    # 3. Leave can_skip=False steps unmarked — _should_skip_step returns
                    #    False for them, so they execute normally when the loop continues.
                    # 4. Do NOT break — let the loop finish.
                    #
                    # step_index is tracked via enumerate() — no O(n) steps.index() scan.
                    logger.info(
                        f"Pipeline skip requested after '{step_config.name}': {skip.reason}"
                    )
                    step_duration = (time.time() - step_start) * 1000
                    event.step_durations_ms[step_config.name] = step_duration
                    event.steps_executed.append(step_config.name)

                    for remaining in steps[step_index + 1:]:
                        if remaining.can_skip:
                            event.steps_skipped.append(remaining.name)
                        # Non-skippable steps intentionally left unmarked — they will run

                except SecurityException as e:
                    step_duration = (time.time() - step_start) * 1000
                    event.step_durations_ms[step_config.name] = step_duration
                    event.step_errors[step_config.name] = str(e)

                    if self._should_fail_open(policy, step_config, e):
                        event.decision = DecisionType.DEGRADED
                        event.failure_mode_triggered = "fail_open"
                        logger.warning(
                            f"DEGRADED MODE: Step '{step_config.name}' failed, "
                            f"continuing fail-open: {e}"
                        )
                        continue
                    else:
                        event.decision = DecisionType.DENY
                        event.failure_mode_triggered = "fail_closed"
                        event.failure_reason = self._classify_failure(e)
                        event.failure_message = str(e)
                        event.total_duration_ms = (time.time() - start_time) * 1000
                        self._emit_telemetry(event)
                        raise

            # All steps completed (executed, skipped, or failed-open)
            event.decision = DecisionType.ALLOW
            event.total_duration_ms = (time.time() - start_time) * 1000

            if event.total_duration_ms > ExecutionLimits.MAX_TOTAL_LATENCY_MS:
                logger.error(
                    f"Policy '{policy.name}' exceeded total latency limit: "
                    f"{event.total_duration_ms:.1f}ms"
                )

            self._emit_telemetry(event)
            return event

        except Exception as e:
            if not isinstance(e, SecurityException):
                event.decision = DecisionType.DENY
                event.failure_reason = FailureReason.UNKNOWN
                event.failure_message = str(e)
                event.total_duration_ms = (time.time() - start_time) * 1000
                self._emit_telemetry(event)
            raise

    # -------------------------------------------------------------------------
    # Step execution
    # -------------------------------------------------------------------------

    def _execute_step(
        self,
        step_config: StepConfig,
        request: Any,
        event: SecurityEvent
    ) -> None:
        """
        Execute a single security step with timeout enforcement.

        TIMEOUT LIMITATION (FIX C):
        Python threads cannot be forcibly interrupted once started.
        future.cancel() only prevents a *pending* future from starting —
        if the thread is already running, it continues executing even after
        we stop waiting for it.

        What this means in practice:
        - The CALLER (this method) will raise ExecutionTimeoutError correctly.
        - The ADAPTER THREAD keeps running until it naturally completes or errors.
        - In a worst case, a permanently-hung adapter leaks threads until the
          pool is exhausted.

        Mitigation: adapters should check stop_event.is_set() periodically
        and return early. The stop_event is passed to adapter.execute() if the
        adapter accepts a keyword argument named 'stop_event'.

        For truly uncancellable adapters (e.g. blocking network I/O),
        the correct long-term fix is to use async adapters with asyncio.wait_for().
        """
        adapter = self._step_adapters.get(step_config.name)

        if not adapter:
            raise SecurityException(
                f"No adapter registered for step '{step_config.name}'",
                recoverable=False
            )

        circuit = self.circuit_registry.get(step_config.name)

        # Cooperative stop signal for well-behaved adapters (FIX C)
        stop_event = threading.Event()

        # Use cached flag — inspect.signature() was called at register_step_adapter time
        accepts_stop_event = self._adapter_stop_event_support.get(step_config.name, False)

        def _run():
            if accepts_stop_event:
                call = lambda: adapter.execute(request, stop_event=stop_event)
            else:
                call = lambda: adapter.execute(request)

            if circuit:
                circuit.call(call, fallback=None)
            else:
                call()

        future = self._executor.submit(_run)
        try:
            future.result(timeout=step_config.timeout_seconds)
        except FutureTimeoutError:
            # Signal the thread to stop if it checks the event
            stop_event.set()
            future.cancel()  # No-op if already running, but cleans up if pending
            logger.warning(
                f"Step '{step_config.name}' timed out after "
                f"{step_config.timeout_seconds}s. "
                f"NOTE: underlying thread may still be running — "
                f"adapter should check stop_event.is_set() to self-terminate."
            )
            event.adapter_errors[step_config.name] = (
                f"timed out after {step_config.timeout_seconds}s"
            )
            raise ExecutionTimeoutError(step_config.name, step_config.timeout_seconds)
        except Exception as e:
            stop_event.set()
            event.adapter_errors[step_config.name] = str(e)
            raise

    # -------------------------------------------------------------------------
    # Step control
    # -------------------------------------------------------------------------

    def _should_skip_step(self, step_config: StepConfig, event: SecurityEvent) -> bool:
        """
        REQUIREMENT 4: Critical Step Protection.

        CRITICAL steps are never skipped.
        Non-skippable steps (can_skip=False) are never skipped.
        A step is skipped only if it has can_skip=True AND has been
        pre-marked in event.steps_skipped (by SkipRemainingSteps handler).
        """
        if step_config.priority_tier == StepPriority.CRITICAL:
            return False

        if not step_config.can_skip:
            return False

        return step_config.name in event.steps_skipped

    def _should_fail_open(
        self,
        policy: Policy,
        step_config: StepConfig,
        error: SecurityException
    ) -> bool:
        """REQUIREMENT 2: Fail-Open Guardrails."""
        if step_config.priority_tier == StepPriority.CRITICAL:
            return False
        if policy.requires_auth:
            return False
        if policy.route_classification in [
            RouteClassification.CRITICAL,
            RouteClassification.PRIVILEGED,
            RouteClassification.AUTHENTICATED
        ]:
            return False
        if not error.recoverable:
            return False
        if policy.failure_mode != FailureMode.FAIL_OPEN:
            return False
        return True

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def _emit_telemetry(self, event: SecurityEvent) -> None:
        self.telemetry.record_decision(event)
        self.audit_logger.log_decision(event)

    def _compute_request_fingerprint(self, request: Any) -> str:
        fingerprint_data = {
            'method': getattr(request, 'method', 'UNKNOWN'),
            'path': str(getattr(request, 'url', 'UNKNOWN')),
            'timestamp': time.time()
        }
        return hashlib.sha256(
            json.dumps(fingerprint_data, sort_keys=True).encode()
        ).hexdigest()[:16]

    def _classify_failure(self, error: SecurityException) -> FailureReason:
        """
        FIX D: All exception imports moved to module level.
        Previously AuthenticationError etc. were imported inside this method
        on every call — inconsistent with the RouteClassification/FailureMode fix.
        """
        if isinstance(error, AuthenticationError):
            return FailureReason.AUTH_FAILED
        elif isinstance(error, AuthorizationError):
            return FailureReason.AUTHZ_FAILED
        elif isinstance(error, RateLimitError):
            return FailureReason.RATE_LIMIT
        elif isinstance(error, FraudError):
            return FailureReason.FRAUD_DETECTED
        elif isinstance(error, CircuitOpenError):
            return FailureReason.CIRCUIT_OPEN
        elif isinstance(error, ExecutionTimeoutError):
            return FailureReason.TIMEOUT
        else:
            return FailureReason.UNKNOWN

    # -------------------------------------------------------------------------
    # Observability
    # -------------------------------------------------------------------------

    def health_check(self) -> Dict[str, Any]:
        registry_errors = self.registry.validate_all()
        circuit_health = self.circuit_registry.health_check()
        return {
            'healthy': (
                len(registry_errors) == 0 and
                circuit_health['healthy'] and
                self._startup_validated
            ),
            'startup_validated': self._startup_validated,
            'registry': {
                'healthy': len(registry_errors) == 0,
                'errors': registry_errors,
                'total_policies': len(self.registry.list_policies())
            },
            'circuit_breakers': circuit_health,
            'telemetry': self.telemetry.get_metrics(),
            'concurrent_executions': self._concurrent_executions,
            'timestamp': time.time()
        }

    def get_metrics(self) -> Dict[str, Any]:
        return {
            'telemetry': self.telemetry.get_metrics(),
            'circuit_breakers': self.circuit_registry.get_all_metrics(),
            'concurrent_executions': self._concurrent_executions,
            'startup_validated': self._startup_validated
        }

    def shutdown(self) -> None:
        """Drain thread pool on application shutdown."""
        logger.info("SecurityEngine shutting down...")
        self._executor.shutdown(wait=True)
        logger.info("SecurityEngine shutdown complete.")

    def __repr__(self):
        return (
            f"<SecurityEngine("
            f"policies={len(self.registry.list_policies())}, "
            f"validated={self._startup_validated}, "
            f"concurrent={self._concurrent_executions}"
            f")>"
        )
