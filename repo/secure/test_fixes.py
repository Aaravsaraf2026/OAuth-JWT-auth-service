"""
Security Framework - Tests for Fixed Issues

Covers the 6 remaining concerns raised in code review:
  A. SkipRemainingSteps leaves non-skippable tail steps unexecuted
  B. ThreadPoolExecutor(max_workers=1000) at init
  C. future.cancel() doesn't stop running threads (documented + stop_event)
  D. _classify_failure() in-method imports
  E. str(None) -> "None" in audit trail
  F. Test coverage for skip/timeout behaviour (previously absent)

Run with:
    python test_fixes.py
"""

import time
import threading
from typing import Any
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from security_framework import (
    SecurityEngine,
    PolicyRegistry,
    Policy,
    StepConfig,
    StepPriority,
    RouteClassification,
    FailureMode,
    TelemetryCollector,
    AuditLogger,
    DecisionType,
    SecurityException,
    ExecutionTimeoutError,
    StartupValidationError,
    PUBLIC_POLICY,
    AUTHENTICATED_POLICY,
    CRITICAL_POLICY,
    ADMIN_POLICY,
)
from security_framework.steps.base import SkipRemainingSteps, SecurityStep, NoOpStep
from security_framework.engine import ExecutionLimits


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_registry(*extra_policies):
    r = PolicyRegistry()
    r.register(PUBLIC_POLICY)
    r.register(AUTHENTICATED_POLICY)
    r.register(CRITICAL_POLICY)
    r.register(ADMIN_POLICY)
    for p in extra_policies:
        r.register(p)
    return r


def _make_engine(registry, pool_size=2):
    """Small pool size for tests — we don't need 32 threads."""
    return SecurityEngine(registry, thread_pool_size=pool_size)


class MockRequest:
    def __init__(self, url=None):
        self.method = "GET"
        self.url = url  # None by default to test FIX E


class ExecutionTracker:
    """Records which step names ran, in order."""
    def __init__(self):
        self.ran = []
        self.lock = threading.Lock()

    def record(self, name):
        with self.lock:
            self.ran.append(name)


class TrackingAdapter:
    """Adapter that records execution."""
    def __init__(self, tracker, name, raise_skip=False, fail=False):
        self.tracker = tracker
        self.name = name
        self.raise_skip = raise_skip
        self.fail = fail

    def execute(self, request, stop_event=None):
        self.tracker.record(self.name)
        if self.raise_skip:
            raise SkipRemainingSteps(f"{self.name} requested skip")
        if self.fail:
            raise SecurityException(f"{self.name} failed", recoverable=False)


class SlowAdapter:
    """Adapter that sleeps, optionally checking stop_event."""
    def __init__(self, sleep_seconds, check_stop_event=False):
        self.sleep_seconds = sleep_seconds
        self.check_stop_event = check_stop_event
        self.was_stopped = False

    def execute(self, request, stop_event=None):
        if self.check_stop_event and stop_event:
            deadline = time.time() + self.sleep_seconds
            while time.time() < deadline:
                if stop_event.is_set():
                    self.was_stopped = True
                    return
                time.sleep(0.05)
        else:
            time.sleep(self.sleep_seconds)


# ---------------------------------------------------------------------------
# FIX A: SkipRemainingSteps — non-skippable tail steps must still execute
# ---------------------------------------------------------------------------

def test_fix_a_skip_executes_required_tail_steps():
    """
    When a step raises SkipRemainingSteps, skippable steps after it are skipped
    but non-skippable (REQUIRED/CRITICAL) steps must still run.

    This was the core bug: the old implementation break'd the loop, silently
    abandoning any required steps that came after the skip signal.
    """
    print("\n=== FIX A: SkipRemainingSteps respects non-skippable tail steps ===")

    tracker = ExecutionTracker()

    policy = Policy(
        name="skip_test",
        version_id="1.0.0",
        route_classification=RouteClassification.PUBLIC,
        failure_mode=FailureMode.FAIL_CLOSED,
        step_configs=(
            StepConfig("step_a",        StepPriority.REQUIRED,      execution_order=0),
            StepConfig("step_skip_me",  StepPriority.REQUIRED,      execution_order=10),  # raises SkipRemainingSteps
            StepConfig("step_optional", StepPriority.OPTIONAL,      execution_order=20, can_skip=True),  # should be skipped
            StepConfig("step_required", StepPriority.REQUIRED,      execution_order=30),  # must still run
        )
    )

    registry = _make_registry(policy)
    engine = _make_engine(registry)
    engine.register_step_adapter("step_a",        TrackingAdapter(tracker, "step_a"))
    engine.register_step_adapter("step_skip_me",  TrackingAdapter(tracker, "step_skip_me", raise_skip=True))
    engine.register_step_adapter("step_optional", TrackingAdapter(tracker, "step_optional"))
    engine.register_step_adapter("step_required", TrackingAdapter(tracker, "step_required"))
    engine.startup_validation()

    event = engine.run(policy, MockRequest())

    assert "step_a" in event.steps_executed,        "step_a should have run"
    assert "step_skip_me" in event.steps_executed,  "step_skip_me should have run (it raised skip)"
    assert "step_optional" in event.steps_skipped,  "step_optional should be skipped (can_skip=True)"
    assert "step_required" in event.steps_executed, \
        f"step_required MUST run after skip — it's non-skippable. Got executed={event.steps_executed}"
    assert "step_optional" not in event.steps_executed, "step_optional should NOT have run"

    assert tracker.ran == ["step_a", "step_skip_me", "step_required"], \
        f"Execution order wrong: {tracker.ran}"

    print(f"  steps executed:  {event.steps_executed}")
    print(f"  steps skipped:   {event.steps_skipped}")
    print("✓ Non-skippable tail steps correctly executed after SkipRemainingSteps")


def test_fix_a_critical_step_never_skipped():
    """CRITICAL steps cannot be skipped under any circumstances."""
    print("\n=== FIX A: CRITICAL steps never skipped after SkipRemainingSteps ===")

    tracker = ExecutionTracker()

    policy = Policy(
        name="critical_skip_test",
        version_id="1.0.0",
        requires_auth=True,
        failure_mode=FailureMode.FAIL_CLOSED,
        step_configs=(
            StepConfig("auth",       StepPriority.CRITICAL,  execution_order=0),
            StepConfig("skip_here",  StepPriority.REQUIRED,  execution_order=10),
            StepConfig("audit",      StepPriority.OPTIONAL,  execution_order=20, can_skip=True),
            StepConfig("authz",      StepPriority.CRITICAL,  execution_order=30),  # must run
        )
    )

    registry = _make_registry(policy)
    engine = _make_engine(registry)
    engine.register_step_adapter("auth",       TrackingAdapter(tracker, "auth"))
    engine.register_step_adapter("skip_here",  TrackingAdapter(tracker, "skip_here", raise_skip=True))
    engine.register_step_adapter("audit",      TrackingAdapter(tracker, "audit"))
    engine.register_step_adapter("authz",      TrackingAdapter(tracker, "authz"))
    engine.startup_validation()

    event = engine.run(policy, MockRequest())

    assert "authz" in event.steps_executed, \
        f"CRITICAL step 'authz' must run even after skip. Got: {event.steps_executed}"
    assert "audit" in event.steps_skipped, "audit (can_skip=True) should be skipped"

    print(f"  steps executed:  {event.steps_executed}")
    print(f"  steps skipped:   {event.steps_skipped}")
    print("✓ CRITICAL steps run correctly after SkipRemainingSteps")


# ---------------------------------------------------------------------------
# FIX B: Thread pool size is configurable, default is 32 not 1000
# ---------------------------------------------------------------------------

def test_fix_b_pool_size_configurable():
    """ThreadPoolExecutor size should default to 32, not MAX_CONCURRENT_EXECUTIONS."""
    print("\n=== FIX B: Thread pool size configurable ===")

    registry = _make_registry()

    # Default pool size
    engine_default = SecurityEngine(registry)
    assert engine_default._executor._max_workers == ExecutionLimits.DEFAULT_THREAD_POOL_SIZE, \
        f"Default pool size should be {ExecutionLimits.DEFAULT_THREAD_POOL_SIZE}, " \
        f"got {engine_default._executor._max_workers}"
    engine_default.shutdown()

    # Custom pool size
    engine_custom = SecurityEngine(registry, thread_pool_size=8)
    assert engine_custom._executor._max_workers == 8, \
        f"Custom pool size should be 8, got {engine_custom._executor._max_workers}"
    engine_custom.shutdown()

    print(f"  Default pool size: {ExecutionLimits.DEFAULT_THREAD_POOL_SIZE} (not 1000)")
    print("✓ Thread pool size is independently configurable from MAX_CONCURRENT_EXECUTIONS")


# ---------------------------------------------------------------------------
# FIX C: Timeout raises correctly; stop_event signals cooperative adapters
# ---------------------------------------------------------------------------

def test_fix_c_timeout_raises_correctly():
    """Timeout correctly stops waiting and raises ExecutionTimeoutError."""
    print("\n=== FIX C: Timeout raises ExecutionTimeoutError ===")

    policy = Policy(
        name="timeout_test",
        version_id="1.0.0",
        route_classification=RouteClassification.PUBLIC,
        failure_mode=FailureMode.FAIL_CLOSED,
        step_configs=(
            StepConfig("slow_step", StepPriority.REQUIRED, execution_order=0, timeout_seconds=0.2),
        )
    )

    registry = _make_registry(policy)
    engine = _make_engine(registry)
    engine.register_step_adapter("slow_step", SlowAdapter(sleep_seconds=5.0))
    engine.startup_validation()

    start = time.time()
    try:
        engine.run(policy, MockRequest())
        assert False, "Should have raised ExecutionTimeoutError"
    except ExecutionTimeoutError as e:
        elapsed = time.time() - start
        assert elapsed < 1.0, f"Timeout should fire at ~0.2s, took {elapsed:.2f}s"
        assert "slow_step" in str(e)
        print(f"  Raised ExecutionTimeoutError in {elapsed:.2f}s (limit was 0.2s)")

    print("✓ Timeout correctly raises and stops waiting for the caller")


def test_fix_c_stop_event_cooperative_termination():
    """
    Adapters that accept stop_event can self-terminate cooperatively.
    This is the documented mitigation for the Python thread interruption limitation.
    """
    print("\n=== FIX C: Cooperative stop via stop_event ===")

    adapter = SlowAdapter(sleep_seconds=5.0, check_stop_event=True)

    policy = Policy(
        name="stop_event_test",
        version_id="1.0.0",
        route_classification=RouteClassification.PUBLIC,
        failure_mode=FailureMode.FAIL_CLOSED,
        step_configs=(
            StepConfig("slow_step", StepPriority.REQUIRED, execution_order=0, timeout_seconds=0.2),
        )
    )

    registry = _make_registry(policy)
    engine = _make_engine(registry)
    engine.register_step_adapter("slow_step", adapter)
    engine.startup_validation()

    try:
        engine.run(policy, MockRequest())
    except ExecutionTimeoutError:
        pass

    # Give the thread a moment to notice the stop event
    time.sleep(0.3)
    assert adapter.was_stopped, \
        "Adapter should have detected stop_event and terminated cooperatively"

    print("✓ Adapter correctly received and acted on stop_event")


def test_fix_c_limitation_documented():
    """
    Confirm the known limitation is documented in _execute_step docstring.
    Non-cooperative adapters (no stop_event check) will leak threads on timeout.
    This test verifies the behaviour is explicit, not hidden.
    """
    print("\n=== FIX C: Thread interruption limitation is documented ===")

    import inspect
    from security_framework.engine import SecurityEngine as SE
    docstring = inspect.getdoc(SE._execute_step)
    assert "cannot be forcibly interrupted" in docstring or \
           "stop_event" in docstring, \
        "_execute_step should document the thread interruption limitation"

    print("✓ Thread interruption limitation explicitly documented in _execute_step")


# ---------------------------------------------------------------------------
# FIX D: _classify_failure uses module-level imports
# ---------------------------------------------------------------------------

def test_fix_d_classify_failure_module_level_imports():
    """_classify_failure should not import inside the method on every call."""
    print("\n=== FIX D: _classify_failure uses module-level imports ===")

    import ast
    import inspect
    from security_framework import engine as engine_module

    source = inspect.getsource(engine_module.SecurityEngine._classify_failure)
    tree = ast.parse(source)

    import_nodes = [
        node for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
    ]

    assert len(import_nodes) == 0, \
        f"_classify_failure should have no in-method imports, found: {import_nodes}"

    print("✓ _classify_failure has no in-method imports")


# ---------------------------------------------------------------------------
# FIX E: None endpoint stored as None, not "None" string
# ---------------------------------------------------------------------------

def test_fix_e_none_endpoint_not_string():
    """
    When request has no url, endpoint in the audit trail should be None (null),
    not the string "None". str(None) == "None" breaks JSON filtering.
    """
    print("\n=== FIX E: None endpoint stored as None not 'None' string ===")

    policy = Policy(
        name="null_url_test",
        version_id="1.0.0",
        route_classification=RouteClassification.PUBLIC,
        step_configs=()
    )

    audit = AuditLogger()
    registry = _make_registry(policy)
    engine = SecurityEngine(registry, audit_logger=audit)
    engine.startup_validation()

    # Request with no url attribute
    request = MockRequest(url=None)
    event = engine.run(policy, request)

    assert event.endpoint is None, \
        f"endpoint should be None when url is None, got: {repr(event.endpoint)}"
    assert event.endpoint != "None", \
        "endpoint must not be the string 'None' — breaks audit filtering"

    # Verify it's also None in the audit trail entry
    trail = audit.get_audit_trail()
    assert len(trail) >= 1
    last_entry = trail[-1]
    assert last_entry['request']['endpoint'] is None, \
        f"Audit trail endpoint should be null, got: {repr(last_entry['request']['endpoint'])}"

    print(f"  event.endpoint = {repr(event.endpoint)} (correct: None)")
    print("✓ None endpoint stored as null in event and audit trail")


def test_fix_e_real_url_still_stored():
    """When url is present, it should still be stored as a string."""
    print("\n=== FIX E: Real URL still stored correctly ===")

    policy = Policy(
        name="real_url_test",
        version_id="1.0.0",
        route_classification=RouteClassification.PUBLIC,
        step_configs=()
    )

    registry = _make_registry(policy)
    engine = _make_engine(registry)
    engine.startup_validation()

    request = MockRequest(url="/api/v1/users")
    event = engine.run(policy, request)

    assert event.endpoint == "/api/v1/users", \
        f"Real URL should be stored as string, got: {repr(event.endpoint)}"

    print(f"  event.endpoint = {repr(event.endpoint)} (correct)")
    print("✓ Real URL stored correctly as string")


# ---------------------------------------------------------------------------
# Run all
# ---------------------------------------------------------------------------

def run_all():
    print("\n" + "=" * 70)
    print("SECURITY FRAMEWORK — FIX VERIFICATION TESTS")
    print("Covers: FIX A (SkipRemainingSteps), FIX B (pool size),")
    print("        FIX C (timeout/stop_event), FIX D (imports), FIX E (None url)")
    print("=" * 70)

    tests = [
        test_fix_a_skip_executes_required_tail_steps,
        test_fix_a_critical_step_never_skipped,
        test_fix_b_pool_size_configurable,
        test_fix_c_timeout_raises_correctly,
        test_fix_c_stop_event_cooperative_termination,
        test_fix_c_limitation_documented,
        test_fix_d_classify_failure_module_level_imports,
        test_fix_e_none_endpoint_not_string,
        test_fix_e_real_url_still_stored,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            failed += 1
            print(f"\n✗ FAILED: {test.__name__}")
            import traceback
            traceback.print_exc()

    print("\n" + "=" * 70)
    print(f"Results: {passed} passed, {failed} failed")
    if failed == 0:
        print("✓ ALL FIX VERIFICATION TESTS PASSED")
    else:
        print("✗ SOME TESTS FAILED — review output above")
    print("=" * 70)
    return failed == 0


if __name__ == "__main__":
    success = run_all()
    sys.exit(0 if success else 1)
