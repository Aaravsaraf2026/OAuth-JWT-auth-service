"""
Security Framework - Telemetry & Observability (Production-Ready)

REQUIREMENT 1: Mandatory Observability Guarantees
REQUIREMENT 8: Audit Trail Requirements

Every security decision must emit structured telemetry.
Security without observability is an illusion.

FIXES IN THIS VERSION:
- FIX 7: AuditLogger._audit_trail is now bounded (max_trail_size, default 10,000).
          Previously it grew forever — an unbounded memory leak under production load.
          Oldest entries are evicted when the limit is reached (FIFO).
          Storage backend still receives every entry regardless of the in-memory cap.
"""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import deque
import time
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Default maximum number of audit entries to keep in memory.
# At ~1KB per entry, 10,000 entries ≈ 10MB. Tune for your environment.
DEFAULT_MAX_AUDIT_TRAIL_SIZE = 10_000


class DecisionType(str, Enum):
    """Type of security decision made."""
    ALLOW = "allow"
    DENY = "deny"
    DEGRADED = "degraded"  # Fail-open mode triggered


class FailureReason(str, Enum):
    """Why a security check failed."""
    AUTH_FAILED = "auth_failed"
    AUTHZ_FAILED = "authz_failed"
    RATE_LIMIT = "rate_limit"
    FRAUD_DETECTED = "fraud_detected"
    ADAPTER_ERROR = "adapter_error"
    TIMEOUT = "timeout"
    VALIDATION_ERROR = "validation_error"
    CIRCUIT_OPEN = "circuit_open"
    UNKNOWN = "unknown"


@dataclass
class SecurityEvent:
    """
    REQUIREMENT 1: Mandatory Observability Guarantees

    Structured telemetry for every security decision.
    This is the MINIMUM information required for each decision.
    """
    # Identity
    event_id: str
    timestamp: float

    # Policy Context
    policy_name: str
    policy_version: str
    policy_hash: str

    # Execution Details
    steps_executed: List[str] = field(default_factory=list)
    steps_skipped: List[str] = field(default_factory=list)

    # Decision
    decision: DecisionType = DecisionType.ALLOW
    failure_mode_triggered: Optional[str] = None  # "fail_open" or "fail_closed"

    # Errors
    adapter_errors: Dict[str, str] = field(default_factory=dict)
    step_errors: Dict[str, str] = field(default_factory=dict)

    # Performance
    total_duration_ms: float = 0.0
    step_durations_ms: Dict[str, float] = field(default_factory=dict)

    # Request Context (for audit trail)
    request_fingerprint: Optional[str] = None
    user_id: Optional[str] = None
    ip_address: Optional[str] = None
    endpoint: Optional[str] = None

    # Failure Details
    failure_reason: Optional[FailureReason] = None
    failure_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging."""
        return asdict(self)

    def to_json(self) -> str:
        """Convert to JSON string."""
        data = self.to_dict()
        if isinstance(data.get('decision'), Enum):
            data['decision'] = data['decision'].value
        if isinstance(data.get('failure_reason'), Enum):
            data['failure_reason'] = data['failure_reason'].value
        return json.dumps(data)


class TelemetryCollector:
    """
    REQUIREMENT 1: Mandatory Observability Guarantees

    Collects and emits security telemetry to multiple destinations:
    - Centralized logs
    - Metrics counters
    - Alert pipeline
    """

    def __init__(
        self,
        enable_logging: bool = True,
        enable_metrics: bool = True,
        enable_alerts: bool = True
    ):
        self.enable_logging = enable_logging
        self.enable_metrics = enable_metrics
        self.enable_alerts = enable_alerts

        self._metrics = {
            'total_decisions': 0,
            'decisions_by_type': {
                DecisionType.ALLOW.value: 0,
                DecisionType.DENY.value: 0,
                DecisionType.DEGRADED.value: 0
            },
            'decisions_by_policy': {},
            'failures_by_reason': {},
            'adapter_errors': {},
            'average_duration_ms': 0.0,
            '_total_duration_ms': 0.0
        }

    def record_decision(self, event: SecurityEvent) -> None:
        """
        REQUIREMENT 1: Emit structured telemetry for security decision.
        Called for EVERY security decision, no exceptions.
        """
        if self.enable_logging:
            self._emit_to_logs(event)
        if self.enable_metrics:
            self._update_metrics(event)
        if self.enable_alerts:
            self._send_alert_if_needed(event)

    def _emit_to_logs(self, event: SecurityEvent) -> None:
        """Send structured event to centralized logging."""
        log_data = event.to_dict()

        if event.decision == DecisionType.DENY:
            logger.warning(
                f"SECURITY_DENY: {event.policy_name} - {event.failure_reason}",
                extra={'security_event': log_data}
            )
        elif event.decision == DecisionType.DEGRADED:
            logger.warning(
                f"SECURITY_DEGRADED: {event.policy_name} - fail-open triggered",
                extra={'security_event': log_data}
            )
        else:
            logger.info(
                f"SECURITY_ALLOW: {event.policy_name}",
                extra={'security_event': log_data}
            )

    def _update_metrics(self, event: SecurityEvent) -> None:
        """Update metrics counters."""
        self._metrics['total_decisions'] += 1

        decision_value = event.decision.value if isinstance(event.decision, Enum) else event.decision
        self._metrics['decisions_by_type'][decision_value] += 1

        if event.policy_name not in self._metrics['decisions_by_policy']:
            self._metrics['decisions_by_policy'][event.policy_name] = {
                'allow': 0, 'deny': 0, 'degraded': 0
            }
        self._metrics['decisions_by_policy'][event.policy_name][decision_value] += 1

        if event.failure_reason:
            reason_value = event.failure_reason.value if isinstance(event.failure_reason, Enum) else event.failure_reason
            self._metrics['failures_by_reason'].setdefault(reason_value, 0)
            self._metrics['failures_by_reason'][reason_value] += 1

        for adapter in event.adapter_errors:
            self._metrics['adapter_errors'].setdefault(adapter, 0)
            self._metrics['adapter_errors'][adapter] += 1

        self._metrics['_total_duration_ms'] += event.total_duration_ms
        self._metrics['average_duration_ms'] = (
            self._metrics['_total_duration_ms'] / self._metrics['total_decisions']
        )

    def _send_alert_if_needed(self, event: SecurityEvent) -> None:
        """Send to alert pipeline if event requires immediate attention."""
        if event.decision == DecisionType.DENY:
            logger.error(
                f"ALERT: Security denial - {event.policy_name} - {event.failure_reason}",
                extra={'security_event': event.to_dict()}
            )

        if event.decision == DecisionType.DEGRADED:
            logger.error(
                f"ALERT: Fail-open triggered - {event.policy_name} - SECURITY IS DEGRADED",
                extra={'security_event': event.to_dict()}
            )

        if event.adapter_errors:
            logger.error(
                f"ALERT: Adapter failures - {', '.join(event.adapter_errors.keys())}",
                extra={'security_event': event.to_dict()}
            )

    def get_metrics(self) -> Dict[str, Any]:
        """Get current metrics snapshot."""
        return self._metrics.copy()

    def reset_metrics(self) -> None:
        """Reset all metrics to zero."""
        self._metrics = {
            'total_decisions': 0,
            'decisions_by_type': {
                DecisionType.ALLOW.value: 0,
                DecisionType.DENY.value: 0,
                DecisionType.DEGRADED.value: 0
            },
            'decisions_by_policy': {},
            'failures_by_reason': {},
            'adapter_errors': {},
            'average_duration_ms': 0.0,
            '_total_duration_ms': 0.0
        }


class AuditLogger:
    """
    REQUIREMENT 8: Audit Trail Requirements

    Forensic audit trail for security decisions.
    Every decision must be reproducible.

    FIX 7: In-memory trail is now bounded by max_trail_size (default 10,000).
    Oldest entries are evicted automatically (FIFO via collections.deque).
    The persistent storage backend still receives every entry — the cap only
    limits what is held in RAM.
    """

    def __init__(
        self,
        storage_backend: Optional[Any] = None,
        max_trail_size: int = DEFAULT_MAX_AUDIT_TRAIL_SIZE
    ):
        """
        Initialize audit logger.

        Args:
            storage_backend: Where to store audit logs (DB, S3, etc.)
            max_trail_size: Maximum number of entries to keep in memory.
                            Older entries are dropped when this limit is hit.
                            Set to 0 for unlimited (not recommended in production).
        """
        self.storage_backend = storage_backend
        self.max_trail_size = max_trail_size

        # FIX 7: Use a bounded deque instead of an unbounded list.
        # maxlen=None means unlimited (for max_trail_size=0 case).
        maxlen = max_trail_size if max_trail_size > 0 else None
        self._audit_trail: deque = deque(maxlen=maxlen)

    def log_decision(
        self,
        event: SecurityEvent,
        request_data: Optional[Dict[str, Any]] = None,
        response_data: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        REQUIREMENT 8: Store audit trail entry.

        Creates a forensically traceable record of the security decision.
        Always writes to the storage backend (if configured).
        In-memory trail is bounded by max_trail_size.
        """
        audit_entry = {
            'event_id': event.event_id,
            'timestamp': event.timestamp,
            'timestamp_iso': datetime.fromtimestamp(event.timestamp).isoformat(),

            'policy': {
                'name': event.policy_name,
                'version': event.policy_version,
                'hash': event.policy_hash
            },

            'execution': {
                'steps_executed': event.steps_executed,
                'steps_skipped': event.steps_skipped,
                'decision': event.decision.value if isinstance(event.decision, Enum) else event.decision,
                'failure_mode': event.failure_mode_triggered
            },

            'request': {
                'fingerprint': event.request_fingerprint,
                'user_id': event.user_id,
                'ip_address': event.ip_address,
                'endpoint': event.endpoint,
                'data': request_data
            },

            'response': response_data,

            'errors': {
                'adapter_errors': event.adapter_errors,
                'step_errors': event.step_errors,
                'failure_reason': event.failure_reason.value if event.failure_reason else None,
                'failure_message': event.failure_message
            },

            'performance': {
                'total_duration_ms': event.total_duration_ms,
                'step_durations_ms': event.step_durations_ms
            }
        }

        # In-memory trail (bounded — old entries auto-evicted by deque maxlen)
        self._audit_trail.append(audit_entry)

        # Persistent backend receives every entry regardless of in-memory cap
        if self.storage_backend:
            self._store_to_backend(audit_entry)

        logger.info(
            f"AUDIT: {event.decision.value if isinstance(event.decision, Enum) else event.decision} "
            f"- {event.policy_name} - {event.event_id}",
            extra={'audit_entry': audit_entry}
        )

    def _store_to_backend(self, audit_entry: Dict[str, Any]) -> None:
        """Store audit entry to persistent backend."""
        try:
            if hasattr(self.storage_backend, 'store_audit'):
                self.storage_backend.store_audit(audit_entry)
        except Exception as e:
            logger.error(f"Failed to store audit entry: {e}")

    def get_audit_trail(
        self,
        limit: Optional[int] = None,
        policy_name: Optional[str] = None,
        decision_type: Optional[DecisionType] = None
    ) -> List[Dict[str, Any]]:
        """
        Retrieve in-memory audit trail with optional filters.

        Note: Only returns entries currently held in memory (up to max_trail_size).
        For complete history, query the storage backend directly.
        """
        filtered = list(self._audit_trail)

        if policy_name:
            filtered = [e for e in filtered if e['policy']['name'] == policy_name]

        if decision_type:
            decision_value = decision_type.value if isinstance(decision_type, Enum) else decision_type
            filtered = [e for e in filtered if e['execution']['decision'] == decision_value]

        if limit:
            filtered = filtered[-limit:]

        return filtered

    def reconstruct_decision(self, event_id: str) -> Optional[Dict[str, Any]]:
        """
        REQUIREMENT 8: Reconstruct a security decision from audit trail.

        Searches the in-memory trail. For decisions older than max_trail_size,
        query the storage backend directly.
        """
        for entry in self._audit_trail:
            if entry['event_id'] == event_id:
                return entry
        return None

    @property
    def trail_size(self) -> int:
        """Number of entries currently held in memory."""
        return len(self._audit_trail)
