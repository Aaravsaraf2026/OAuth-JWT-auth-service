"""
Security Framework - Policy Layer (Production-Ready)

REQUIREMENT 3: Policy Validation Engine
REQUIREMENT 4: Critical Step Protection
REQUIREMENT 9: Policy Versioning
REQUIREMENT 6: Deterministic Execution Ordering

Policies are immutable, versioned configuration objects.

FIXES IN THIS VERSION:
- FIX 4: Step execution_order validation no longer requires sequential 0,1,2,3...
          Gaps are now allowed (e.g. 0, 10, 20) so steps can be inserted later
          without renumbering. Only uniqueness and non-negative values are enforced.
- FIX 5: Policy.__eq__ and __hash__ now use version_hash (content) not just name+version,
          so two policies with the same name/version but different content are not equal.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, Optional, FrozenSet, List, Tuple
from enum import Enum
import hashlib
import json
import time


class FailureMode(str, Enum):
    """How to handle failures in this policy."""
    FAIL_OPEN = "fail_open"       # Continue with degraded security
    FAIL_CLOSED = "fail_closed"   # Block request on any failure


class StepPriority(str, Enum):
    """
    REQUIREMENT 4: Critical Step Protection

    Priority tiers for security steps.
    Critical steps CANNOT be skipped, ever.
    """
    CRITICAL = "critical"             # Cannot skip (auth, authz)
    REQUIRED = "required"             # Should not skip (rate limit, fraud)
    OPTIONAL = "optional"             # Can skip if needed (observability)
    OBSERVATIONAL = "observational"   # Non-blocking only


class RouteClassification(str, Enum):
    """
    REQUIREMENT 2: Fail-Open Guardrails

    Route criticality determines allowed failure modes.
    """
    CRITICAL = "critical"             # Must fail-closed (payment, auth)
    PRIVILEGED = "privileged"         # Must fail-closed (admin, config)
    AUTHENTICATED = "authenticated"   # Must fail-closed (user data)
    PUBLIC = "public"                 # Can fail-open (landing pages)


@dataclass(frozen=True)
class StepConfig:
    """
    Configuration for a single security step in the pipeline.

    REQUIREMENT 6: Deterministic Execution Ordering
    Steps are ordered by execution_order number, not list position.

    execution_order values do NOT need to be sequential — gaps are intentional.
    Use gaps (e.g. 0, 10, 20) so future steps can be inserted without renumbering.
    """
    name: str
    priority_tier: StepPriority
    execution_order: int  # Explicit ordering (lower = earlier). Gaps allowed.
    timeout_seconds: float = 5.0
    retry_attempts: int = 0
    can_skip: bool = False  # Can SkipRemainingSteps skip this?

    def __post_init__(self):
        """Validate step configuration."""
        if self.execution_order < 0:
            raise ValueError(f"Step '{self.name}': execution_order must be >= 0")

        if self.timeout_seconds <= 0:
            raise ValueError(f"Step '{self.name}': timeout_seconds must be > 0")

        if self.retry_attempts < 0:
            raise ValueError(f"Step '{self.name}': retry_attempts must be >= 0")

        # REQUIREMENT 4: Critical steps cannot be skipped
        if self.priority_tier == StepPriority.CRITICAL and self.can_skip:
            raise ValueError(
                f"Step '{self.name}': CRITICAL steps cannot have can_skip=True"
            )


@dataclass(frozen=True)
class Policy:
    """
    Immutable, versioned security policy configuration.

    PRODUCTION REQUIREMENTS IMPLEMENTED:
    - R3: Policy Validation Engine (see validate())
    - R4: Critical Step Protection (via StepPriority)
    - R6: Deterministic Execution (via execution_order)
    - R9: Policy Versioning (version_id, version_hash)
    - R2: Fail-Open Guardrails (route_classification)
    """

    # Identity & Versioning (R9)
    name: str
    version_id: str           # Semantic version (e.g., "1.2.3")
    version_hash: str = ""    # Immutable content hash (auto-computed)
    deployed_at: float = 0.0  # Unix timestamp

    # Route Classification (R2)
    route_classification: RouteClassification = RouteClassification.AUTHENTICATED

    # Authentication
    requires_auth: bool = False
    requires_roles: FrozenSet[str] = field(default_factory=frozenset)

    # Rate Limiting
    rate_limit: bool = False
    rate_limit_count: int = 100
    rate_limit_window: int = 60  # seconds

    # Audit
    audit: bool = False
    audit_level: str = "basic"  # "basic" or "detailed"

    # Fraud Detection
    fraud_check: bool = False
    fraud_threshold: int = 80  # 0-100

    # Execution
    blocking: bool = True
    observe_only: bool = False

    # Error Handling
    failure_mode: FailureMode = FailureMode.FAIL_CLOSED

    # Step Pipeline (R6: Deterministic Ordering)
    step_configs: Tuple[StepConfig, ...] = field(default_factory=tuple)

    # Extensibility
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Change History (R9)
    change_history: Tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self):
        """
        REQUIREMENT 3: Policy Validation Engine

        Validate policy at creation time.
        Catches configuration errors before they reach production.
        """
        errors = self.validate()
        if errors:
            from .exceptions import PolicyValidationError
            raise PolicyValidationError(self.name, errors)

        # Auto-compute version hash if not provided
        if not self.version_hash:
            object.__setattr__(self, 'version_hash', self._compute_hash())

        # Auto-set deployment timestamp if not provided
        if self.deployed_at == 0.0:
            object.__setattr__(self, 'deployed_at', time.time())

    def validate(self) -> List[str]:
        """
        REQUIREMENT 3: Policy Validation Engine

        Run comprehensive validation checks.
        Returns list of error messages (empty = valid).
        """
        errors = []

        # 1. Validate name
        if not self.name:
            errors.append("Policy name cannot be empty")
        elif not self.name.replace("_", "").replace("-", "").isalnum():
            errors.append(
                f"Policy name '{self.name}' must be alphanumeric "
                "(underscores and hyphens allowed)"
            )

        # 2. Validate version_id
        if not self.version_id:
            errors.append("Policy version_id cannot be empty")

        # 3. Validate mutual exclusivity
        if self.blocking and self.observe_only:
            errors.append("Cannot be both blocking and observe_only")

        # 4. Validate rate limit config
        if self.rate_limit:
            if self.rate_limit_count <= 0:
                errors.append("rate_limit_count must be positive")
            if self.rate_limit_window <= 0:
                errors.append("rate_limit_window must be positive")

        # 5. Validate audit level
        if self.audit and self.audit_level not in ["basic", "detailed"]:
            errors.append("audit_level must be 'basic' or 'detailed'")

        # 6. Validate fraud threshold
        if self.fraud_check:
            if not 0 <= self.fraud_threshold <= 100:
                errors.append("fraud_threshold must be 0-100")

        # 7. Validate roles requirement
        if self.requires_roles and not self.requires_auth:
            errors.append("requires_roles needs requires_auth=True")

        # 8. REQUIREMENT 2: Fail-Open Guardrails
        if self.route_classification in [
            RouteClassification.CRITICAL,
            RouteClassification.PRIVILEGED,
            RouteClassification.AUTHENTICATED
        ]:
            if self.failure_mode == FailureMode.FAIL_OPEN:
                errors.append(
                    f"Route classification '{self.route_classification.value}' "
                    f"cannot use FAIL_OPEN mode (security violation)"
                )

        # 9. Auth-required policies must fail-closed
        if self.requires_auth and self.failure_mode == FailureMode.FAIL_OPEN:
            errors.append(
                "Policies with requires_auth=True must use FAIL_CLOSED mode"
            )

        # 10. Validate step configurations (R3, R6)
        step_errors = self._validate_steps()
        errors.extend(step_errors)

        return errors

    def _validate_steps(self) -> List[str]:
        """
        REQUIREMENT 3: Policy Validation Engine
        REQUIREMENT 6: Deterministic Execution Ordering

        FIX 4: Steps no longer need to be sequential (0, 1, 2...).
        Gaps are allowed and intentional — they let you insert new steps
        between existing ones without renumbering the whole pipeline.
        Only uniqueness and non-negative values are enforced.
        """
        errors = []

        if not self.step_configs:
            return errors

        # Check for duplicate names
        names = [s.name for s in self.step_configs]
        if len(names) != len(set(names)):
            duplicates = {n for n in names if names.count(n) > 1}
            errors.append(f"Duplicate step names: {duplicates}")

        # Check for duplicate execution orders
        orders = [s.execution_order for s in self.step_configs]
        if len(orders) != len(set(orders)):
            duplicates = {o for o in orders if orders.count(o) > 1}
            errors.append(f"Duplicate execution_order values: {duplicates}")

        # NOTE: We no longer require orders to be sequential 0,1,2,...
        # Gaps (e.g. 0, 10, 20) are valid and encouraged for future extensibility.
        # get_ordered_steps() uses sort, so execution order is always deterministic.

        # REQUIREMENT 4: Critical Step Protection
        if self.requires_auth:
            has_critical = any(
                s.priority_tier == StepPriority.CRITICAL
                for s in self.step_configs
            )
            if not has_critical:
                errors.append(
                    "Auth-required policy must have at least one CRITICAL step"
                )

        return errors

    def _compute_hash(self) -> str:
        """
        REQUIREMENT 9: Policy Versioning

        Compute immutable content hash for this policy.
        Used to detect configuration changes.
        """
        content = {
            'name': self.name,
            'version_id': self.version_id,
            'route_classification': self.route_classification.value,
            'requires_auth': self.requires_auth,
            'requires_roles': sorted(self.requires_roles),
            'rate_limit': self.rate_limit,
            'rate_limit_count': self.rate_limit_count,
            'rate_limit_window': self.rate_limit_window,
            'audit': self.audit,
            'audit_level': self.audit_level,
            'fraud_check': self.fraud_check,
            'fraud_threshold': self.fraud_threshold,
            'blocking': self.blocking,
            'observe_only': self.observe_only,
            'failure_mode': self.failure_mode.value,
            'step_configs': [
                {
                    'name': s.name,
                    'priority_tier': s.priority_tier.value,
                    'execution_order': s.execution_order,
                    'timeout_seconds': s.timeout_seconds,
                    'retry_attempts': s.retry_attempts,
                    'can_skip': s.can_skip
                }
                for s in sorted(self.step_configs, key=lambda x: x.execution_order)
            ]
        }

        json_str = json.dumps(content, sort_keys=True)
        return hashlib.sha256(json_str.encode()).hexdigest()[:16]

    def get_ordered_steps(self) -> List[StepConfig]:
        """
        REQUIREMENT 6: Deterministic Execution Ordering

        Return steps in deterministic execution order.
        Sorting by execution_order is the source of truth — list position is irrelevant.
        """
        return sorted(self.step_configs, key=lambda s: s.execution_order)

    def __hash__(self):
        """
        FIX 5: Hash now includes version_hash (content fingerprint).
        Previously only name+version_id were used, so two policies with the
        same name/version but different content had the same hash — wrong.
        """
        return hash((self.name, self.version_id, self.version_hash))

    def __eq__(self, other):
        """
        FIX 5: Equality now checks content hash, not just name+version.
        Two policies are only equal if their full content is identical.
        """
        if not isinstance(other, Policy):
            return False
        return (
            self.name == other.name and
            self.version_id == other.version_id and
            self.version_hash == other.version_hash
        )

    def __lt__(self, other):
        """Enable sorting policies."""
        if not isinstance(other, Policy):
            return NotImplemented
        return (self.name, self.version_id) < (other.name, other.version_id)

    def to_dict(self) -> Dict[str, Any]:
        """Convert policy to dictionary for serialization."""
        return {
            'name': self.name,
            'version_id': self.version_id,
            'version_hash': self.version_hash,
            'deployed_at': self.deployed_at,
            'route_classification': self.route_classification.value,
            'requires_auth': self.requires_auth,
            'requires_roles': list(self.requires_roles),
            'rate_limit': self.rate_limit,
            'rate_limit_count': self.rate_limit_count,
            'rate_limit_window': self.rate_limit_window,
            'audit': self.audit,
            'audit_level': self.audit_level,
            'fraud_check': self.fraud_check,
            'fraud_threshold': self.fraud_threshold,
            'blocking': self.blocking,
            'observe_only': self.observe_only,
            'failure_mode': self.failure_mode.value,
            'step_configs': [
                {
                    'name': s.name,
                    'priority_tier': s.priority_tier.value,
                    'execution_order': s.execution_order,
                    'timeout_seconds': s.timeout_seconds,
                    'retry_attempts': s.retry_attempts,
                    'can_skip': s.can_skip
                }
                for s in self.step_configs
            ],
            'metadata': self.metadata,
            'change_history': list(self.change_history)
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Policy':
        """Create policy from dictionary."""
        data = dict(data)  # don't mutate caller's dict

        if 'requires_roles' in data and isinstance(data['requires_roles'], list):
            data['requires_roles'] = frozenset(data['requires_roles'])

        if 'failure_mode' in data and isinstance(data['failure_mode'], str):
            data['failure_mode'] = FailureMode(data['failure_mode'])

        if 'route_classification' in data and isinstance(data['route_classification'], str):
            data['route_classification'] = RouteClassification(data['route_classification'])

        if 'step_configs' in data:
            steps = []
            for step_data in data['step_configs']:
                step_data = dict(step_data)
                if isinstance(step_data['priority_tier'], str):
                    step_data['priority_tier'] = StepPriority(step_data['priority_tier'])
                steps.append(StepConfig(**step_data))
            data['step_configs'] = tuple(steps)

        if 'change_history' in data and isinstance(data['change_history'], list):
            data['change_history'] = tuple(data['change_history'])

        return cls(**data)


# =============================================================================
# PREDEFINED POLICIES (Production-Ready)
# Note: execution_order uses gaps (0, 10, 20...) so new steps can be inserted
# between existing ones without renumbering.
# =============================================================================

def _create_step_config(
    name: str,
    priority: StepPriority,
    order: int,
    timeout: float = 5.0,
    can_skip: bool = False
) -> StepConfig:
    """Helper to create step configurations."""
    return StepConfig(
        name=name,
        priority_tier=priority,
        execution_order=order,
        timeout_seconds=timeout,
        can_skip=can_skip
    )


PUBLIC_POLICY = Policy(
    name="public",
    version_id="1.0.0",
    route_classification=RouteClassification.PUBLIC,
    requires_auth=False,
    rate_limit=True,
    rate_limit_count=100,
    rate_limit_window=60,
    audit=False,
    failure_mode=FailureMode.FAIL_CLOSED,
    step_configs=(
        _create_step_config("rate_limit", StepPriority.REQUIRED, 0, timeout=2.0),
    ),
    metadata={"description": "Public endpoints with rate limiting"},
    change_history=("Initial version",)
)

AUTHENTICATED_POLICY = Policy(
    name="authenticated",
    version_id="1.0.0",
    route_classification=RouteClassification.AUTHENTICATED,
    requires_auth=True,
    rate_limit=True,
    rate_limit_count=1000,
    rate_limit_window=60,
    audit=True,
    audit_level="basic",
    failure_mode=FailureMode.FAIL_CLOSED,
    step_configs=(
        _create_step_config("auth", StepPriority.CRITICAL, 0, timeout=3.0),
        _create_step_config("rate_limit", StepPriority.REQUIRED, 10, timeout=2.0),
        _create_step_config("audit", StepPriority.OPTIONAL, 20, timeout=1.0, can_skip=True),
    ),
    metadata={"description": "Authenticated users with basic audit"},
    change_history=("Initial version",)
)

CRITICAL_POLICY = Policy(
    name="critical",
    version_id="1.0.0",
    route_classification=RouteClassification.CRITICAL,
    requires_auth=True,
    rate_limit=True,
    rate_limit_count=100,
    rate_limit_window=60,
    audit=True,
    audit_level="detailed",
    fraud_check=True,
    fraud_threshold=70,
    failure_mode=FailureMode.FAIL_CLOSED,
    step_configs=(
        _create_step_config("auth", StepPriority.CRITICAL, 0, timeout=3.0),
        _create_step_config("authorization", StepPriority.CRITICAL, 10, timeout=2.0),
        _create_step_config("rate_limit", StepPriority.REQUIRED, 20, timeout=2.0),
        _create_step_config("fraud_check", StepPriority.REQUIRED, 30, timeout=5.0),
        _create_step_config("audit", StepPriority.OPTIONAL, 40, timeout=1.0, can_skip=True),
    ),
    metadata={"description": "Critical operations with full security"},
    change_history=("Initial version",)
)

ADMIN_POLICY = Policy(
    name="admin",
    version_id="1.0.0",
    route_classification=RouteClassification.PRIVILEGED,
    requires_auth=True,
    requires_roles=frozenset({"admin"}),
    rate_limit=True,
    rate_limit_count=500,
    rate_limit_window=60,
    audit=True,
    audit_level="detailed",
    failure_mode=FailureMode.FAIL_CLOSED,
    step_configs=(
        _create_step_config("auth", StepPriority.CRITICAL, 0, timeout=3.0),
        _create_step_config("role_check", StepPriority.CRITICAL, 10, timeout=2.0),
        _create_step_config("rate_limit", StepPriority.REQUIRED, 20, timeout=2.0),
        _create_step_config("audit", StepPriority.REQUIRED, 30, timeout=1.0),
    ),
    metadata={"description": "Admin-only operations"},
    change_history=("Initial version",)
)

OBSERVE_POLICY = Policy(
    name="observe",
    version_id="1.0.0",
    route_classification=RouteClassification.PUBLIC,
    requires_auth=False,
    rate_limit=False,
    audit=True,
    audit_level="basic",
    blocking=False,
    observe_only=True,
    failure_mode=FailureMode.FAIL_OPEN,
    step_configs=(
        _create_step_config("audit", StepPriority.OBSERVATIONAL, 0, timeout=1.0, can_skip=True),
    ),
    metadata={"description": "Non-blocking observation only"},
    change_history=("Initial version",)
)

DEFAULT_POLICY = AUTHENTICATED_POLICY
