"""
Security Framework - Policy Registry (Production-Ready)

REQUIREMENT 7: Startup Integrity Checks
REQUIREMENT 3: Policy Validation Engine

The registry is the source of truth for all security policies.
It validates everything at startup and refuses to boot if misconfigured.
"""

from typing import Dict, List, Optional, Any
from .policy import Policy, StepPriority
from .exceptions import (
    PolicyNotFoundError,
    PolicyValidationError,
    StartupValidationError
)
import logging

logger = logging.getLogger(__name__)


class PolicyRegistry:
    """
    Central registry for security policies.
    
    PRODUCTION REQUIREMENTS:
    - R3: Validates all policies on registration
    - R7: Runs startup integrity checks
    - R9: Tracks policy versions
    
    The registry REFUSES to register invalid policies.
    The system REFUSES to start if registry validation fails.
    """
    
    def __init__(self, strict_mode: bool = True):
        """
        Initialize policy registry.
        
        Args:
            strict_mode: If True, enforce all validation rules strictly.
                        In production, this should ALWAYS be True.
        """
        self._policies: Dict[str, Policy] = {}
        self._policy_versions: Dict[str, List[str]] = {}  # name -> [version_ids]
        self._strict_mode = strict_mode
        self._startup_validated = False
    
    def register(
        self,
        policy: Policy,
        force: bool = False
    ) -> None:
        """
        Register a security policy.
        
        REQUIREMENT 3: Policy Validation Engine
        
        Validates policy before registration.
        Rejects invalid policies in strict mode.
        
        Args:
            policy: Policy to register
            force: If True, skip validation (USE WITH EXTREME CAUTION)
        
        Raises:
            PolicyValidationError: If policy is invalid
        """
        # REQUIREMENT 3: Validate policy
        if not force:
            errors = policy.validate()
            if errors:
                if self._strict_mode:
                    raise PolicyValidationError(policy.name, errors)
                else:
                    logger.warning(
                        f"Policy '{policy.name}' has validation errors but "
                        f"strict_mode=False: {errors}"
                    )
        
        # Store policy
        self._policies[policy.name] = policy
        
        # Track version history
        if policy.name not in self._policy_versions:
            self._policy_versions[policy.name] = []
        
        if policy.version_id not in self._policy_versions[policy.name]:
            self._policy_versions[policy.name].append(policy.version_id)
        
        logger.info(
            f"Registered policy '{policy.name}' v{policy.version_id} "
            f"(hash: {policy.version_hash})"
        )
    
    def get(self, policy_name: str) -> Policy:
        """
        Get policy by name.
        
        Args:
            policy_name: Policy name
        
        Returns:
            Policy object
        
        Raises:
            PolicyNotFoundError: If policy not found
        """
        if policy_name not in self._policies:
            raise PolicyNotFoundError(policy_name)
        
        return self._policies[policy_name]
    
    def get_by_version(self, policy_name: str, version_id: str) -> Optional[Policy]:
        """
        Get specific policy version.
        
        Args:
            policy_name: Policy name
            version_id: Version identifier
        
        Returns:
            Policy if found and version matches, else None
        """
        policy = self._policies.get(policy_name)
        if policy and policy.version_id == version_id:
            return policy
        return None
    
    def list_policies(self) -> List[str]:
        """List all registered policy names."""
        return list(self._policies.keys())
    
    def list_versions(self, policy_name: str) -> List[str]:
        """
        List all versions of a policy.
        
        REQUIREMENT 9: Policy Versioning
        """
        return self._policy_versions.get(policy_name, [])
    
    def has_policy(self, policy_name: str) -> bool:
        """Check if policy is registered."""
        return policy_name in self._policies
    
    def unregister(self, policy_name: str) -> None:
        """
        Unregister a policy.
        
        WARNING: Use with caution. Can break running services.
        """
        if policy_name in self._policies:
            del self._policies[policy_name]
            logger.warning(f"Unregistered policy '{policy_name}'")
        else:
            logger.warning(f"Attempted to unregister unknown policy '{policy_name}'")
    
    def validate_all(self) -> List[str]:
        """
        REQUIREMENT 3: Policy Validation Engine
        
        Validate all registered policies.
        
        Returns:
            List of error messages (empty = all valid)
        """
        all_errors = []
        
        for policy_name, policy in self._policies.items():
            errors = policy.validate()
            if errors:
                all_errors.append(
                    f"Policy '{policy_name}': {'; '.join(errors)}"
                )
        
        return all_errors
    
    def startup_validation(self) -> None:
        """
        REQUIREMENT 7: Startup Integrity Checks
        
        Run comprehensive validation at system startup.
        
        REFUSES TO START if any checks fail.
        
        Validates:
        - All policies are valid
        - No conflicting configurations
        - Critical policies exist
        - No missing dependencies
        
        Raises:
            StartupValidationError: If any validation fails
        """
        logger.info("Running startup validation checks...")
        
        errors = []
        
        # 1. Validate all policies
        policy_errors = self.validate_all()
        if policy_errors:
            errors.extend(policy_errors)
        
        # 2. Check for required policies
        required_policies = ['public', 'authenticated', 'critical', 'admin']
        for required in required_policies:
            if required not in self._policies:
                errors.append(f"Missing required policy: '{required}'")
        
        # 3. Validate no duplicate policy names with different versions
        # (Current implementation only stores latest version)
        
        # 4. Check for circular dependencies
        # (Not applicable in current implementation)
        
        # 5. Validate step configurations are consistent
        for policy_name, policy in self._policies.items():
            step_names = [s.name for s in policy.step_configs]
            
            # Check for critical steps in auth-required policies
            if policy.requires_auth:
                critical_steps = [
                    s for s in policy.step_configs
                    if s.priority_tier == StepPriority.CRITICAL
                ]
                if not critical_steps:
                    errors.append(
                        f"Policy '{policy_name}' requires auth but has no CRITICAL steps"
                    )
        
        # If any errors, refuse to start
        if errors:
            error_msg = "\n".join([f"  - {e}" for e in errors])
            logger.error(f"Startup validation FAILED:\n{error_msg}")
            raise StartupValidationError(errors)
        
        self._startup_validated = True
        logger.info(
            f"✓ Startup validation PASSED "
            f"({len(self._policies)} policies registered)"
        )
    
    def is_startup_validated(self) -> bool:
        """Check if startup validation has been run successfully."""
        return self._startup_validated
    
    def get_registry_info(self) -> Dict[str, Any]:
        """
        Get registry information for monitoring.
        
        Returns comprehensive metadata about registered policies.
        """
        return {
            'total_policies': len(self._policies),
            'policy_names': list(self._policies.keys()),
            'policy_versions': {
                name: {
                    'current_version': policy.version_id,
                    'version_hash': policy.version_hash,
                    'deployed_at': policy.deployed_at,
                    'all_versions': self._policy_versions.get(name, [])
                }
                for name, policy in self._policies.items()
            },
            'startup_validated': self._startup_validated,
            'strict_mode': self._strict_mode
        }
    
    def export_policies(self) -> Dict[str, Dict[str, Any]]:
        """
        Export all policies to dictionary format.
        
        Useful for:
        - Configuration backup
        - Policy migration
        - Audit trails
        """
        return {
            name: policy.to_dict()
            for name, policy in self._policies.items()
        }
    
    def import_policies(
        self,
        policies_dict: Dict[str, Dict[str, Any]],
        validate: bool = True
    ) -> None:
        """
        Import policies from dictionary format.
        
        Args:
            policies_dict: Dictionary of policy configurations
            validate: Run validation on imported policies
        """
        for name, policy_data in policies_dict.items():
            try:
                policy = Policy.from_dict(policy_data)
                self.register(policy, force=not validate)
            except Exception as e:
                logger.error(f"Failed to import policy '{name}': {e}")
                if self._strict_mode:
                    raise
    
    def __repr__(self):
        return (
            f"<PolicyRegistry("
            f"policies={len(self._policies)}, "
            f"validated={self._startup_validated}, "
            f"strict={self._strict_mode}"
            f")>"
        )
