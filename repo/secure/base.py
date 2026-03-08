"""
Security Framework - Security Steps Base Classes

REQUIREMENT 10: Concurrency Safety

Steps must be stateless or explicitly synchronized.
No shared mutable state across requests.
"""

from abc import ABC, abstractmethod
from typing import Any, Optional
import logging

logger = logging.getLogger(__name__)


class SecurityStep(ABC):
    """
    Base class for all security steps.
    
    REQUIREMENT 10: Concurrency Safety
    Steps must be STATELESS or explicitly thread-safe.
    
    Each step is a pure function:
    - No shared mutable state
    - No side effects except logging
    - Thread-safe by design
    """
    
    def __init__(self, name: str):
        """
        Initialize security step.
        
        Args:
            name: Step name (must match StepConfig.name)
        """
        self.name = name
        self._enabled = True
    
    @abstractmethod
    def execute(self, request: Any) -> None:
        """
        Execute security check.
        
        This is called during the blocking request phase.
        
        Args:
            request: Request object
        
        Raises:
            SecurityException: If check fails
        """
        pass
    
    def is_enabled(self) -> bool:
        """Check if step is enabled."""
        return self._enabled
    
    def enable(self) -> None:
        """Enable this step."""
        self._enabled = True
        logger.info(f"Step '{self.name}' enabled")
    
    def disable(self) -> None:
        """
        Disable this step.
        
        WARNING: Disabling security steps is dangerous.
        Only use for emergency troubleshooting.
        """
        self._enabled = False
        logger.warning(f"Step '{self.name}' DISABLED - security is reduced")
    
    def __repr__(self):
        return f"<{self.__class__.__name__}(name='{self.name}', enabled={self._enabled})>"


class SkipRemainingSteps(Exception):
    """
    Signal to skip remaining steps in pipeline.
    
    REQUIREMENT 4: Can only skip steps with can_skip=True.
    CRITICAL steps cannot be skipped.
    
    Example:
        If user is admin, skip rate limiting:
        
        if user.is_admin:
            raise SkipRemainingSteps("Admin bypass")
    """
    
    def __init__(self, reason: str = "Skipping remaining steps"):
        super().__init__(reason)
        self.reason = reason


class NoOpStep(SecurityStep):
    """
    No-operation step for testing and placeholders.
    
    Always passes, does nothing.
    """
    
    def execute(self, request: Any) -> None:
        """Do nothing."""
        logger.debug(f"NoOpStep '{self.name}' executed")
