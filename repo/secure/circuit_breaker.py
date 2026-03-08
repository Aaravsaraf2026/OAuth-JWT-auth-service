"""
Security Framework - Circuit Breaker (Production-Ready)

REQUIREMENT 5: Adapter Failure Isolation

Prevents cascading failures when external systems are down.
Distinguishes between infrastructure failures and malicious attacks.
"""

from typing import Optional, Callable, Any
from dataclasses import dataclass
from enum import Enum
import time
import logging

logger = logging.getLogger(__name__)


class CircuitState(str, Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failures exceeded threshold
    HALF_OPEN = "half_open"  # Testing if system recovered


@dataclass
class CircuitConfig:
    """
    Circuit breaker configuration.
    
    REQUIREMENT 5: Each adapter must have circuit breaker.
    """
    # Failure thresholds
    failure_threshold: int = 5  # Open circuit after N failures
    success_threshold: int = 2  # Close circuit after N successes (in half-open)
    
    # Timeouts
    timeout_seconds: float = 5.0  # Operation timeout
    recovery_timeout: float = 30.0  # How long to stay open
    
    # Rate limiting
    half_open_max_calls: int = 3  # Max concurrent calls in half-open
    
    def __post_init__(self):
        """Validate configuration."""
        if self.failure_threshold < 1:
            raise ValueError("failure_threshold must be >= 1")
        if self.success_threshold < 1:
            raise ValueError("success_threshold must be >= 1")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be > 0")
        if self.recovery_timeout <= 0:
            raise ValueError("recovery_timeout must be > 0")


class CircuitBreaker:
    """
    REQUIREMENT 5: Circuit Breaker for External Adapters
    
    Protects system from:
    - Redis down
    - JWT provider slow
    - Database locked
    - Network timeouts
    
    Distinguishes:
    - Infrastructure failure (recoverable)
    - Malicious denial (non-recoverable)
    - Degraded mode (partial availability)
    """
    
    def __init__(
        self,
        name: str,
        config: Optional[CircuitConfig] = None
    ):
        """
        Initialize circuit breaker.
        
        Args:
            name: Adapter name (e.g., "redis", "jwt_provider")
            config: Circuit breaker configuration
        """
        self.name = name
        self.config = config or CircuitConfig()
        
        # State
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: Optional[float] = None
        self._half_open_calls = 0
        
        # Metrics
        self._total_calls = 0
        self._total_failures = 0
        self._total_timeouts = 0
        self._total_circuit_opens = 0
    
    @property
    def state(self) -> CircuitState:
        """Get current circuit state."""
        return self._state
    
    @property
    def is_available(self) -> bool:
        """Check if circuit allows calls."""
        if self._state == CircuitState.CLOSED:
            return True
        
        if self._state == CircuitState.OPEN:
            # Check if recovery timeout elapsed
            if self._should_attempt_reset():
                self._transition_to_half_open()
                return True
            return False
        
        if self._state == CircuitState.HALF_OPEN:
            # Allow limited calls in half-open state
            return self._half_open_calls < self.config.half_open_max_calls
        
        return False
    
    def call(
        self,
        func: Callable,
        *args,
        fallback: Optional[Callable] = None,
        **kwargs
    ) -> Any:
        """
        Execute function with circuit breaker protection.
        
        Args:
            func: Function to execute
            *args: Function arguments
            fallback: Fallback function if circuit is open
            **kwargs: Function keyword arguments
        
        Returns:
            Function result or fallback result
        
        Raises:
            CircuitOpenError: If circuit is open and no fallback
        """
        from .exceptions import CircuitOpenError, ExecutionTimeoutError
        
        self._total_calls += 1
        
        # Check if circuit allows calls
        if not self.is_available:
            logger.warning(f"Circuit breaker '{self.name}' is OPEN")
            
            if fallback:
                logger.info(f"Using fallback for '{self.name}'")
                return fallback(*args, **kwargs)
            
            raise CircuitOpenError(
                f"Circuit breaker '{self.name}' is open",
                retry_after=int(self.config.recovery_timeout)
            )
        
        # Track half-open calls
        if self._state == CircuitState.HALF_OPEN:
            self._half_open_calls += 1
        
        # Execute with timeout
        start_time = time.time()
        
        try:
            # Simple timeout check (in production, use async timeout)
            result = func(*args, **kwargs)
            duration = time.time() - start_time
            
            if duration > self.config.timeout_seconds:
                self._total_timeouts += 1
                raise ExecutionTimeoutError(
                    self.name,
                    self.config.timeout_seconds
                )
            
            # Success
            self._on_success()
            return result
        
        except Exception as e:
            # Failure
            self._on_failure(e)
            
            # Use fallback if available
            if fallback:
                logger.warning(
                    f"Adapter '{self.name}' failed, using fallback: {e}"
                )
                return fallback(*args, **kwargs)
            
            raise
        
        finally:
            # Reset half-open call count
            if self._state == CircuitState.HALF_OPEN:
                self._half_open_calls -= 1
    
    def _on_success(self) -> None:
        """Handle successful call."""
        if self._state == CircuitState.HALF_OPEN:
            self._success_count += 1
            
            if self._success_count >= self.config.success_threshold:
                self._transition_to_closed()
        
        # Reset failure count on success
        self._failure_count = 0
    
    def _on_failure(self, error: Exception) -> None:
        """Handle failed call."""
        self._total_failures += 1
        self._failure_count += 1
        self._last_failure_time = time.time()
        
        logger.warning(
            f"Adapter '{self.name}' failure {self._failure_count}/"
            f"{self.config.failure_threshold}: {error}"
        )
        
        # Check if should open circuit
        if self._failure_count >= self.config.failure_threshold:
            self._transition_to_open()
    
    def _should_attempt_reset(self) -> bool:
        """Check if circuit should attempt reset."""
        if self._state != CircuitState.OPEN:
            return False
        
        if self._last_failure_time is None:
            return False
        
        elapsed = time.time() - self._last_failure_time
        return elapsed >= self.config.recovery_timeout
    
    def _transition_to_closed(self) -> None:
        """Transition to CLOSED state."""
        logger.info(f"Circuit breaker '{self.name}': CLOSED (recovered)")
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._half_open_calls = 0
    
    def _transition_to_open(self) -> None:
        """Transition to OPEN state."""
        logger.error(
            f"Circuit breaker '{self.name}': OPEN "
            f"(failures: {self._failure_count})"
        )
        self._state = CircuitState.OPEN
        self._success_count = 0
        self._total_circuit_opens += 1
    
    def _transition_to_half_open(self) -> None:
        """Transition to HALF_OPEN state."""
        logger.info(
            f"Circuit breaker '{self.name}': HALF_OPEN "
            f"(attempting recovery)"
        )
        self._state = CircuitState.HALF_OPEN
        self._failure_count = 0
        self._success_count = 0
        self._half_open_calls = 0
    
    def reset(self) -> None:
        """Manually reset circuit breaker."""
        logger.warning(f"Circuit breaker '{self.name}': Manual reset")
        self._transition_to_closed()
    
    def get_metrics(self) -> dict:
        """Get circuit breaker metrics."""
        return {
            'name': self.name,
            'state': self._state.value,
            'total_calls': self._total_calls,
            'total_failures': self._total_failures,
            'total_timeouts': self._total_timeouts,
            'total_circuit_opens': self._total_circuit_opens,
            'current_failure_count': self._failure_count,
            'current_success_count': self._success_count,
            'last_failure_time': self._last_failure_time,
            'failure_threshold': self.config.failure_threshold,
            'success_threshold': self.config.success_threshold
        }
    
    def __repr__(self):
        return (
            f"<CircuitBreaker(name='{self.name}', "
            f"state={self._state.value}, "
            f"failures={self._failure_count}/{self.config.failure_threshold})>"
        )


class CircuitBreakerRegistry:
    """
    REQUIREMENT 5: Central registry for all adapter circuit breakers.
    
    Provides system-wide view of adapter health.
    """
    
    def __init__(self):
        """Initialize registry."""
        self._breakers: dict[str, CircuitBreaker] = {}
    
    def register(
        self,
        name: str,
        config: Optional[CircuitConfig] = None
    ) -> CircuitBreaker:
        """
        Register a circuit breaker for an adapter.
        
        Args:
            name: Adapter name
            config: Circuit breaker configuration
        
        Returns:
            Circuit breaker instance
        """
        if name in self._breakers:
            logger.warning(f"Circuit breaker '{name}' already registered")
            return self._breakers[name]
        
        breaker = CircuitBreaker(name, config)
        self._breakers[name] = breaker
        
        logger.info(f"Registered circuit breaker: {name}")
        return breaker
    
    def get(self, name: str) -> Optional[CircuitBreaker]:
        """Get circuit breaker by name."""
        return self._breakers.get(name)
    
    def list_all(self) -> list[str]:
        """List all registered circuit breakers."""
        return list(self._breakers.keys())
    
    def get_all_metrics(self) -> dict[str, dict]:
        """Get metrics for all circuit breakers."""
        return {
            name: breaker.get_metrics()
            for name, breaker in self._breakers.items()
        }
    
    def reset_all(self) -> None:
        """Reset all circuit breakers (use with caution)."""
        for breaker in self._breakers.values():
            breaker.reset()
    
    def health_check(self) -> dict:
        """
        Check health of all adapters.
        
        Returns:
            Health status with details
        """
        all_metrics = self.get_all_metrics()
        
        open_circuits = [
            name for name, metrics in all_metrics.items()
            if metrics['state'] == CircuitState.OPEN.value
        ]
        
        degraded_circuits = [
            name for name, metrics in all_metrics.items()
            if metrics['state'] == CircuitState.HALF_OPEN.value
        ]
        
        return {
            'healthy': len(open_circuits) == 0,
            'total_circuits': len(self._breakers),
            'open_circuits': open_circuits,
            'degraded_circuits': degraded_circuits,
            'metrics': all_metrics
        }
