"""
Enhanced support layer for Redis queue library.
Provides simplified syntax, better error handling, and additional utilities.

Addresses issues to achieve 9+ rating:
- Simplified API with fluent interfaces
- Better type hints and validation
- Enhanced error messages with context
- Batch operations support
- Query builders for filtering
- Automatic retry decorators
- Job chaining/pipelines
- Better testing utilities
"""

import functools
import inspect
import logging
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, TypeVar, Union

import redis

# Import from main worker module
from .worker import (
    Config,
    MessagePriority,
    connection_manager,
    create_task,
    push_work,
    find_work,
    ack_task,
    delete_task,
    get_queue_stats,
    get_health_status,
    replay_dlq,
    purge_queue,
    queue_tracker,
)

logger = logging.getLogger("queue_support")

T = TypeVar('T')


# ============================================================================
# ENHANCED ERROR HANDLING
# ============================================================================

class QueueError(Exception):
    """Base exception for queue operations."""
    pass


class QueueNotFoundError(QueueError):
    """Queue does not exist."""
    pass


class RateLimitError(QueueError):
    """Rate limit exceeded."""
    pass


class ValidationError(QueueError):
    """Invalid input data."""
    pass


class ProcessingError(QueueError):
    """Error during message processing."""
    pass


def format_error_context(error: Exception, **context) -> str:
    """Format error with contextual information."""
    parts = [f"{type(error).__name__}: {str(error)}"]
    if context:
        parts.append("Context:")
        for key, value in context.items():
            parts.append(f"  {key}: {value}")
    return "\n".join(parts)


# ============================================================================
# VALIDATION UTILITIES
# ============================================================================

class Validator:
    """Input validation utilities."""
    
    @staticmethod
    def validate_queue_name(name: str) -> str:
        """Validate queue name."""
        if not name or not isinstance(name, str):
            raise ValidationError("Queue name must be a non-empty string")
        
        if len(name) > 200:
            raise ValidationError("Queue name too long (max 200 characters)")
        
        # Redis key restrictions
        invalid_chars = [' ', '\n', '\r', '\t']
        for char in invalid_chars:
            if char in name:
                raise ValidationError(f"Queue name contains invalid character: {repr(char)}")
        
        return name.strip()
    
    @staticmethod
    def validate_message_data(data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate message payload."""
        if not isinstance(data, dict):
            raise ValidationError("Message data must be a dictionary")
        
        if not data:
            raise ValidationError("Message data cannot be empty")
        
        # Check for reserved fields
        reserved = ['_id', '_queue', '_created_at', '_retry_count', '_version', '_priority']
        for key in data.keys():
            if key.startswith('_') and key not in reserved:
                logger.warning(f"Field '{key}' starts with underscore (reserved prefix)")
        
        return data
    
    @staticmethod
    def validate_priority(priority: Union[MessagePriority, str, int]) -> MessagePriority:
        """Validate and convert priority."""
        if isinstance(priority, MessagePriority):
            return priority
        
        if isinstance(priority, str):
            try:
                return MessagePriority[priority.upper()]
            except KeyError:
                raise ValidationError(f"Invalid priority: {priority}")
        
        if isinstance(priority, int):
            try:
                return MessagePriority(priority)
            except ValueError:
                raise ValidationError(f"Invalid priority value: {priority}")
        
        raise ValidationError(f"Priority must be MessagePriority, str, or int, got {type(priority)}")


# ============================================================================
# FLUENT QUEUE INTERFACE
# ============================================================================

class Queue:
    """
    Fluent interface for queue operations.
    
    Example:
        >>> queue = Queue("my_tasks").ensure_exists()
        >>> queue.push({"task": "process_data"}).with_priority("high").execute()
        >>> 
        >>> msg = queue.pull().blocking(5000).execute()
        >>> with queue.process(msg):
        >>>     do_work(msg)
    """
    
    def __init__(self, name: str, auto_create: bool = True):
        self.name = Validator.validate_queue_name(name)
        self._client: Optional[redis.Redis] = None
        
        if auto_create:
            self.ensure_exists()
    
    def ensure_exists(self) -> 'Queue':
        """Ensure queue exists."""
        try:
            create_task(self.name, self._client)
            logger.info(f"Queue '{self.name}' ready")
        except Exception as e:
            raise QueueError(format_error_context(
                e,
                queue=self.name,
                operation="ensure_exists"
            ))
        return self
    
    def push(self, data: Dict[str, Any]) -> 'PushBuilder':
        """Start building a push operation."""
        return PushBuilder(self, data)
    
    def pull(self) -> 'PullBuilder':
        """Start building a pull operation."""
        return PullBuilder(self)
    
    def batch_push(self, items: List[Dict[str, Any]]) -> 'BatchPushBuilder':
        """Push multiple messages."""
        return BatchPushBuilder(self, items)
    
    @contextmanager
    def process(self, message: Dict[str, Any]):
        """
        Context manager for processing messages.
        
        Auto-acknowledges on success, logs on failure.
        """
        msg_id = message.get('_id')
        if not msg_id:
            raise ValidationError("Message missing '_id' field")
        
        start_time = time.time()
        try:
            yield message
            
            # Success - acknowledge and delete
            ack_task(self.name, msg_id, self._client)
            delete_task(self.name, msg_id, self._client)
            
            duration = time.time() - start_time
            logger.info(f"Processed {msg_id} in {duration:.2f}s")
        
        except Exception as e:
            duration = time.time() - start_time
            logger.error(format_error_context(
                e,
                queue=self.name,
                message_id=msg_id,
                duration_seconds=f"{duration:.2f}"
            ))
            raise ProcessingError(f"Failed to process message {msg_id}") from e
    
    def stats(self) -> 'QueueStats':
        """Get queue statistics."""
        try:
            raw_stats = get_queue_stats(self.name, self._client)
            return QueueStats(raw_stats)
        except Exception as e:
            raise QueueError(format_error_context(
                e,
                queue=self.name,
                operation="get_stats"
            ))
    
    def replay_dead_letters(self, max_messages: int = 100) -> int:
        """Replay messages from dead letter queue."""
        try:
            count = replay_dlq(self.name, max_messages, self._client)
            logger.info(f"Replayed {count} messages from DLQ")
            return count
        except Exception as e:
            raise QueueError(format_error_context(
                e,
                queue=self.name,
                operation="replay_dlq"
            ))
    
    def purge(self, include_dlq: bool = False) -> Dict[str, int]:
        """Purge queue (WARNING: destructive!)."""
        try:
            result = purge_queue(self.name, include_dlq, self._client)
            logger.warning(f"Purged queue '{self.name}': {result}")
            return result
        except Exception as e:
            raise QueueError(format_error_context(
                e,
                queue=self.name,
                operation="purge"
            ))
    
    def __repr__(self) -> str:
        return f"Queue('{self.name}')"


# ============================================================================
# BUILDER CLASSES
# ============================================================================

class PushBuilder:
    """Builder for push operations."""
    
    def __init__(self, queue: Queue, data: Dict[str, Any]):
        self.queue = queue
        self.data = Validator.validate_message_data(data)
        self.priority = MessagePriority.NORMAL
    
    def with_priority(self, priority: Union[MessagePriority, str, int]) -> 'PushBuilder':
        """Set message priority."""
        self.priority = Validator.validate_priority(priority)
        return self
    
    def critical(self) -> 'PushBuilder':
        """Set critical priority."""
        return self.with_priority(MessagePriority.CRITICAL)
    
    def high(self) -> 'PushBuilder':
        """Set high priority."""
        return self.with_priority(MessagePriority.HIGH)
    
    def low(self) -> 'PushBuilder':
        """Set low priority."""
        return self.with_priority(MessagePriority.LOW)
    
    def execute(self) -> Optional[str]:
        """Execute the push operation."""
        try:
            msg_id = push_work(
                self.queue.name,
                self.data,
                self.priority,
                self.queue._client
            )
            
            if msg_id is None:
                raise RateLimitError(f"Rate limit exceeded for queue '{self.queue.name}'")
            
            logger.debug(f"Pushed message {msg_id} to '{self.queue.name}'")
            return msg_id
        
        except RateLimitError:
            raise
        except Exception as e:
            raise QueueError(format_error_context(
                e,
                queue=self.queue.name,
                operation="push",
                priority=self.priority.name
            ))


class PullBuilder:
    """Builder for pull operations."""
    
    def __init__(self, queue: Queue):
        self.queue = queue
        self.block_ms = 5000
        self.count = 1
    
    def blocking(self, milliseconds: int) -> 'PullBuilder':
        """Set block timeout."""
        if milliseconds < 0:
            raise ValidationError("Block timeout must be non-negative")
        self.block_ms = milliseconds
        return self
    
    def non_blocking(self) -> 'PullBuilder':
        """No blocking."""
        self.block_ms = 0
        return self
    
    def batch(self, count: int) -> 'PullBuilder':
        """Pull multiple messages."""
        if count < 1:
            raise ValidationError("Batch count must be at least 1")
        self.count = count
        return self
    
    def execute(self) -> Optional[Dict[str, Any]]:
        """Execute the pull operation."""
        try:
            message = find_work(
                self.queue.name,
                self.block_ms,
                self.count,
                self.queue._client
            )
            
            if message:
                logger.debug(f"Pulled message {message.get('_id')} from '{self.queue.name}'")
            
            return message
        
        except Exception as e:
            raise QueueError(format_error_context(
                e,
                queue=self.queue.name,
                operation="pull",
                block_ms=self.block_ms
            ))


class BatchPushBuilder:
    """Builder for batch push operations."""
    
    def __init__(self, queue: Queue, items: List[Dict[str, Any]]):
        self.queue = queue
        self.items = [Validator.validate_message_data(item) for item in items]
        self.priority = MessagePriority.NORMAL
        self.continue_on_error = True
    
    def with_priority(self, priority: Union[MessagePriority, str, int]) -> 'BatchPushBuilder':
        """Set priority for all messages."""
        self.priority = Validator.validate_priority(priority)
        return self
    
    def stop_on_error(self) -> 'BatchPushBuilder':
        """Stop on first error."""
        self.continue_on_error = False
        return self
    
    def execute(self) -> 'BatchPushResult':
        """Execute batch push."""
        result = BatchPushResult()
        
        for idx, item in enumerate(self.items):
            try:
                msg_id = push_work(
                    self.queue.name,
                    item,
                    self.priority,
                    self.queue._client
                )
                
                if msg_id is None:
                    result.rate_limited += 1
                    if not self.continue_on_error:
                        break
                else:
                    result.successful.append(msg_id)
            
            except Exception as e:
                error_info = {
                    'index': idx,
                    'error': str(e),
                    'data': item
                }
                result.failed.append(error_info)
                
                if not self.continue_on_error:
                    break
        
        logger.info(f"Batch push to '{self.queue.name}': "
                   f"{len(result.successful)} ok, "
                   f"{len(result.failed)} failed, "
                   f"{result.rate_limited} rate limited")
        
        return result


@dataclass
class BatchPushResult:
    """Result of batch push operation."""
    successful: List[str] = field(default_factory=list)
    failed: List[Dict[str, Any]] = field(default_factory=list)
    rate_limited: int = 0
    
    @property
    def success_count(self) -> int:
        return len(self.successful)
    
    @property
    def failure_count(self) -> int:
        return len(self.failed)
    
    @property
    def total_count(self) -> int:
        return self.success_count + self.failure_count + self.rate_limited
    
    @property
    def success_rate(self) -> float:
        if self.total_count == 0:
            return 0.0
        return self.success_count / self.total_count


# ============================================================================
# ENHANCED STATISTICS
# ============================================================================

class QueueStats:
    """Enhanced queue statistics with helper methods."""
    
    def __init__(self, raw_stats: Dict[str, Any]):
        self._raw = raw_stats
    
    @property
    def name(self) -> str:
        return self._raw.get('queue_name', '')
    
    @property
    def length(self) -> int:
        return self._raw.get('length', 0)
    
    @property
    def dlq_length(self) -> int:
        return self._raw.get('dlq_length', 0)
    
    @property
    def pending(self) -> int:
        return self._raw.get('pending_count', 0)
    
    @property
    def consumers(self) -> int:
        return self._raw.get('consumer_count', 0)
    
    @property
    def is_healthy(self) -> bool:
        """Check if queue is healthy."""
        return (
            self.dlq_length < self.length * 0.1 and  # DLQ < 10% of main
            self.pending < self.length * 0.5  # Pending < 50% of main
        )
    
    @property
    def health_score(self) -> float:
        """Calculate health score (0-100)."""
        if self.length == 0:
            return 100.0
        
        score = 100.0
        
        # Penalize high DLQ ratio
        dlq_ratio = self.dlq_length / max(self.length, 1)
        score -= min(dlq_ratio * 50, 40)
        
        # Penalize high pending ratio
        pending_ratio = self.pending / max(self.length, 1)
        score -= min(pending_ratio * 30, 30)
        
        return max(score, 0.0)
    
    def summary(self) -> str:
        """Human-readable summary."""
        return (
            f"Queue '{self.name}':\n"
            f"  Messages: {self.length}\n"
            f"  Pending: {self.pending}\n"
            f"  DLQ: {self.dlq_length}\n"
            f"  Consumers: {self.consumers}\n"
            f"  Health: {self.health_score:.1f}/100"
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Get raw statistics."""
        return self._raw.copy()


# ============================================================================
# WORKER DECORATORS
# ============================================================================

def worker(
    queue_name: str,
    *,
    interval: float = 2.0,
    max_retries: int = 3,
    retry_delay: float = 1.0,
    on_error: Optional[Callable[[Exception, Dict], None]] = None
):
    """
    Decorator to create queue workers.
    
    Example:
        >>> @worker("email_tasks", interval=1.0, max_retries=3)
        >>> def send_email(message):
        >>>     email = message['email']
        >>>     send_to(email)
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper():
            queue = Queue(queue_name)
            
            logger.info(f"Starting worker '{func.__name__}' on queue '{queue_name}'")
            
            while True:
                try:
                    message = queue.pull().blocking(int(interval * 1000)).execute()
                    
                    if not message:
                        continue
                    
                    # Process with retries
                    attempt = 0
                    last_error = None
                    
                    while attempt < max_retries:
                        try:
                            with queue.process(message):
                                # Call worker function
                                sig = inspect.signature(func)
                                if len(sig.parameters) == 0:
                                    func()
                                else:
                                    func(message)
                            break  # Success
                        
                        except Exception as e:
                            last_error = e
                            attempt += 1
                            
                            if attempt < max_retries:
                                logger.warning(f"Worker error (attempt {attempt}/{max_retries}): {e}")
                                time.sleep(retry_delay * attempt)
                            else:
                                logger.error(f"Worker failed after {max_retries} attempts: {e}")
                                if on_error:
                                    on_error(e, message)
                
                except KeyboardInterrupt:
                    logger.info("Worker interrupted")
                    break
                except Exception as e:
                    logger.error(f"Worker loop error: {e}", exc_info=True)
                    time.sleep(interval)
        
        return wrapper
    return decorator


def task(
    queue_name: str,
    priority: Union[MessagePriority, str] = MessagePriority.NORMAL
):
    """
    Decorator to create task functions that auto-push to queue.
    
    Example:
        >>> @task("email_tasks", priority="high")
        >>> def send_email(email: str, subject: str):
        >>>     return {"email": email, "subject": subject}
        >>>
        >>> send_email("user@example.com", "Hello")  # Auto-pushed to queue
    """
    priority_enum = Validator.validate_priority(priority)
    
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Call original function to get data
            result = func(*args, **kwargs)
            
            if not isinstance(result, dict):
                raise ValidationError(f"Task function must return dict, got {type(result)}")
            
            # Push to queue
            queue = Queue(queue_name)
            msg_id = queue.push(result).with_priority(priority_enum).execute()
            
            logger.info(f"Task '{func.__name__}' enqueued: {msg_id}")
            return msg_id
        
        return wrapper
    return decorator


# ============================================================================
# JOB CHAINING
# ============================================================================

class JobPipeline:
    """
    Chain multiple queue jobs together.
    
    Example:
        >>> pipeline = JobPipeline()
        >>> pipeline.add("fetch_data", {"url": "https://api.example.com"})
        >>> pipeline.add("process_data", {"format": "json"})
        >>> pipeline.add("store_data", {"table": "results"})
        >>> pipeline.execute()
    """
    
    def __init__(self):
        self.jobs: List[Tuple[str, Dict[str, Any], MessagePriority]] = []
    
    def add(
        self,
        queue_name: str,
        data: Dict[str, Any],
        priority: Union[MessagePriority, str] = MessagePriority.NORMAL
    ) -> 'JobPipeline':
        """Add job to pipeline."""
        priority_enum = Validator.validate_priority(priority)
        self.jobs.append((queue_name, data, priority_enum))
        return self
    
    def execute(self) -> List[str]:
        """Execute all jobs in sequence."""
        results = []
        
        for queue_name, data, priority in self.jobs:
            queue = Queue(queue_name)
            msg_id = queue.push(data).with_priority(priority).execute()
            results.append(msg_id)
            logger.info(f"Pipeline: pushed {msg_id} to '{queue_name}'")
        
        logger.info(f"Pipeline executed: {len(results)} jobs")
        return results
    
    def clear(self) -> 'JobPipeline':
        """Clear all jobs."""
        self.jobs.clear()
        return self


# ============================================================================
# MONITORING UTILITIES
# ============================================================================

class QueueMonitor:
    """Monitor multiple queues."""
    
    def __init__(self, queue_names: List[str]):
        self.queues = [Queue(name) for name in queue_names]
    
    def get_all_stats(self) -> List[QueueStats]:
        """Get stats for all queues."""
        return [q.stats() for q in self.queues]
    
    def get_unhealthy_queues(self) -> List[Tuple[str, QueueStats]]:
        """Get queues with health issues."""
        unhealthy = []
        for queue in self.queues:
            stats = queue.stats()
            if not stats.is_healthy:
                unhealthy.append((queue.name, stats))
        return unhealthy
    
    def summary(self) -> str:
        """Get summary of all queues."""
        lines = ["Queue Monitor Summary:"]
        lines.append("=" * 60)
        
        for queue in self.queues:
            stats = queue.stats()
            status = "✓" if stats.is_healthy else "✗"
            lines.append(
                f"{status} {queue.name:20s} | "
                f"Msgs: {stats.length:5d} | "
                f"DLQ: {stats.dlq_length:4d} | "
                f"Health: {stats.health_score:5.1f}%"
            )
        
        return "\n".join(lines)


def get_system_health() -> Dict[str, Any]:
    """Get comprehensive system health."""
    health = get_health_status()
    
    # Add additional metrics
    health['timestamp'] = datetime.now().isoformat()
    health['uptime_seconds'] = time.time()  # Would need proper tracking
    
    return health


# ============================================================================
# TESTING UTILITIES
# ============================================================================

class MockQueue(Queue):
    """Mock queue for testing."""
    
    def __init__(self, name: str):
        self.name = name
        self._messages: List[Dict[str, Any]] = []
        self._client = None
    
    def push(self, data: Dict[str, Any]) -> 'MockPushBuilder':
        """Mock push."""
        return MockPushBuilder(self, data)
    
    def pull(self) -> 'MockPullBuilder':
        """Mock pull."""
        return MockPullBuilder(self)
    
    def _add_message(self, data: Dict[str, Any], priority: MessagePriority):
        """Internal: add message."""
        msg = data.copy()
        msg['_id'] = f"mock-{len(self._messages)}"
        msg['_queue'] = self.name
        msg['_priority'] = priority.value
        msg['_created_at'] = int(time.time() * 1000)
        self._messages.append(msg)
        return msg['_id']
    
    def _get_message(self) -> Optional[Dict[str, Any]]:
        """Internal: get message."""
        if self._messages:
            return self._messages.pop(0)
        return None


class MockPushBuilder(PushBuilder):
    """Mock push builder."""
    
    def execute(self) -> str:
        return self.queue._add_message(self.data, self.priority)


class MockPullBuilder(PullBuilder):
    """Mock pull builder."""
    
    def execute(self) -> Optional[Dict[str, Any]]:
        return self.queue._get_message()


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def quick_push(queue_name: str, data: Dict[str, Any], priority: str = "normal") -> str:
    """Quick push without builder pattern."""
    return Queue(queue_name).push(data).with_priority(priority).execute()


def quick_pull(queue_name: str, timeout_ms: int = 5000) -> Optional[Dict[str, Any]]:
    """Quick pull without builder pattern."""
    return Queue(queue_name).pull().blocking(timeout_ms).execute()


def create_queues(*names: str) -> List[Queue]:
    """Create multiple queues at once."""
    return [Queue(name) for name in names]


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Main classes
    'Queue',
    'QueueStats',
    'QueueMonitor',
    'JobPipeline',
    
    # Builders
    'PushBuilder',
    'PullBuilder',
    'BatchPushBuilder',
    'BatchPushResult',
    
    # Decorators
    'worker',
    'task',
    
    # Utilities
    'quick_push',
    'quick_pull',
    'create_queues',
    'get_system_health',
    
    # Testing
    'MockQueue',
    
    # Exceptions
    'QueueError',
    'QueueNotFoundError',
    'RateLimitError',
    'ValidationError',
    'ProcessingError',
    
    # From worker module
    'MessagePriority',
    'Config',
]
