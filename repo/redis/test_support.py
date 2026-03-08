"""
Simple wrapper layer for Redis worker library.
Makes the API super simple to use.

ENHANCEMENTS:
- Added schema validation support
- Added tracing context
- Added DLQ analysis
- Better error messages
"""

from typing import Any, Callable, Dict, Optional, Type
from worker import (
    create_task,
    push_work,
    find_work,
    ack_task,
    delete_task,
    message_context,
    always_run,
    get_health_status,
    get_queue_stats,
    analyze_dlq,
    replay_dlq,
    purge_queue,
    shutdown,
    MessagePriority,
    MessageSchema,
    ValidationError,
    Config
)


class SimpleQueue:
    """
    Super simple queue wrapper with validation support.
    
    Example:
        >>> queue = SimpleQueue("my-queue")
        >>> queue.push({"task": "send_email", "to": "user@example.com"})
        >>> job = queue.pull()
        >>> if job:
        >>>     print(job["task"])
        >>>     queue.complete(job)
        
    Example with validation:
        >>> class EmailSchema(MessageSchema):
        >>>     @classmethod
        >>>     def validate(cls, data):
        >>>         if "to" not in data or "@" not in data["to"]:
        >>>             raise ValidationError("to", "Invalid email")
        >>>         return data
        >>> 
        >>> queue = SimpleQueue("emails", schema=EmailSchema)
        >>> queue.push({"to": "user@example.com", "subject": "Hello"})
    """
    
    def __init__(
        self, 
        name: str, 
        redis_client=None,
        schema: Optional[Type[MessageSchema]] = None
    ):
        """
        Initialize queue.
        
        Args:
            name: Queue name
            redis_client: Optional Redis client
            schema: Optional validation schema
        """
        self.name = name
        self.redis_client = redis_client
        self.schema = schema
        create_task(name, redis_client)
    
    def push(
        self, 
        data: Dict[str, Any], 
        priority: str = "normal",
        correlation_id: Optional[str] = None
    ) -> Optional[str]:
        """
        Push job to queue with validation.
        
        Args:
            data: Job data dictionary
            priority: "critical", "high", "normal", or "low"
            correlation_id: Optional correlation ID for tracing
            
        Returns:
            Message ID or None if rate limited
            
        Raises:
            ValidationError: If schema validation fails
            ValueError: If data contains non-serializable objects
        """
        if not isinstance(data, dict):
            raise ValueError(f"Data must be a dictionary, got {type(data).__name__}")
        
        if not data:
            raise ValueError("Data cannot be empty")
        
        priority_map = {
            "critical": MessagePriority.CRITICAL,
            "high": MessagePriority.HIGH,
            "normal": MessagePriority.NORMAL,
            "low": MessagePriority.LOW
        }
        
        priority_enum = priority_map.get(priority.lower())
        if priority_enum is None:
            raise ValueError(
                f"Invalid priority '{priority}'. "
                f"Must be one of: {', '.join(priority_map.keys())}"
            )
        
        # Add correlation ID if provided
        if correlation_id:
            data = data.copy()
            data["_correlation_id"] = correlation_id
        
        return push_work(
            self.name, 
            data, 
            priority_enum,
            schema=self.schema,
            redis_client=self.redis_client
        )
    
    def pull(self, timeout_ms: int = 5000) -> Optional[Dict[str, Any]]:
        """
        Pull job from queue (blocking).
        
        Args:
            timeout_ms: Block timeout in milliseconds
            
        Returns:
            Job dictionary or None
        """
        return find_work(self.name, timeout_ms, 1, self.redis_client)
    
    def complete(self, job: Dict[str, Any]):
        """
        Mark job as complete.
        
        Args:
            job: Job dictionary from pull()
        """
        msg_id = job.get("_id")
        if msg_id:
            ack_task(self.name, msg_id, self.redis_client)
            delete_task(self.name, msg_id, self.redis_client)
    
    def stats(self) -> Dict[str, Any]:
        """
        Get queue statistics.
        
        Returns:
            Dictionary with queue stats including length, DLQ length, etc.
        """
        return get_queue_stats(self.name, self.redis_client)
    
    def analyze_dlq(self) -> Dict[str, Any]:
        """
        Analyze dead letter queue for failure patterns.
        
        Returns:
            Dictionary with DLQ analysis including:
            - Total count
            - Breakdown by failure reason
            - Oldest message age
            - Recent failures
        """
        return analyze_dlq(self.name, self.redis_client)
    
    def replay_failed(self, max_count: int = 100) -> int:
        """
        Replay failed messages from DLQ.
        
        Args:
            max_count: Maximum number of messages to replay
            
        Returns:
            Number of messages replayed
        """
        return replay_dlq(self.name, max_count, self.redis_client)
    
    def purge(self, include_dlq: bool = False) -> Dict[str, int]:
        """
        Purge all messages (WARNING: destructive!).
        
        Args:
            include_dlq: Also purge the dead letter queue
            
        Returns:
            Dictionary with count of purged messages
        """
        return purge_queue(self.name, include_dlq, self.redis_client)
    
    def process(self, handler: Callable[[Dict], None], interval: float = 2.0):
        """
        Process jobs continuously.
        
        Args:
            handler: Function that processes job data
            interval: Seconds between polls
        """
        def worker():
            job = self.pull(timeout_ms=int(interval * 1000))
            if job:
                try:
                    handler(job)
                    self.complete(job)
                except Exception as e:
                    print(f"Job failed: {e}")
        
        always_run(worker, interval)


class SimpleWorker:
    """
    Super simple worker wrapper.
    
    Example:
        >>> def process_job(job):
        >>>     print(f"Processing: {job['task']}")
        >>> 
        >>> worker = SimpleWorker("my-queue", process_job)
        >>> worker.start()  # Runs forever
    """
    
    def __init__(
        self, 
        queue_name: str, 
        handler: Callable[[Dict], None], 
        interval: float = 2.0, 
        redis_client=None,
        schema: Optional[Type[MessageSchema]] = None
    ):
        """
        Initialize worker.
        
        Args:
            queue_name: Queue to process
            handler: Function to process each job
            interval: Seconds between polls
            redis_client: Optional Redis client
            schema: Optional validation schema
        """
        self.queue = SimpleQueue(queue_name, redis_client, schema)
        self.handler = handler
        self.interval = interval
    
    def start(self):
        """Start processing jobs (blocks forever)."""
        self.queue.process(self.handler, self.interval)


def simple_health() -> Dict[str, Any]:
    """
    Get simple health status.
    
    Returns:
        Dictionary with health information including:
        - Redis connection status
        - Circuit breaker state
        - Active queues
        - Background service status
    """
    return get_health_status()


def simple_shutdown():
    """Shutdown gracefully."""
    shutdown()


# ============================================================================
# CONFIGURATION HELPERS
# ============================================================================

def set_redis_host(host: str):
    """Set Redis host."""
    Config.REDIS_HOST = host


def set_redis_port(port: int):
    """Set Redis port."""
    Config.REDIS_PORT = port


def set_redis_password(password: str):
    """Set Redis password."""
    Config.REDIS_PASSWORD = password


def set_redis_db(db: int):
    """Set Redis database number."""
    Config.REDIS_DB = db


def set_max_retries(retries: int):
    """Set max retry attempts before moving to DLQ."""
    Config.MAX_RETRIES = retries


def set_message_timeout(milliseconds: int):
    """Set message timeout before reclaim."""
    Config.MESSAGE_TIMEOUT_MS = milliseconds


def set_rate_limit(messages_per_second: int):
    """Set rate limit for message processing."""
    Config.MAX_MESSAGES_PER_SECOND = messages_per_second


def set_backpressure(enabled: bool, threshold: int = 5000):
    """
    Configure backpressure settings.
    
    Args:
        enabled: Whether to enable backpressure
        threshold: Queue length threshold to trigger backpressure
    """
    Config.BACKPRESSURE_ENABLED = enabled
    Config.BACKPRESSURE_THRESHOLD = threshold


def enable_ssl(enabled: bool = True):
    """Enable/disable SSL for Redis connection."""
    Config.REDIS_SSL = enabled


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Main classes
    'SimpleQueue',
    'SimpleWorker',
    
    # Utilities
    'simple_health',
    'simple_shutdown',
    
    # Configuration
    'set_redis_host',
    'set_redis_port',
    'set_redis_password',
    'set_redis_db',
    'set_max_retries',
    'set_message_timeout',
    'set_rate_limit',
    'set_backpressure',
    'enable_ssl',
    
    # For advanced users
    'MessageSchema',
    'ValidationError',
    'MessagePriority',
]