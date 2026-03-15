"""
Complete examples showing how to use the enhanced Redis queue library.
"""

from test_support import (
    SimpleQueue,
    SimpleWorker,
    MessageSchema,
    ValidationError,
    simple_health,
    simple_shutdown,
    set_redis_host,
    set_max_retries,
    set_backpressure
)


# ============================================================================
# EXAMPLE 1: Basic Usage
# ============================================================================

def example_basic():
    """Basic push/pull example."""
    print("=== Example 1: Basic Usage ===\n")
    
    # Create a queue
    queue = SimpleQueue("tasks")
    
    # Push some work
    msg_id = queue.push({
        "task": "send_email",
        "to": "user@example.com",
        "subject": "Hello World"
    })
    print(f"Pushed message: {msg_id}")
    
    # Pull and process
    job = queue.pull()
    if job:
        print(f"Processing: {job['task']}")
        queue.complete(job)
        print("Job completed!\n")


# ============================================================================
# EXAMPLE 2: With Validation Schema
# ============================================================================

class EmailSchema(MessageSchema):
    """Schema for email messages."""
    
    @classmethod
    def validate(cls, data):
        """Validate email message data."""
        required_fields = {"to", "subject", "body"}
        missing = required_fields - set(data.keys())
        
        if missing:
            raise ValidationError(
                field="required",
                message=f"Missing required fields: {', '.join(missing)}"
            )
        
        # Validate email format
        if "@" not in data["to"]:
            raise ValidationError(
                field="to",
                message=f"Invalid email address: {data['to']}"
            )
        
        # Validate subject length
        if len(data["subject"]) > 200:
            raise ValidationError(
                field="subject",
                message="Subject too long (max 200 characters)"
            )
        
        return data


def example_with_validation():
    """Example with schema validation."""
    print("=== Example 2: With Validation ===\n")
    
    # Create queue with schema
    queue = SimpleQueue("emails", schema=EmailSchema)
    
    # Valid message
    try:
        msg_id = queue.push({
            "to": "user@example.com",
            "subject": "Hello",
            "body": "This is a test email"
        })
        print(f"✓ Valid message pushed: {msg_id}")
    except ValidationError as e:
        print(f"✗ Validation failed: {e}")
    
    # Invalid message (missing body)
    try:
        queue.push({
            "to": "user@example.com",
            "subject": "Hello"
        })
        print("✓ Invalid message pushed (shouldn't happen)")
    except ValidationError as e:
        print(f"✓ Validation caught error: {e.message}\n")


# ============================================================================
# EXAMPLE 3: Priority Queues
# ============================================================================

def example_priorities():
    """Example with different priorities."""
    print("=== Example 3: Priority Queues ===\n")
    
    queue = SimpleQueue("priority-test")
    
    # Push with different priorities
    queue.push({"task": "low-priority"}, priority="low")
    queue.push({"task": "high-priority"}, priority="high")
    queue.push({"task": "critical"}, priority="critical")
    
    print("Pushed 3 messages with different priorities")
    print("(Redis Streams processes in order, but metadata is tracked)\n")


# ============================================================================
# EXAMPLE 4: Worker Pattern
# ============================================================================

def process_email(job):
    """Process an email job."""
    print(f"Sending email to: {job['to']}")
    print(f"Subject: {job['subject']}")
    # Simulate work
    import time
    time.sleep(0.1)


def example_worker():
    """Example of continuous worker."""
    print("=== Example 4: Worker Pattern ===\n")
    
    # Create queue and push some jobs
    queue = SimpleQueue("email-queue")
    for i in range(3):
        queue.push({
            "to": f"user{i}@example.com",
            "subject": f"Email {i}",
            "body": "Test email"
        })
    
    print("Pushed 3 email jobs")
    print("Starting worker (will process and exit)...\n")
    
    # Process jobs manually (in production, use worker.start() which runs forever)
    for _ in range(3):
        job = queue.pull(timeout_ms=1000)
        if job:
            process_email(job)
            queue.complete(job)
    
    print("\nAll jobs processed!\n")


# ============================================================================
# EXAMPLE 5: DLQ Analysis
# ============================================================================

def example_dlq_analysis():
    """Example of DLQ analysis."""
    print("=== Example 5: DLQ Analysis ===\n")
    
    queue = SimpleQueue("test-queue")
    
    # Get queue stats
    stats = queue.stats()
    print(f"Queue: {stats['queue_name']}")
    print(f"  Main queue length: {stats['length']}")
    print(f"  DLQ length: {stats['dlq_length']}")
    print(f"  Pending: {stats['pending_count']}")
    
    # Analyze DLQ
    if stats['dlq_length'] > 0:
        analysis = queue.analyze_dlq()
        print(f"\nDLQ Analysis:")
        print(f"  Total failed messages: {analysis['total_count']}")
        print(f"  Failure reasons:")
        for reason, count in analysis['reasons'].items():
            print(f"    - {reason}: {count}")
        
        if analysis['oldest_message_age_seconds']:
            age_hours = analysis['oldest_message_age_seconds'] / 3600
            print(f"  Oldest message: {age_hours:.1f} hours old")
        
        # Replay failed messages
        print("\n  Replaying failed messages...")
        replayed = queue.replay_failed(max_count=10)
        print(f"  Replayed {replayed} messages")
    else:
        print("  DLQ is empty")
    
    print()


# ============================================================================
# EXAMPLE 6: Health Monitoring
# ============================================================================

def example_health():
    """Example of health monitoring."""
    print("=== Example 6: Health Monitoring ===\n")
    
    health = simple_health()
    
    print(f"Redis Connected: {health['redis_connected']}")
    print(f"Circuit Breaker: {health['circuit_breaker_state']}")
    print(f"Active Queues: {len(health['tracked_queues'])}")
    
    if health['tracked_queues']:
        print(f"  Queues: {', '.join(health['tracked_queues'])}")
    
    print(f"\nBackground Services:")
    services = health['background_services']
    for name, running in services.items():
        status = "✓ Running" if running else "✗ Stopped"
        print(f"  {name}: {status}")
    
    print()


# ============================================================================
# EXAMPLE 7: Configuration
# ============================================================================

def example_configuration():
    """Example of runtime configuration."""
    print("=== Example 7: Configuration ===\n")
    
    # Configure Redis connection
    set_redis_host("localhost")
    # set_redis_port(6379)
    # set_redis_password("your-password")
    
    # Configure retry behavior
    set_max_retries(5)  # Retry up to 5 times before DLQ
    
    # Configure backpressure
    set_backpressure(
        enabled=True,
        threshold=5000  # Stop accepting new messages if queue > 5000
    )
    
    print("Configuration updated:")
    print("  Max retries: 5")
    print("  Backpressure: enabled (threshold: 5000)")
    print()


# ============================================================================
# EXAMPLE 8: Correlation IDs for Tracing
# ============================================================================

def example_tracing():
    """Example with correlation IDs for distributed tracing."""
    print("=== Example 8: Distributed Tracing ===\n")
    
    queue = SimpleQueue("traced-queue")
    
    # Push with correlation ID
    correlation_id = "order-12345"
    msg_id = queue.push(
        {
            "task": "process_order",
            "order_id": "12345"
        },
        correlation_id=correlation_id
    )
    
    print(f"Pushed with correlation_id: {correlation_id}")
    print(f"Message ID: {msg_id}")
    print("(Check logs for trace_id in structured logging)\n")


# ============================================================================
# EXAMPLE 9: Error Handling
# ============================================================================

def example_error_handling():
    """Example of proper error handling."""
    print("=== Example 9: Error Handling ===\n")
    
    queue = SimpleQueue("error-test")
    
    # Try to push invalid data
    try:
        # This will fail - functions are not JSON-serializable
        queue.push({"handler": lambda x: x})
    except ValueError as e:
        print(f"✓ Caught serialization error:")
        print(f"  {str(e)[:100]}...\n")
    
    # Try to push empty data
    try:
        queue.push({})
    except ValueError as e:
        print(f"✓ Caught empty data error:")
        print(f"  {e}\n")


# ============================================================================
# EXAMPLE 10: Complete Production Example
# ============================================================================

class OrderSchema(MessageSchema):
    """Schema for order processing messages."""
    
    @classmethod
    def validate(cls, data):
        required = {"order_id", "customer_id", "items", "total"}
        missing = required - set(data.keys())
        
        if missing:
            raise ValidationError(
                field="required",
                message=f"Missing: {', '.join(missing)}"
            )
        
        if not isinstance(data["items"], list) or len(data["items"]) == 0:
            raise ValidationError(
                field="items",
                message="Must have at least one item"
            )
        
        if data["total"] <= 0:
            raise ValidationError(
                field="total",
                message="Total must be positive"
            )
        
        return data


def process_order(job):
    """Process an order."""
    print(f"Processing order {job['order_id']}")
    print(f"  Customer: {job['customer_id']}")
    print(f"  Items: {len(job['items'])}")
    print(f"  Total: ${job['total']:.2f}")
    
    # Simulate processing
    import time
    time.sleep(0.1)
    
    print(f"  ✓ Order {job['order_id']} completed")


def example_production():
    """Complete production-ready example."""
    print("=== Example 10: Production Setup ===\n")
    
    # Configure
    set_redis_host("localhost")
    set_max_retries(3)
    set_backpressure(enabled=True, threshold=10000)
    
    # Create queue with validation
    queue = SimpleQueue("orders", schema=OrderSchema)
    
    # Push some orders
    orders = [
        {
            "order_id": "ORD-001",
            "customer_id": "CUST-123",
            "items": ["item1", "item2"],
            "total": 99.99
        },
        {
            "order_id": "ORD-002",
            "customer_id": "CUST-456",
            "items": ["item3"],
            "total": 49.99
        }
    ]
    
    for order in orders:
        msg_id = queue.push(order, priority="high", correlation_id=order["order_id"])
        print(f"Queued: {order['order_id']} -> {msg_id}")
    
    print()
    
    # Process orders
    print("Processing orders...")
    for _ in range(len(orders)):
        job = queue.pull(timeout_ms=1000)
        if job:
            try:
                process_order(job)
                queue.complete(job)
            except Exception as e:
                print(f"  ✗ Failed: {e}")
    
    print()
    
    # Check health
    stats = queue.stats()
    print(f"Final stats:")
    print(f"  Processed: {stats['message_count']}")
    print(f"  Remaining: {stats['length']}")
    print(f"  Failed: {stats['dlq_length']}")
    print()


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("Redis Queue Library - Usage Examples")
    print("=" * 70 + "\n")
    
    try:
        # Run examples
        example_basic()
        example_with_validation()
        example_priorities()
        example_worker()
        example_tracing()
        example_error_handling()
        example_configuration()
        example_health()
        example_dlq_analysis()
        example_production()
        
        print("=" * 70)
        print("All examples completed successfully!")
        print("=" * 70 + "\n")
        
    except Exception as e:
        print(f"\n✗ Error: {e}\n")
    
    finally:
        # Clean shutdown
        simple_shutdown()
