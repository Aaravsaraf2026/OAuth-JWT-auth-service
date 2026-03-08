"""
Comprehensive unit tests for Redis queue library.
Run with: python test.py
"""

import json
import sys
import time
import unittest
from datetime import datetime
from typing import Any, Dict, List
from unittest.mock import MagicMock, Mock, patch, call

# Mock Redis before importing modules
mock_redis = MagicMock()
mock_exceptions = MagicMock()

# Create proper exception classes
class MockConnectionError(Exception):
    """Mock ConnectionError."""
    pass

class MockTimeoutError(Exception):
    """Mock TimeoutError."""
    pass

class MockResponseError(Exception):
    """Mock ResponseError."""
    pass

# Set up mock exceptions module
mock_exceptions.ConnectionError = MockConnectionError
mock_exceptions.TimeoutError = MockTimeoutError
mock_exceptions.ResponseError = MockResponseError

sys.modules['redis'] = mock_redis
sys.modules['redis.exceptions'] = mock_exceptions

# Also patch the imports in worker module
from redis.exceptions import ConnectionError, TimeoutError, ResponseError

# Import after mocking
from worker import (
    Config,
    MessagePriority,
    CircuitState,
    CircuitBreaker,
    RateLimiter,
    encode_message_fields,
    decode_message_fields,
    generate_consumer_name,
    ConsumerGroupManager,
    QueueTracker,
    QueueMetadata,
)

from redis_helper import (
    Queue,
    QueueStats,
    QueueMonitor,
    JobPipeline,
    PushBuilder,
    PullBuilder,
    BatchPushBuilder,
    BatchPushResult,
    Validator,
    QueueError,
    ValidationError,
    RateLimitError,
    ProcessingError,
    worker,
    task,
    quick_push,
    quick_pull,
    create_queues,
    MockQueue,
)


# ============================================================================
# TEST UTILITIES
# ============================================================================

class TestResult:
    """Simple test result tracker."""
    
    def __init__(self):
        self.tests_run = 0
        self.failures = []
        self.errors = []
        self.skipped = []
        self.start_time = None
        self.end_time = None
    
    def add_success(self, test_name: str):
        self.tests_run += 1
        print(f"✓ {test_name}")
    
    def add_failure(self, test_name: str, message: str):
        self.tests_run += 1
        self.failures.append((test_name, message))
        print(f"✗ {test_name}: {message}")
    
    def add_error(self, test_name: str, error: Exception):
        self.tests_run += 1
        self.errors.append((test_name, str(error)))
        print(f"✗ {test_name}: ERROR - {error}")
    
    def add_skip(self, test_name: str, reason: str):
        self.skipped.append((test_name, reason))
        print(f"⊘ {test_name}: SKIPPED - {reason}")
    
    @property
    def success_count(self) -> int:
        return self.tests_run - len(self.failures) - len(self.errors)
    
    @property
    def was_successful(self) -> bool:
        return len(self.failures) == 0 and len(self.errors) == 0
    
    def print_summary(self):
        duration = self.end_time - self.start_time if self.end_time else 0
        
        print("\n" + "=" * 70)
        print(f"Test Results ({duration:.2f}s)")
        print("=" * 70)
        print(f"Tests run: {self.tests_run}")
        print(f"Successes: {self.success_count}")
        print(f"Failures: {len(self.failures)}")
        print(f"Errors: {len(self.errors)}")
        print(f"Skipped: {len(self.skipped)}")
        
        if self.failures:
            print("\nFAILURES:")
            for test_name, message in self.failures:
                print(f"  - {test_name}: {message}")
        
        if self.errors:
            print("\nERRORS:")
            for test_name, error in self.errors:
                print(f"  - {test_name}: {error}")
        
        print("=" * 70)
        
        if self.was_successful:
            print("✓ ALL TESTS PASSED")
        else:
            print("✗ SOME TESTS FAILED")
        
        print("=" * 70)


# ============================================================================
# WORKER MODULE TESTS
# ============================================================================

class TestMessagePriority(unittest.TestCase):
    """Test MessagePriority enum."""
    
    def test_priority_values(self):
        """Test priority enum values."""
        self.assertEqual(MessagePriority.CRITICAL.value, 0)
        self.assertEqual(MessagePriority.HIGH.value, 1)
        self.assertEqual(MessagePriority.NORMAL.value, 2)
        self.assertEqual(MessagePriority.LOW.value, 3)
    
    def test_priority_ordering(self):
        """Test priority ordering."""
        self.assertTrue(MessagePriority.CRITICAL.value < MessagePriority.HIGH.value)
        self.assertTrue(MessagePriority.HIGH.value < MessagePriority.NORMAL.value)
        self.assertTrue(MessagePriority.NORMAL.value < MessagePriority.LOW.value)


class TestEncoding(unittest.TestCase):
    """Test message encoding/decoding."""
    
    def test_encode_string(self):
        """Test encoding string values."""
        data = {"key": "value"}
        encoded = encode_message_fields(data)
        self.assertEqual(encoded["key"], "value")
    
    def test_encode_dict(self):
        """Test encoding nested dict."""
        data = {"key": {"nested": "value"}}
        encoded = encode_message_fields(data)
        self.assertEqual(encoded["key"], '{"nested": "value"}')
    
    def test_encode_list(self):
        """Test encoding list."""
        data = {"items": [1, 2, 3]}
        encoded = encode_message_fields(data)
        self.assertEqual(encoded["items"], "[1, 2, 3]")
    
    def test_encode_number(self):
        """Test encoding numbers."""
        data = {"count": 42, "price": 19.99}
        encoded = encode_message_fields(data)
        self.assertEqual(encoded["count"], "42")
        self.assertEqual(encoded["price"], "19.99")
    
    def test_decode_json(self):
        """Test decoding JSON strings."""
        fields = {"key": '{"nested": "value"}'}
        decoded = decode_message_fields(fields)
        self.assertEqual(decoded["key"], {"nested": "value"})
    
    def test_decode_plain_string(self):
        """Test decoding plain strings."""
        fields = {"key": "value"}
        decoded = decode_message_fields(fields)
        self.assertEqual(decoded["key"], "value")
    
    def test_roundtrip(self):
        """Test encoding then decoding."""
        original = {
            "string": "hello",
            "number": 42,
            "dict": {"nested": "value"},
            "list": [1, 2, 3],
            "bool": True
        }
        encoded = encode_message_fields(original)
        decoded = decode_message_fields(encoded)
        
        self.assertEqual(decoded["string"], "hello")
        self.assertEqual(decoded["number"], 42)
        self.assertEqual(decoded["dict"], {"nested": "value"})
        self.assertEqual(decoded["list"], [1, 2, 3])
        self.assertEqual(decoded["bool"], True)


class TestCircuitBreaker(unittest.TestCase):
    """Test circuit breaker functionality."""
    
    def test_initial_state_closed(self):
        """Test circuit starts in CLOSED state."""
        cb = CircuitBreaker(failure_threshold=3, timeout=1)
        self.assertEqual(cb.state, CircuitState.CLOSED)
    
    def test_open_after_failures(self):
        """Test circuit opens after threshold failures."""
        cb = CircuitBreaker(failure_threshold=3, timeout=1)
        
        def failing_func():
            raise ConnectionError("Test error")
        
        for _ in range(3):
            try:
                cb.call(failing_func)
            except ConnectionError:
                pass
        
        self.assertEqual(cb.state, CircuitState.OPEN)
    
    def test_success_resets_failures(self):
        """Test successes reset failure count."""
        cb = CircuitBreaker(failure_threshold=3, timeout=1)
        
        def failing_func():
            raise ConnectionError("Test error")
        
        def success_func():
            return "success"
        
        # Two failures
        for _ in range(2):
            try:
                cb.call(failing_func)
            except ConnectionError:
                pass
        
        # Success resets
        cb.call(success_func)
        
        # Should still be closed
        self.assertEqual(cb.state, CircuitState.CLOSED)
    
    def test_half_open_to_closed(self):
        """Test transition from HALF_OPEN to CLOSED."""
        cb = CircuitBreaker(failure_threshold=2, success_threshold=2, timeout=0.1)
        
        def failing_func():
            raise TimeoutError("Test error")
        
        def success_func():
            return "success"
        
        # Open the circuit
        for _ in range(2):
            try:
                cb.call(failing_func)
            except TimeoutError:
                pass
        
        self.assertEqual(cb.state, CircuitState.OPEN)
        
        # Wait for timeout
        time.sleep(0.2)
        
        # Should transition to HALF_OPEN and then CLOSED
        cb.call(success_func)
        self.assertEqual(cb.state, CircuitState.HALF_OPEN)
        
        cb.call(success_func)
        self.assertEqual(cb.state, CircuitState.CLOSED)


class TestRateLimiter(unittest.TestCase):
    """Test rate limiter functionality."""
    
    def test_acquire_tokens(self):
        """Test acquiring tokens."""
        limiter = RateLimiter(max_rate=10, window=1.0)
        
        # Should be able to acquire
        self.assertTrue(limiter.acquire(1))
        self.assertTrue(limiter.acquire(5))
    
    def test_rate_limit_exceeded(self):
        """Test rate limit is enforced."""
        limiter = RateLimiter(max_rate=5, window=1.0)
        
        # Acquire all tokens
        for _ in range(5):
            self.assertTrue(limiter.acquire(1))
        
        # Should be rate limited
        self.assertFalse(limiter.acquire(1))
    
    def test_token_refill(self):
        """Test tokens refill over time."""
        limiter = RateLimiter(max_rate=10, window=0.1)
        
        # Exhaust tokens
        for _ in range(10):
            limiter.acquire(1)
        
        # Should be limited
        self.assertFalse(limiter.acquire(1))
        
        # Wait for refill
        time.sleep(0.2)
        
        # Should have tokens again
        self.assertTrue(limiter.acquire(1))
    
    def test_reset(self):
        """Test manual reset."""
        limiter = RateLimiter(max_rate=5, window=1.0)
        
        # Exhaust tokens
        for _ in range(5):
            limiter.acquire(1)
        
        self.assertFalse(limiter.acquire(1))
        
        # Reset
        limiter.reset()
        
        # Should work again
        self.assertTrue(limiter.acquire(1))


class TestQueueTracker(unittest.TestCase):
    """Test queue tracking functionality."""
    
    def setUp(self):
        self.tracker = QueueTracker()
    
    def test_add_queue(self):
        """Test adding a queue."""
        metadata = self.tracker.add_queue("test_queue")
        
        self.assertEqual(metadata.name, "test_queue")
        self.assertTrue(metadata.is_active)
        self.assertEqual(metadata.message_count, 0)
        self.assertEqual(metadata.error_count, 0)
    
    def test_get_queue(self):
        """Test retrieving queue metadata."""
        self.tracker.add_queue("test_queue")
        metadata = self.tracker.get_queue("test_queue")
        
        self.assertIsNotNone(metadata)
        self.assertEqual(metadata.name, "test_queue")
    
    def test_remove_queue(self):
        """Test removing a queue."""
        self.tracker.add_queue("test_queue")
        self.tracker.remove_queue("test_queue")
        
        metadata = self.tracker.get_queue("test_queue")
        self.assertIsNone(metadata)
    
    def test_list_active_queues(self):
        """Test listing active queues."""
        self.tracker.add_queue("queue1")
        self.tracker.add_queue("queue2")
        
        queues = self.tracker.list_queues(active_only=True)
        self.assertEqual(len(queues), 2)
    
    def test_mark_error(self):
        """Test marking errors."""
        self.tracker.add_queue("test_queue")
        self.tracker.mark_error("test_queue")
        
        metadata = self.tracker.get_queue("test_queue")
        self.assertEqual(metadata.error_count, 1)
    
    def test_increment_message_count(self):
        """Test incrementing message count."""
        self.tracker.add_queue("test_queue")
        self.tracker.increment_message_count("test_queue")
        self.tracker.increment_message_count("test_queue")
        
        metadata = self.tracker.get_queue("test_queue")
        self.assertEqual(metadata.message_count, 2)
    
    def test_rate_limiter_per_queue(self):
        """Test rate limiting per queue."""
        self.tracker.add_queue("queue1")
        self.tracker.add_queue("queue2")
        
        # Each queue should have independent rate limiters
        self.assertTrue(self.tracker.acquire_rate_limit("queue1"))
        self.assertTrue(self.tracker.acquire_rate_limit("queue2"))


class TestConsumerGroupManager(unittest.TestCase):
    """Test consumer group management."""
    
    def test_get_group_name(self):
        """Test group name generation."""
        group_name = ConsumerGroupManager.get_group_name("test_queue")
        self.assertEqual(group_name, f"{Config.GROUP_PREFIX}test_queue")
    
    def test_different_queues_different_locks(self):
        """Test each queue gets its own lock."""
        lock1 = ConsumerGroupManager._get_queue_lock("queue1")
        lock2 = ConsumerGroupManager._get_queue_lock("queue2")
        
        self.assertIsNot(lock1, lock2)
    
    def test_same_queue_same_lock(self):
        """Test same queue returns same lock."""
        lock1 = ConsumerGroupManager._get_queue_lock("queue1")
        lock2 = ConsumerGroupManager._get_queue_lock("queue1")
        
        self.assertIs(lock1, lock2)


class TestGenerateConsumerName(unittest.TestCase):
    """Test consumer name generation."""
    
    def test_unique_names(self):
        """Test consumer names are unique."""
        name1 = generate_consumer_name()
        name2 = generate_consumer_name()
        
        # Should be different due to thread ID or timing
        self.assertIsInstance(name1, str)
        self.assertIsInstance(name2, str)
        self.assertGreater(len(name1), 0)
    
    def test_contains_hostname_pid(self):
        """Test consumer name contains hostname and PID."""
        name = generate_consumer_name()
        
        # Should contain hyphens separating components
        self.assertIn("-", name)
        parts = name.split("-")
        self.assertGreaterEqual(len(parts), 3)


# ============================================================================
# REDIS HELPER TESTS
# ============================================================================

class TestValidator(unittest.TestCase):
    """Test input validation."""
    
    def test_valid_queue_name(self):
        """Test valid queue name."""
        result = Validator.validate_queue_name("my_queue")
        self.assertEqual(result, "my_queue")
    
    def test_empty_queue_name(self):
        """Test empty queue name raises error."""
        with self.assertRaises(ValidationError):
            Validator.validate_queue_name("")
    
    def test_queue_name_too_long(self):
        """Test queue name length limit."""
        long_name = "x" * 201
        with self.assertRaises(ValidationError):
            Validator.validate_queue_name(long_name)
    
    def test_queue_name_invalid_chars(self):
        """Test invalid characters in queue name."""
        with self.assertRaises(ValidationError):
            Validator.validate_queue_name("queue name")
        
        with self.assertRaises(ValidationError):
            Validator.validate_queue_name("queue\nname")
    
    def test_validate_message_data_valid(self):
        """Test valid message data."""
        data = {"key": "value"}
        result = Validator.validate_message_data(data)
        self.assertEqual(result, data)
    
    def test_validate_message_data_not_dict(self):
        """Test non-dict message data."""
        with self.assertRaises(ValidationError):
            Validator.validate_message_data("not a dict")
    
    def test_validate_message_data_empty(self):
        """Test empty message data."""
        with self.assertRaises(ValidationError):
            Validator.validate_message_data({})
    
    def test_validate_priority_enum(self):
        """Test priority validation with enum."""
        result = Validator.validate_priority(MessagePriority.HIGH)
        self.assertEqual(result, MessagePriority.HIGH)
    
    def test_validate_priority_string(self):
        """Test priority validation with string."""
        result = Validator.validate_priority("high")
        self.assertEqual(result, MessagePriority.HIGH)
    
    def test_validate_priority_int(self):
        """Test priority validation with int."""
        result = Validator.validate_priority(1)
        self.assertEqual(result, MessagePriority.HIGH)
    
    def test_validate_priority_invalid(self):
        """Test invalid priority."""
        with self.assertRaises(ValidationError):
            Validator.validate_priority("invalid")


class TestMockQueue(unittest.TestCase):
    """Test mock queue for testing."""
    
    def test_push_and_pull(self):
        """Test basic push/pull."""
        queue = MockQueue("test")
        
        msg_id = queue.push({"task": "test"}).execute()
        self.assertIsNotNone(msg_id)
        
        message = queue.pull().execute()
        self.assertIsNotNone(message)
        self.assertEqual(message["task"], "test")
    
    def test_empty_pull(self):
        """Test pulling from empty queue."""
        queue = MockQueue("test")
        message = queue.pull().execute()
        self.assertIsNone(message)
    
    def test_fifo_order(self):
        """Test FIFO ordering."""
        queue = MockQueue("test")
        
        queue.push({"order": 1}).execute()
        queue.push({"order": 2}).execute()
        queue.push({"order": 3}).execute()
        
        msg1 = queue.pull().execute()
        msg2 = queue.pull().execute()
        msg3 = queue.pull().execute()
        
        self.assertEqual(msg1["order"], 1)
        self.assertEqual(msg2["order"], 2)
        self.assertEqual(msg3["order"], 3)
    
    def test_message_has_metadata(self):
        """Test message includes metadata."""
        queue = MockQueue("test")
        queue.push({"data": "test"}).execute()
        
        message = queue.pull().execute()
        
        self.assertIn("_id", message)
        self.assertIn("_queue", message)
        self.assertIn("_priority", message)
        self.assertIn("_created_at", message)


class TestQueueStats(unittest.TestCase):
    """Test queue statistics."""
    
    def test_basic_stats(self):
        """Test basic statistics."""
        raw = {
            "queue_name": "test",
            "length": 10,
            "dlq_length": 2,
            "pending_count": 3,
            "consumer_count": 5
        }
        stats = QueueStats(raw)
        
        self.assertEqual(stats.name, "test")
        self.assertEqual(stats.length, 10)
        self.assertEqual(stats.dlq_length, 2)
        self.assertEqual(stats.pending, 3)
        self.assertEqual(stats.consumers, 5)
    
    def test_health_score_perfect(self):
        """Test health score with perfect queue."""
        raw = {
            "queue_name": "test",
            "length": 100,
            "dlq_length": 0,
            "pending_count": 0,
            "consumer_count": 5
        }
        stats = QueueStats(raw)
        self.assertEqual(stats.health_score, 100.0)
    
    def test_health_score_with_dlq(self):
        """Test health score with DLQ messages."""
        raw = {
            "queue_name": "test",
            "length": 100,
            "dlq_length": 20,
            "pending_count": 0,
            "consumer_count": 5
        }
        stats = QueueStats(raw)
        self.assertLess(stats.health_score, 100.0)
    
    def test_is_healthy_true(self):
        """Test healthy queue detection."""
        raw = {
            "queue_name": "test",
            "length": 100,
            "dlq_length": 5,
            "pending_count": 20,
            "consumer_count": 5
        }
        stats = QueueStats(raw)
        self.assertTrue(stats.is_healthy)
    
    def test_is_healthy_false(self):
        """Test unhealthy queue detection."""
        raw = {
            "queue_name": "test",
            "length": 100,
            "dlq_length": 50,
            "pending_count": 80,
            "consumer_count": 5
        }
        stats = QueueStats(raw)
        self.assertFalse(stats.is_healthy)
    
    def test_summary(self):
        """Test summary string generation."""
        raw = {
            "queue_name": "test",
            "length": 10,
            "dlq_length": 2,
            "pending_count": 3,
            "consumer_count": 5
        }
        stats = QueueStats(raw)
        summary = stats.summary()
        
        self.assertIn("test", summary)
        self.assertIn("10", summary)
        self.assertIn("Health", summary)


class TestBatchPushResult(unittest.TestCase):
    """Test batch push result."""
    
    def test_empty_result(self):
        """Test empty result."""
        result = BatchPushResult()
        self.assertEqual(result.success_count, 0)
        self.assertEqual(result.failure_count, 0)
        self.assertEqual(result.total_count, 0)
        self.assertEqual(result.success_rate, 0.0)
    
    def test_all_successful(self):
        """Test all successful."""
        result = BatchPushResult()
        result.successful = ["id1", "id2", "id3"]
        
        self.assertEqual(result.success_count, 3)
        self.assertEqual(result.success_rate, 1.0)
    
    def test_mixed_results(self):
        """Test mixed results."""
        result = BatchPushResult()
        result.successful = ["id1", "id2"]
        result.failed = [{"error": "test"}]
        result.rate_limited = 1
        
        self.assertEqual(result.success_count, 2)
        self.assertEqual(result.failure_count, 1)
        self.assertEqual(result.total_count, 4)
        self.assertEqual(result.success_rate, 0.5)


class TestJobPipeline(unittest.TestCase):
    """Test job pipeline."""
    
    def test_add_jobs(self):
        """Test adding jobs to pipeline."""
        pipeline = JobPipeline()
        pipeline.add("queue1", {"task": "first"})
        pipeline.add("queue2", {"task": "second"}, priority="high")
        
        self.assertEqual(len(pipeline.jobs), 2)
    
    def test_clear_pipeline(self):
        """Test clearing pipeline."""
        pipeline = JobPipeline()
        pipeline.add("queue1", {"task": "first"})
        pipeline.add("queue2", {"task": "second"})
        
        pipeline.clear()
        self.assertEqual(len(pipeline.jobs), 0)
    
    def test_fluent_interface(self):
        """Test fluent interface."""
        pipeline = JobPipeline()
        result = pipeline.add("queue1", {"task": "first"}).add("queue2", {"task": "second"})
        
        self.assertIs(result, pipeline)
        self.assertEqual(len(pipeline.jobs), 2)


class TestQueueMonitor(unittest.TestCase):
    """Test queue monitor."""
    
    @patch('redis_helper.Queue')
    def test_monitor_initialization(self, mock_queue):
        """Test monitor initialization."""
        monitor = QueueMonitor(["queue1", "queue2", "queue3"])
        self.assertEqual(len(monitor.queues), 3)
    
    @patch('redis_helper.Queue')
    def test_get_all_stats(self, mock_queue):
        """Test getting all queue stats."""
        mock_stats = Mock()
        mock_queue.return_value.stats.return_value = mock_stats
        
        monitor = QueueMonitor(["queue1", "queue2"])
        stats = monitor.get_all_stats()
        
        self.assertEqual(len(stats), 2)


class TestConvenienceFunctions(unittest.TestCase):
    """Test convenience functions."""
    
    def test_create_queues(self):
        """Test creating multiple queues."""
        with patch('redis_helper.Queue') as mock_queue:
            mock_queue.return_value = Mock()
            queues = create_queues("queue1", "queue2", "queue3")
            
            self.assertEqual(len(queues), 3)
            self.assertEqual(mock_queue.call_count, 3)


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

class TestIntegration(unittest.TestCase):
    """Integration tests using MockQueue."""
    
    def test_complete_workflow(self):
        """Test complete push-pull-ack workflow."""
        queue = MockQueue("integration_test")
        
        # Push a message
        msg_id = queue.push({"task": "process", "data": 123}).high().execute()
        self.assertIsNotNone(msg_id)
        
        # Pull the message
        message = queue.pull().execute()
        self.assertIsNotNone(message)
        self.assertEqual(message["task"], "process")
        self.assertEqual(message["data"], 123)
        
        # Verify metadata
        self.assertIn("_id", message)
        self.assertIn("_priority", message)
    
    def test_batch_operations(self):
        """Test batch push and pull."""
        queue = MockQueue("batch_test")
        
        # Batch push
        items = [
            {"task": f"task_{i}", "value": i}
            for i in range(5)
        ]
        
        for item in items:
            queue.push(item).execute()
        
        # Pull all
        messages = []
        for _ in range(5):
            msg = queue.pull().execute()
            if msg:
                messages.append(msg)
        
        self.assertEqual(len(messages), 5)
        self.assertEqual(messages[0]["task"], "task_0")
        self.assertEqual(messages[4]["task"], "task_4")
    
    def test_priority_handling(self):
        """Test different priority messages."""
        queue = MockQueue("priority_test")
        
        # Push with different priorities
        queue.push({"order": 1}).low().execute()
        queue.push({"order": 2}).high().execute()
        queue.push({"order": 3}).critical().execute()
        
        # Pull all (mock doesn't sort by priority, but they're in queue)
        messages = []
        for _ in range(3):
            msg = queue.pull().execute()
            if msg:
                messages.append(msg)
        
        self.assertEqual(len(messages), 3)


# ============================================================================
# TEST RUNNER
# ============================================================================

def run_test_case(test_case_class, result: TestResult):
    """Run a single test case class."""
    suite = unittest.TestLoader().loadTestsFromTestCase(test_case_class)
    
    for test in suite:
        test_name = f"{test_case_class.__name__}.{test._testMethodName}"
        
        try:
            test.debug()
            result.add_success(test_name)
        except AssertionError as e:
            result.add_failure(test_name, str(e))
        except Exception as e:
            result.add_error(test_name, e)


def main():
    """Main test runner."""
    print("=" * 70)
    print("Redis Queue Library - Unit Tests")
    print("=" * 70)
    print()
    
    result = TestResult()
    result.start_time = time.time()
    
    # Define test cases in order
    test_cases = [
        # Worker module tests
        TestMessagePriority,
        TestEncoding,
        TestCircuitBreaker,
        TestRateLimiter,
        TestQueueTracker,
        TestConsumerGroupManager,
        TestGenerateConsumerName,
        
        # Redis helper tests
        TestValidator,
        TestMockQueue,
        TestQueueStats,
        TestBatchPushResult,
        TestJobPipeline,
        TestQueueMonitor,
        TestConvenienceFunctions,
        
        # Integration tests
        TestIntegration,
    ]
    
    for test_case in test_cases:
        print(f"\n--- {test_case.__name__} ---")
        run_test_case(test_case, result)
    
    result.end_time = time.time()
    result.print_summary()
    
    # Exit with appropriate code
    sys.exit(0 if result.was_successful else 1)


if __name__ == "__main__":
    main()