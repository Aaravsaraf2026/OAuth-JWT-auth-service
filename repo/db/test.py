"""
test.py - Comprehensive Test Suite for Database Modules
========================================================

Simple test runner that validates db_engine_prod.py and db_helper_prod.py

Usage:
    python test.py              # Run all tests
    python test.py --verbose    # Verbose output
    python test.py --engine     # Test only db_engine
    python test.py --helper     # Test only db_helper
    python test.py --integration # Test integration
    python test.py --fix        # Create fixed db_helper_prod.py

Requirements:
    pip install sqlalchemy
"""

import os
import sys
import time
import tempfile
import argparse
from pathlib import Path
from typing import List, Dict, Any
import traceback

# ============================================================================
# COLOR OUTPUT
# ============================================================================

class Colors:
    """Terminal colors for pretty output."""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def colored(text: str, color: str) -> str:
    """Return colored text."""
    return f"{color}{text}{Colors.RESET}"

# ============================================================================
# TEST FRAMEWORK
# ============================================================================

class TestResult:
    """Store test result."""
    def __init__(self, name: str, passed: bool, duration: float, error: str = None):
        self.name = name
        self.passed = passed
        self.duration = duration
        self.error = error

class TestRunner:
    """Simple test runner."""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.results: List[TestResult] = []
        self.current_section = ""
    
    def section(self, name: str):
        """Print section header."""
        self.current_section = name
        print(f"\n{colored('='*70, Colors.CYAN)}")
        print(colored(f"  {name}", Colors.BOLD + Colors.CYAN))
        print(colored('='*70, Colors.CYAN))
    
    def test(self, name: str, func):
        """Run a single test."""
        full_name = f"{self.current_section} > {name}" if self.current_section else name
        
        if self.verbose:
            print(f"\n{colored('→', Colors.BLUE)} Running: {name}")
        
        start = time.time()
        
        try:
            func()
            duration = time.time() - start
            self.results.append(TestResult(full_name, True, duration))
            
            status = colored('✓', Colors.GREEN)
            timing = colored(f"({duration:.3f}s)", Colors.BLUE)
            print(f"  {status} {name} {timing}")
            
            return True
        
        except Exception as e:
            duration = time.time() - start
            error = str(e)
            self.results.append(TestResult(full_name, False, duration, error))
            
            status = colored('✗', Colors.RED)
            print(f"  {status} {name}")
            print(colored(f"    Error: {error}", Colors.RED))
            
            if self.verbose:
                print(colored(traceback.format_exc(), Colors.RED))
            
            return False
    
    def summary(self):
        """Print test summary."""
        passed = sum(1 for r in self.results if r.passed)
        failed = sum(1 for r in self.results if not r.passed)
        total = len(self.results)
        total_time = sum(r.duration for r in self.results)
        
        print(f"\n{colored('='*70, Colors.CYAN)}")
        print(colored("  TEST SUMMARY", Colors.BOLD + Colors.CYAN))
        print(colored('='*70, Colors.CYAN))
        
        print(f"\n  Total Tests:  {total}")
        print(f"  {colored('✓ Passed:', Colors.GREEN)}    {passed}")
        print(f"  {colored('✗ Failed:', Colors.RED)}    {failed}")
        print(f"  Duration:     {total_time:.2f}s")
        
        if failed > 0:
            print(f"\n{colored('  FAILED TESTS:', Colors.RED)}")
            for result in self.results:
                if not result.passed:
                    print(f"    • {result.name}")
                    if result.error and self.verbose:
                        print(f"      {colored(result.error, Colors.RED)}")
        
        print(f"\n{colored('='*70, Colors.CYAN)}")
        
        if failed == 0:
            print(colored("\n  🎉 ALL TESTS PASSED! 🎉\n", Colors.GREEN + Colors.BOLD))
            return True
        else:
            print(colored(f"\n  ❌ {failed} TEST(S) FAILED\n", Colors.RED + Colors.BOLD))
            return False

# ============================================================================
# IMPORT MODULES
# ============================================================================

def check_imports():
    """Check if required modules are available."""
    print(colored("\n📦 Checking dependencies...", Colors.CYAN))
    
    errors = []
    
    # Check SQLAlchemy
    try:
        import sqlalchemy
        print(f"  ✓ SQLAlchemy {sqlalchemy.__version__}")
    except ImportError:
        errors.append("SQLAlchemy not installed: pip install sqlalchemy")
    
    # Check db_engine_prod
    try:
        import db_engine_prod
        print(f"  ✓ db_engine_prod v{db_engine_prod.__version__}")
    except ImportError:
        errors.append("db_engine_prod.py not found")
    
    # Check db_helper_prod
    try:
        import db_helper_prod
        print(f"  ✓ db_helper_prod found")
    except ImportError:
        errors.append("db_helper_prod.py not found")
    
    if errors:
        print(colored("\n❌ Missing dependencies:", Colors.RED))
        for error in errors:
            print(f"  • {error}")
        sys.exit(1)
    
    print(colored("✓ All dependencies available\n", Colors.GREEN))

# ============================================================================
# DB ENGINE TESTS
# ============================================================================

def test_engine(runner: TestRunner):
    """Test db_engine_prod.py"""
    from db_engine_prod import (
        create_engine_safe,
        create_sqlite_engine,
        create_postgresql_engine,
        test_connection,
        get_health_report,
        get_pool_status,
        shutdown_engine,
        shutdown_all_engines
    )
    from sqlalchemy import text
    
    runner.section("DB Engine Tests")
    
    # Test 1: SQLite Memory Engine
    def test_sqlite_memory():
        engine = create_sqlite_engine(":memory:")
        assert engine is not None
        assert test_connection(engine)
        shutdown_engine(engine)
    
    runner.test("SQLite Memory Engine", test_sqlite_memory)
    
    # Test 2: SQLite File Engine
    def test_sqlite_file():
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name
        
        try:
            engine = create_sqlite_engine(db_path, wal=True)
            assert test_connection(engine)
            
            # Test query
            with engine.connect() as conn:
                result = conn.execute(text("SELECT 1 as num"))
                assert result.scalar() == 1
                conn.commit()
            
            shutdown_engine(engine)
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)
    
    runner.test("SQLite File Engine", test_sqlite_file)
    
    # Test 3: create_engine_safe
    def test_engine_safe():
        engine = create_engine_safe(":memory:")
        assert test_connection(engine)
        shutdown_engine(engine)
    
    runner.test("create_engine_safe", test_engine_safe)
    
    # Test 4: Health Report
    def test_health_report():
        engine = create_engine_safe(":memory:")
        health = get_health_report(engine)
        
        assert health['status'] in ['HEALTHY', 'DEGRADED', 'UNHEALTHY']
        assert 'connection_test' in health
        assert 'pool_utilization' in health
        assert health['connection_test'] is True
        
        shutdown_engine(engine)
    
    runner.test("Health Report", test_health_report)
    
    # Test 5: Pool Status
    def test_pool_status():
        engine = create_engine_safe(":memory:")
        status = get_pool_status(engine)
        
        assert status.size >= 0
        assert status.checked_out >= 0
        assert status.utilization_percent >= 0
        
        shutdown_engine(engine)
    
    runner.test("Pool Status", test_pool_status)
    
    # Test 6: Connection Retry
    def test_connection_operations():
        engine = create_engine_safe(":memory:")
        
        # Multiple connections
        for _ in range(5):
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
                conn.commit()
        
        shutdown_engine(engine)
    
    runner.test("Connection Operations", test_connection_operations)
    
    # Test 7: WAL Mode
    def test_wal_mode():
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name
        
        try:
            engine = create_sqlite_engine(db_path, wal=True)
            
            with engine.connect() as conn:
                result = conn.execute(text("PRAGMA journal_mode"))
                mode = result.scalar()
                assert mode.upper() == 'WAL'
                conn.commit()
            
            shutdown_engine(engine)
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)
    
    runner.test("WAL Mode", test_wal_mode)
    
    # Test 8: Shutdown All
    def test_shutdown_all():
        engines = [create_engine_safe(":memory:") for _ in range(3)]
        shutdown_all_engines()
        # Just verify no errors
    
    runner.test("Shutdown All Engines", test_shutdown_all)

# ============================================================================
# DB HELPER TESTS
# ============================================================================

def test_helper(runner: TestRunner):
    """Test db_helper_prod.py"""
    from db_helper_prod import DB
    
    runner.section("DB Helper Tests")
    
    # Test 1: Create DB
    def test_create_db():
        db = DB(":memory:")
        assert db is not None
        assert db.db_type == "sqlite"
        db.close()
    
    runner.test("Create DB", test_create_db)
    
    # Test 2: Create Table
    def test_create_table():
        db = DB(":memory:")
        
        try:
            success = db.create_table("users", {
                "id": "serial primary",
                "name": "str not null",
                "email": "str unique"
            })
            
            # Check if table actually exists (more important than return value)
            assert db.table_exists("users"), "Table was not created"
        except Exception as e:
            db.close()
            raise AssertionError(f"Failed to create table: {e}")
        
        db.close()
    
    runner.test("Create Table", test_create_table)
    
    # Test 3: Insert Data
    def test_insert():
        db = DB(":memory:")
        db.create_table("users", {
            "id": "serial primary",
            "name": "str not null"
        })
        
        user_id = db.insert("users", {"name": "Alice"}, return_id=True)
        assert user_id is not None
        
        db.close()
    
    runner.test("Insert Data", test_insert)
    
    # Test 4: Query Data
    def test_query():
        db = DB(":memory:")
        db.create_table("users", {
            "id": "serial primary",
            "name": "str not null"
        })
        
        db.insert("users", {"name": "Alice"})
        db.insert("users", {"name": "Bob"})
        
        users = db.query("SELECT * FROM users")
        assert len(users) == 2
        
        db.close()
    
    runner.test("Query Data", test_query)
    
    # Test 5: Query Builder
    def test_query_builder():
        db = DB(":memory:")
        db.create_table("users", {
            "id": "serial primary",
            "name": "str not null",
            "age": "int"
        })
        
        db.insert("users", {"name": "Alice", "age": 30})
        db.insert("users", {"name": "Bob", "age": 25})
        
        # Test where
        result = db.table("users").where(name="Alice").first()
        assert result is not None
        assert result["name"] == "Alice"
        
        # Test count
        count = db.table("users").count()
        assert count == 2
        
        # Test order by
        users = db.table("users").order_by("age").all()
        assert users[0]["name"] == "Bob"
        
        db.close()
    
    runner.test("Query Builder", test_query_builder)
    
    # Test 6: Update
    def test_update():
        db = DB(":memory:")
        db.create_table("users", {
            "id": "serial primary",
            "name": "str not null"
        })
        
        db.insert("users", {"name": "Alice"})
        
        rows = db.update("users", {"name": "Alice Updated"}, {"name": "Alice"})
        assert rows == 1
        
        result = db.table("users").where(name="Alice Updated").first()
        assert result is not None
        
        db.close()
    
    runner.test("Update Data", test_update)
    
    # Test 7: Delete
    def test_delete():
        db = DB(":memory:")
        db.create_table("users", {
            "id": "serial primary",
            "name": "str not null"
        })
        
        db.insert("users", {"name": "Alice"})
        db.insert("users", {"name": "Bob"})
        
        rows = db.delete("users", {"name": "Alice"})
        assert rows == 1
        
        count = db.table("users").count()
        assert count == 1
        
        db.close()
    
    runner.test("Delete Data", test_delete)
    
    # Test 8: JSONB Support
    def test_jsonb():
        db = DB(":memory:")
        db.create_table("users", {
            "id": "serial primary",
            "name": "str not null",
            "profile": "jsonb"
        })
        
        profile_data = {"age": 30, "city": "NYC", "active": True}
        db.insert("users", {"name": "Alice", "profile": profile_data})
        
        result = db.table("users").where(name="Alice").first()
        assert result["profile"] == profile_data
        
        db.close()
    
    runner.test("JSONB Support", test_jsonb)
    
    # Test 9: BLOB Support
    def test_blob():
        db = DB(":memory:", compress_blobs=True)
        db.create_table("files", {
            "id": "serial primary",
            "name": "str not null",
            "data": "blob"
        })
        
        binary_data = b"Hello World" * 100
        db.insert("files", {"name": "test.txt", "data": binary_data})
        
        retrieved = db.get_blob("files", "data", {"name": "test.txt"})
        assert retrieved == binary_data
        
        db.close()
    
    runner.test("BLOB Support", test_blob)
    
    # Test 10: Indexes
    def test_indexes():
        db = DB(":memory:")
        db.create_table("users", {
            "id": "serial primary",
            "email": "str unique not null"
        })
        
        success = db.create_index("idx_email", "users", "email", unique=True)
        assert success is True
        
        db.close()
    
    runner.test("Create Index", test_indexes)
    
    # Test 11: Transactions
    def test_transactions():
        db = DB(":memory:")
        db.create_table("users", {
            "id": "serial primary",
            "name": "str not null"
        })
        
        with db.transaction():
            db.insert("users", {"name": "Alice"})
            db.insert("users", {"name": "Bob"})
        
        count = db.table("users").count()
        assert count == 2
        
        db.close()
    
    runner.test("Transactions", test_transactions)
    
    # Test 12: Bulk Insert
    def test_bulk_insert():
        db = DB(":memory:")
        db.create_table("users", {
            "id": "serial primary",
            "name": "str not null"
        })
        
        rows = [
            {"name": f"User{i}"}
            for i in range(10)
        ]
        
        count = db.insert_many("users", rows)
        assert count == 10
        
        total = db.table("users").count()
        assert total == 10
        
        db.close()
    
    runner.test("Bulk Insert", test_bulk_insert)
    
    # Test 13: Table Operations
    def test_table_operations():
        db = DB(":memory:")
        
        db.create_table("test_table", {"id": "serial primary"})
        
        assert db.table_exists("test_table")
        
        tables = db.list_tables()
        assert "test_table" in tables
        
        stats = db.analyze_table("test_table")
        assert stats["exists"] is True
        assert stats["row_count"] == 0
        
        db.drop_table("test_table")
        assert not db.table_exists("test_table")
        
        db.close()
    
    runner.test("Table Operations", test_table_operations)

# ============================================================================
# INTEGRATION TESTS
# ============================================================================

def test_integration(runner: TestRunner):
    """Test integration between modules"""
    from db_engine_prod import create_engine_safe, shutdown_engine
    from db_helper_prod import DB
    
    runner.section("Integration Tests")
    
    # Test 1: Use Engine with DB Helper
    def test_engine_integration():
        engine = create_engine_safe(":memory:")
        db = DB(engine=engine)
        
        db.create_table("users", {
            "id": "serial primary",
            "name": "str not null"
        })
        
        db.insert("users", {"name": "Alice"})
        count = db.table("users").count()
        assert count == 1
        
        # DB shouldn't close engine it doesn't own
        db.close()
        
        # Engine should still work
        from sqlalchemy import text
        with engine.connect() as conn:
            result = conn.execute(text("SELECT COUNT(*) FROM users"))
            assert result.scalar() == 1
            conn.commit()
        
        shutdown_engine(engine)
    
    runner.test("Engine + DB Helper Integration", test_engine_integration)
    
    # Test 2: Complex Workflow
    def test_complex_workflow():
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name
        
        try:
            # Create with engine
            engine = create_engine_safe(db_path, wal=True)
            db = DB(engine=engine)
            
            # Create schema
            db.create_table("products", {
                "id": "serial primary",
                "name": "str not null",
                "price": "float",
                "metadata": "jsonb"
            })
            
            db.create_index("idx_name", "products", "name")
            
            # Insert data
            products = [
                {"name": "Widget", "price": 19.99, "metadata": {"category": "tools"}},
                {"name": "Gadget", "price": 29.99, "metadata": {"category": "electronics"}},
                {"name": "Doohickey", "price": 9.99, "metadata": {"category": "tools"}},
            ]
            
            db.insert_many("products", products)
            
            # Query
            tools = [
                p for p in db.table("products").all()
                if p["metadata"]["category"] == "tools"
            ]
            assert len(tools) == 2
            
            # Update
            db.update("products", {"price": 24.99}, {"name": "Widget"})
            
            # Verify
            widget = db.table("products").where(name="Widget").first()
            assert widget["price"] == 24.99
            
            db.close()
            shutdown_engine(engine)
            
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)
    
    runner.test("Complex Workflow", test_complex_workflow)

# ============================================================================
# PERFORMANCE TESTS
# ============================================================================

def test_performance(runner: TestRunner):
    """Basic performance tests"""
    from db_helper_prod import DB
    
    runner.section("Performance Tests")
    
    # Test 1: Bulk Insert Performance
    def test_bulk_performance():
        db = DB(":memory:")
        db.create_table("test", {
            "id": "serial primary",
            "name": "str not null",
            "value": "int"
        })
        
        rows = [{"name": f"item{i}", "value": i} for i in range(1000)]
        
        start = time.time()
        db.insert_many("test", rows)
        duration = time.time() - start
        
        count = db.table("test").count()
        assert count == 1000
        
        print(f"    → Inserted 1000 rows in {duration:.3f}s ({1000/duration:.0f} rows/sec)")
        
        db.close()
    
    runner.test("Bulk Insert (1000 rows)", test_bulk_performance)
    
    # Test 2: Query Performance
    def test_query_performance():
        db = DB(":memory:")
        db.create_table("test", {
            "id": "serial primary",
            "name": "str not null",
            "value": "int"
        })
        
        rows = [{"name": f"item{i}", "value": i} for i in range(1000)]
        db.insert_many("test", rows)
        
        start = time.time()
        for _ in range(100):
            db.table("test").where(value=500).first()
        duration = time.time() - start
        
        print(f"    → 100 queries in {duration:.3f}s ({100/duration:.0f} queries/sec)")
        
        db.close()
    
    runner.test("Query Performance (100 queries)", test_query_performance)

# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="Test database modules")
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--engine', action='store_true', help='Test only db_engine')
    parser.add_argument('--helper', action='store_true', help='Test only db_helper')
    parser.add_argument('--integration', action='store_true', help='Test only integration')
    parser.add_argument('--performance', action='store_true', help='Include performance tests')
    
    args = parser.parse_args()
    
    print(colored("\n" + "="*70, Colors.CYAN))
    print(colored("  DATABASE MODULE TEST SUITE", Colors.BOLD + Colors.CYAN))
    print(colored("="*70, Colors.CYAN))
    
    # Check dependencies
    check_imports()
    
    # Create runner
    runner = TestRunner(verbose=args.verbose)
    
    # Run tests
    if args.engine or not (args.helper or args.integration):
        test_engine(runner)
    
    if args.helper or not (args.engine or args.integration):
        test_helper(runner)
    
    if args.integration or not (args.engine or args.helper):
        test_integration(runner)
    
    if args.performance:
        test_performance(runner)
    
    # Print summary
    success = runner.summary()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()