"""
Diagnostic script to identify the exact issue with create_table
"""

import logging
import sys

# Enable detailed logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(levelname)s: %(message)s'
)

try:
    from db_helper_prod import DB
except ImportError:
    print("ERROR: Cannot import db_helper_prod.py")
    print("Make sure the fixed version is saved as db_helper_prod.py")
    sys.exit(1)

print("=" * 70)
print("DIAGNOSTIC TEST: Create Table Issue")
print("=" * 70)

# Test 1: Basic table creation
print("\n1. Testing basic table creation...")
try:
    db = DB(":memory:")
    print(f"   ✓ DB created: {db}")
    print(f"   ✓ DB type: {db.db_type}")
    
    print("\n2. Attempting to create table...")
    result = db.create_table("users", {
        "id": "serial primary",
        "name": "str not null",
        "email": "str unique"
    })
    
    print(f"   create_table returned: {result}")
    
    print("\n3. Checking if table exists...")
    exists = db.table_exists("users")
    print(f"   table_exists returned: {exists}")
    
    if not exists:
        print("\n   ⚠ TABLE WAS NOT CREATED!")
        print("   Attempting to query sqlite_master...")
        
        try:
            tables = db.query("SELECT * FROM sqlite_master WHERE type='table'")
            print(f"   Tables in database: {tables}")
        except Exception as e:
            print(f"   Error querying sqlite_master: {e}")
    else:
        print("   ✓ Table exists!")
        
        # Try to describe it
        try:
            rows = db.query("PRAGMA table_info(users)")
            print("\n   Table structure:")
            for row in rows:
                print(f"     - {row}")
        except Exception as e:
            print(f"   Error getting table info: {e}")
    
    db.close()
    
except Exception as e:
    print(f"\n   ✗ ERROR: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 70)
print("\n4. Testing with explicit SQL...")

try:
    db = DB(":memory:")
    
    # Try direct SQL
    print("   Executing: CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT)")
    db.execute("CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT)")
    
    exists = db.table_exists("test")
    print(f"   Direct SQL table exists: {exists}")
    
    if exists:
        print("   ✓ Direct SQL works!")
        db.insert("test", {"name": "Alice"})
        rows = db.query("SELECT * FROM test")
        print(f"   Inserted and retrieved: {rows}")
    
    db.close()
    
except Exception as e:
    print(f"   ✗ Direct SQL failed: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 70)
print("\n5. Testing column type parsing...")

try:
    db = DB(":memory:")
    
    # Test the _parse_column_type method directly
    test_types = [
        "serial primary",
        "int",
        "str not null",
        "str unique",
        "text",
        "jsonb",
        "blob"
    ]
    
    print("   Parsed column types:")
    for type_str in test_types:
        try:
            sql_type, python_type = db._parse_column_type(type_str)
            print(f"     '{type_str}' -> SQL: '{sql_type}', Python: {python_type.__name__}")
        except Exception as e:
            print(f"     '{type_str}' -> ERROR: {e}")
    
    db.close()
    
except Exception as e:
    print(f"   ✗ Type parsing failed: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 70)
print("\n6. Testing full CREATE TABLE SQL generation...")

try:
    db = DB(":memory:")
    
    # Manually replicate what create_table does
    columns = {
        "id": "serial primary",
        "name": "str not null",
        "email": "str unique"
    }
    
    col_defs = []
    for col_name, col_type in columns.items():
        sql_type, python_type = db._parse_column_type(col_type)
        col_def = f"{col_name} {sql_type}"
        col_defs.append(col_def)
        print(f"   Column: {col_def}")
    
    sql = f"CREATE TABLE IF NOT EXISTS users ({', '.join(col_defs)})"
    print(f"\n   Generated SQL:\n   {sql}")
    
    print("\n   Executing SQL...")
    if db.engine:
        from sqlalchemy import text
        with db._connect() as conn:
            conn.execute(text(sql))
            conn.commit()
    else:
        with db._connect() as conn:
            conn.execute(sql)
            conn.commit()
    
    print("   ✓ SQL executed")
    
    exists = db.table_exists("users")
    print(f"   Table exists: {exists}")
    
    db.close()
    
except Exception as e:
    print(f"   ✗ SQL generation/execution failed: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 70)
print("DIAGNOSTIC COMPLETE")
print("=" * 70)
