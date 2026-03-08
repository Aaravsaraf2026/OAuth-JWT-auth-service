# 🚀 FastAPI Database Integration - Production Ready

**Enterprise-grade database layer with PostgreSQL & SQLite support**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![SQLAlchemy 2.0+](https://img.shields.io/badge/sqlalchemy-2.0+-green.svg)](https://www.sqlalchemy.org/)
[![FastAPI](https://img.shields.io/badge/fastapi-0.100+-teal.svg)](https://fastapi.tiangolo.com/)

---

## ⚡ Quick Start (5 Minutes)

### 1. Installation

```bash
pip install fastapi uvicorn sqlalchemy psycopg[binary]
```

### 2. Project Structure

```
your-app/
├── app/
│   ├── main.py           # FastAPI app
│   ├── database.py       # DB configuration
│   └── routers/          # API routes
├── db_engine_prod.py     # Connection engine
├── db_helper_prod.py     # ORM layer
├── .env                  # Environment vars
└── init_db.py           # Schema initialization
```

### 3. Database Configuration

**`.env` file:**
```bash
# PostgreSQL
DATABASE_URL=postgresql://user:password@localhost:5432/mydb

# SQLite (alternative)
# DATABASE_URL=sqlite:///./app.db

# Connection Pool
DB_POOL_SIZE=20
DB_MAX_OVERFLOW=40
```

**`app/database.py`:**
```python
from db_engine_prod import create_engine_safe
from db_helper_prod import DB
from contextlib import contextmanager
import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite3:///./app.db")

# Create engine (reused across app)
engine = create_engine_safe(
    DATABASE_URL,
    pool_size=20,
    max_overflow=40
)

# Create DB helper
db_helper = DB(engine=engine)

@contextmanager
def get_db():
    """Database dependency."""
    try:
        yield db_helper
    except Exception:
        raise
```

### 4. Initialize Schema

**`init_db.py`:**
```python
from app.database import db_helper

def init_database():
    # Users table
    db_helper.create_table("users", {
        "id": "serial primary",
        "email": "str unique not null",
        "username": "str unique not null",
        "hashed_password": "str not null",
        "profile": "jsonb",  # JSON data
        "created_at": "datetime default CURRENT_TIMESTAMP"
    })
    
    # Indexes
    db_helper.create_index("idx_users_email", "users", "email", unique=True)
    
    print("✅ Database initialized!")

if __name__ == "__main__":
    init_database()
```

Run: `python init_db.py`

### 5. FastAPI Application

**`app/main.py`:**
```python
from fastapi import FastAPI, Depends, HTTPException
from app.database import get_db
from db_helper_prod import DB
from pydantic import BaseModel

app = FastAPI()

class UserCreate(BaseModel):
    email: str
    username: str
    password: str

def get_database():
    return next(get_db())

@app.post("/users")
async def create_user(user: UserCreate, db: DB = Depend(get_database)):
    user_id = db.insert("users", {
        "email": user.email,
        "username": user.username,
        "hashed_password": hash_password(user.password),
        "profile": {}
    }, return_id=True)
    
    return {"id": user_id, "email": user.email}

@app.get("/users/{user_id}")
async def get_user(user_id: int, db: DB = Depends(get_database)):
    user = db.table("users").where(id=user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@app.get("/health")
async def health_check():
    from db_engine_prod import get_health_report
    from app.database import engine
    health = get_health_report(engine)
    return {"status": health['status']}
```

Run: `uvicorn app.main:app --reload`

---

## 🐘 PostgreSQL Setup

### Local Development

```bash
# Install PostgreSQL
sudo apt install postgresql  # Ubuntu
brew install postgresql@15   # macOS

# Create database
sudo -u postgres psql
CREATE DATABASE myapp;
CREATE USER myapp_user WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE myapp TO myapp_user;
\q

# Update .env
DATABASE_URL=postgresql://myapp_user:secure_password@localhost:5432/myapp
```

### Docker Compose

**`docker-compose.yml`:**
```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_USER: myapp_user
      POSTGRES_PASSWORD: secure_password
      POSTGRES_DB: myapp
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U myapp_user"]
      interval: 10s
      timeout: 5s
      retries: 5

  api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://myapp_user:secure_password@postgres:5432/myapp
    depends_on:
      postgres:
        condition: service_healthy

volumes:
  postgres_data:
```

**Commands:**
```bash
docker-compose up -d          # Start services
docker-compose logs -f api    # View logs
docker-compose down           # Stop services
```

---

## 🎯 Common Use Cases

### 1. CRUD Operations

```python
from fastapi import APIRouter, Depends
from app.database import get_database
from db_helper_prod import DB

router = APIRouter()

# CREATE
@router.post("/posts")
async def create_post(title: str, content: str, db: DB = Depends(get_database)):
    post_id = db.insert("posts", {
        "title": title,
        "content": content,
        "tags": ["python", "fastapi"]  # JSONB
    }, return_id=True)
    return {"id": post_id}

# READ
@router.get("/posts/{post_id}")
async def get_post(post_id: int, db: DB = Depends(get_database)):
    return db.table("posts").where(id=post_id).first()

# UPDATE
@router.patch("/posts/{post_id}")
async def update_post(post_id: int, title: str, db: DB = Depends(get_database)):
    db.update("posts", {"title": title}, {"id": post_id})
    return {"message": "Updated"}

# DELETE
@router.delete("/posts/{post_id}")
async def delete_post(post_id: int, db: DB = Depends(get_database)):
    db.delete("posts", {"id": post_id})
    return {"message": "Deleted"}

# LIST with Pagination
@router.get("/posts")
async def list_posts(skip: int = 0, limit: int = 20, db: DB = Depends(get_database)):
    return db.table("posts").offset(skip).limit(limit).all()
```

### 2. Query Builder (Fluent Interface)

```python
# Simple query
users = db.table("users").where(is_active=True).all()

# Complex query
posts = (db.table("posts")
         .where(published=True)
         .where_raw("view_count > ?", [100])
         .order_by("created_at", desc=True)
         .limit(10)
         .all())

# Count
active_users = db.table("users").where(is_active=True).count()

# First result
user = db.table("users").where(email="alice@example.com").first()
```

### 3. Transactions

```python
@router.post("/transfer")
async def transfer(from_id: int, to_id: int, amount: float, db: DB = Depends(get_database)):
    with db.transaction():
        # Deduct from sender
        db.execute(
            "UPDATE accounts SET balance = balance - :amt WHERE id = :id",
            {"amt": amount, "id": from_id}
        )
        
        # Add to receiver
        db.execute(
            "UPDATE accounts SET balance = balance + :amt WHERE id = :id",
            {"amt": amount, "id": to_id}
        )
        
        # If any operation fails, entire transaction rolls back
    
    return {"status": "success"}
```

### 4. JSONB Queries (PostgreSQL)

```python
# Find users by city in profile
users = db.query_json("users", "profile->>'city'", "NYC")

# Check if JSON contains key
users = db.query(
    "SELECT * FROM users WHERE profile ? :key",
    {"key": "phone"}
)

# Update specific JSON fields
db.execute(
    "UPDATE users SET profile = profile || :data::jsonb WHERE id = :id",
    {"data": json.dumps({"city": "SF"}), "id": user_id}
)
```

### 5. Full-Text Search

```python
# Search posts
results = db.fulltext_search("posts", "python tutorial")

# PostgreSQL with ranking
results = db.query("""
    SELECT *, 
           ts_rank(to_tsvector('english', title || ' ' || content), 
                   plainto_tsquery('english', :query)) as rank
    FROM posts
    WHERE to_tsvector('english', title || ' ' || content) 
          @@ plainto_tsquery('english', :query)
    ORDER BY rank DESC
""", {"query": search_term})
```

### 6. File Upload (BLOB)

```python
from fastapi import UploadFile, File

@router.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    db: DB = Depends(get_database)
):
    content = await file.read()
    
    file_id = db.insert("files", {
        "filename": file.filename,
        "content_type": file.content_type,
        "data": content  # Automatically compressed
    }, return_id=True)
    
    return {"id": file_id, "size": len(content)}

@router.get("/files/{file_id}")
async def download_file(file_id: int, db: DB = Depends(get_database)):
    from fastapi.responses import Response
    
    data = db.get_blob("files", "data", {"id": file_id})
    file_info = db.table("files").where(id=file_id).first()
    
    return Response(content=data, media_type=file_info["content_type"])
```

---

## 🔧 Best Practices

### ✅ DO

```python
# Use dependency injection
@app.get("/users")
async def get_users(db: DB = Depends(get_database)):
    return db.table("users").all()

# Use transactions for multiple operations
with db.transaction():
    db.insert("users", {...})
    db.insert("audit_log", {...})

# Use parameterized queries
db.query("SELECT * FROM users WHERE email = :email", {"email": email})

# Add indexes
db.create_index("idx_posts_user", "posts", "user_id")

# Paginate large results
db.table("posts").offset(skip).limit(100).all()
```

### ❌ DON'T

```python
# Don't create new DB instance per request
db = DB("./app.db")  # Bad!

# Don't concatenate SQL strings
db.query(f"SELECT * FROM users WHERE email = '{email}'")  # SQL injection!

# Don't fetch all rows without limit
db.table("posts").all()  # Could be millions!

# Don't ignore errors
try:
    db.insert("users", data)
except:
    pass  # Silent failure!
```

---

## 🏥 Health & Monitoring

```python
from db_engine_prod import get_health_report, get_pool_status

@app.get("/health")
async def health():
    health = get_health_report(engine)
    return {
        "status": health['status'],
        "issues": health['issues'],
        "pool_utilization": health['pool_utilization']
    }

@app.get("/metrics")
async def metrics():
    pool = get_pool_status(engine)
    return {
        "pool_size": pool.size,
        "connections_active": pool.checked_out,
        "utilization_percent": pool.utilization_percent
    }
```

---

## 🐛 Troubleshooting

| Problem | Solution |
|---------|----------|
| **Pool exhausted** | Increase `pool_size` and `max_overflow` |
| **Slow queries** | Add indexes, use `EXPLAIN ANALYZE` |
| **Connection timeout** | Check database is running, verify credentials |
| **`:memory:` table not found** | Already fixed in `db_helper_prod.py` v3.0.1 |
| **Transaction deadlock** | Keep transactions short, retry failed operations |

---

## 📦 Features Summary

- ✅ **Multi-database**: PostgreSQL, SQLite, MySQL
- ✅ **Connection Pooling**: Automatic management
- ✅ **Auto-retry**: Exponential backoff
- ✅ **Circuit Breaker**: Failure protection
- ✅ **JSONB Support**: Native PostgreSQL, simulated SQLite
- ✅ **BLOB Compression**: Automatic for large files
- ✅ **Full-text Search**: GIN indexes, FTS5
- ✅ **Query Builder**: Fluent, chainable API
- ✅ **Transactions**: Context managers
- ✅ **Health Checks**: Production-ready monitoring
- ✅ **Type Validation**: Automatic checking
- ✅ **Security**: SQL injection prevention

---

## 📚 Documentation

- **SQLAlchemy**: https://docs.sqlalchemy.org/
- **FastAPI**: https://fastapi.tiangolo.com/
- **PostgreSQL**: https://www.postgresql.org/docs/

---

## 📄 License

MIT License - Use freely in production!

**Built with ❤️ for FastAPI applications**
