# 🚀 Production Database Layer for FastAPI

**Enterprise-grade database integration with connection pooling, health monitoring, and advanced features.**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![SQLAlchemy 2.0+](https://img.shields.io/badge/sqlalchemy-2.0+-green.svg)](https://www.sqlalchemy.org/)
[![FastAPI](https://img.shields.io/badge/fastapi-0.100+-teal.svg)](https://fastapi.tiangolo.com/)

---

## 📋 Table of Contents

- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [FastAPI Integration](#-fastapi-integration)
- [Database Configuration](#-database-configuration)
- [Advanced Usage](#-advanced-usage)
- [API Examples](#-api-examples)
- [Best Practices](#-best-practices)
- [Monitoring & Health Checks](#-monitoring--health-checks)
- [Production Deployment](#-production-deployment)
- [Troubleshooting](#-troubleshooting)

---

## ✨ Features

### Core Capabilities
- 🔌 **Multi-Database Support**: SQLite, PostgreSQL, MySQL, MariaDB
- 🏊 **Connection Pooling**: Automatic pool management with health monitoring
- 🔄 **Auto-Retry**: Exponential backoff for transient failures
- 🔐 **Security**: SQL injection prevention, input validation, SSL support
- 📊 **Health Monitoring**: Real-time connection metrics and status
- 🛡️ **Circuit Breaker**: Automatic failure detection and recovery

### Advanced Features
- 📦 **JSONB Support**: Native PostgreSQL JSONB, simulated for SQLite
- 🗜️ **BLOB Compression**: Automatic compression for large binary data
- 🔍 **Full-Text Search**: GIN indexes (PostgreSQL), FTS5 (SQLite)
- 🏗️ **Query Builder**: Fluent, chainable query interface
- 🔄 **Transactions**: Context managers for atomic operations
- ✅ **Type Validation**: Automatic data type checking and coercion

---

## 📦 Installation

### Requirements

```bash
pip install fastapi uvicorn sqlalchemy python-multipart
```

### Optional Dependencies

```bash
# PostgreSQL support
pip install psycopg[binary]

# MySQL support
pip install pymysql

# Async support (optional)
pip install asyncpg  # PostgreSQL async
```

### Project Structure

```
your-fastapi-app/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI application
│   ├── database.py          # Database configuration
│   ├── models.py            # Pydantic models
│   ├── routers/
│   │   ├── __init__.py
│   │   ├── users.py
│   │   └── posts.py
│   └── dependencies.py      # Dependency injection
├── db_engine_prod.py        # Database engine layer
├── db_helper_prod.py        # ORM helper layer
├── .env                     # Environment variables
├── requirements.txt
└── README.md
```

---

## ⚡ Quick Start

### 1. Basic Setup

**database.py**
```python
from db_engine_prod import create_engine_safe, get_health_report
from db_helper_prod import DB
from contextlib import contextmanager
import os

# Database URL from environment
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///./app.db"  # Default to SQLite
)

# Create engine with production settings
engine = create_engine_safe(
    DATABASE_URL,
    pool_size=10,
    max_overflow=20,
    echo=False  # Set True for SQL debugging
)

# Create DB helper instance
db_helper = DB(engine=engine)


@contextmanager
def get_db():
    """Dependency for FastAPI routes."""
    try:
        yield db_helper
    except Exception as e:
        raise
    # Don't close - engine is persistent


def get_db_health():
    """Get database health status."""
    return get_health_report(engine)
```

### 2. Initialize Database Schema

**init_db.py**
```python
from app.database import db_helper

def init_database():
    """Initialize database tables."""
    
    # Users table
    db_helper.create_table("users", {
        "id": "serial primary",
        "email": "str unique not null",
        "username": "str unique not null",
        "hashed_password": "str not null",
        "full_name": "str",
        "is_active": "bool default TRUE",
        "profile": "jsonb",  # JSON data
        "created_at": "datetime default CURRENT_TIMESTAMP"
    })
    
    # Create indexes
    db_helper.create_index("idx_users_email", "users", "email", unique=True)
    db_helper.create_index("idx_users_username", "users", "username", unique=True)
    
    # Posts table
    db_helper.create_table("posts", {
        "id": "serial primary",
        "user_id": "int not null",
        "title": "str not null",
        "content": "text not null",
        "tags": "jsonb",
        "published": "bool default FALSE",
        "created_at": "datetime default CURRENT_TIMESTAMP",
        "updated_at": "datetime default CURRENT_TIMESTAMP"
    })
    
    db_helper.create_index("idx_posts_user", "posts", "user_id")
    db_helper.create_index("idx_posts_published", "posts", "published")
    
    # Full-text search on posts
    db_helper.create_fulltext_index("idx_posts_fts", "posts", ["title", "content"])
    
    print("✅ Database initialized successfully!")


if __name__ == "__main__":
    init_database()
```

### 3. FastAPI Application

**main.py**
```python
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from app.database import get_db, get_db_health
from db_helper_prod import DB
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="My API",
    description="FastAPI with production database layer",
    version="1.0.0"
)


# Startup event
@app.on_event("startup")
async def startup_event():
    """Initialize on startup."""
    logger.info("🚀 Application starting up...")
    health = get_db_health()
    logger.info(f"📊 Database status: {health['status']}")


# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    logger.info("👋 Application shutting down...")
    from db_engine_prod import shutdown_all_engines
    shutdown_all_engines()


# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check with database status."""
    health = get_db_health()
    
    status_code = status.HTTP_200_OK
    if health['status'] == 'UNHEALTHY':
        status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    elif health['status'] == 'DEGRADED':
        status_code = status.HTTP_200_OK  # Still operational
    
    return JSONResponse(
        content={
            "status": "ok" if health['status'] == 'HEALTHY' else "degraded",
            "database": health
        },
        status_code=status_code
    )


# Root endpoint
@app.get("/")
async def root():
    return {
        "message": "Welcome to the API",
        "docs": "/docs",
        "health": "/health"
    }
```

---

## 🔗 FastAPI Integration

### Dependency Injection Pattern

**dependencies.py**
```python
from fastapi import Depends, HTTPException, status
from app.database import get_db
from db_helper_prod import DB, DBError


def get_database() -> DB:
    """Database dependency."""
    db = next(get_db())
    return db


def require_transaction(db: DB = Depends(get_database)):
    """Dependency that ensures transaction context."""
    with db.transaction():
        yield db
```

### User Management Example

**models.py**
```python
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, Dict, Any
from datetime import datetime


class UserBase(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)
    full_name: Optional[str] = None


class UserCreate(UserBase):
    password: str = Field(..., min_length=8)


class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    profile: Optional[Dict[str, Any]] = None


class UserResponse(UserBase):
    id: int
    is_active: bool
    profile: Optional[Dict[str, Any]] = None
    created_at: datetime
    
    class Config:
        from_attributes = True


class UserInDB(UserResponse):
    hashed_password: str
```

**routers/users.py**
```python
from fastapi import APIRouter, Depends, HTTPException, status
from app.models import UserCreate, UserResponse, UserUpdate
from app.dependencies import get_database
from db_helper_prod import DB, DBError
from passlib.context import CryptContext
from typing import List

router = APIRouter(prefix="/users", tags=["users"])

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(user: UserCreate, db: DB = Depends(get_database)):
    """Create a new user."""
    try:
        # Check if user exists
        existing = db.table("users").where(email=user.email).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
        
        # Create user
        user_id = db.insert("users", {
            "email": user.email,
            "username": user.username,
            "hashed_password": hash_password(user.password),
            "full_name": user.full_name,
            "profile": {}  # Empty JSON object
        }, return_id=True)
        
        # Fetch created user
        created_user = db.table("users").where(id=user_id).first()
        return created_user
        
    except DBError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
        )


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(user_id: int, db: DB = Depends(get_database)):
    """Get user by ID."""
    user = db.table("users").where(id=user_id).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return user


@router.get("/", response_model=List[UserResponse])
async def list_users(
    skip: int = 0,
    limit: int = 100,
    db: DB = Depends(get_database)
):
    """List all users with pagination."""
    users = (db.table("users")
             .select("id", "email", "username", "full_name", "is_active", "profile", "created_at")
             .order_by("created_at", desc=True)
             .offset(skip)
             .limit(limit)
             .all())
    
    return users


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    user_update: UserUpdate,
    db: DB = Depends(get_database)
):
    """Update user profile."""
    # Check if user exists
    existing = db.table("users").where(id=user_id).first()
    if not existing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Build update data
    update_data = {}
    if user_update.full_name is not None:
        update_data["full_name"] = user_update.full_name
    if user_update.profile is not None:
        update_data["profile"] = user_update.profile
    
    if update_data:
        db.update("users", update_data, {"id": user_id})
    
    # Return updated user
    updated_user = db.table("users").where(id=user_id).first()
    return updated_user


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(user_id: int, db: DB = Depends(get_database)):
    """Delete a user."""
    deleted = db.delete("users", {"id": user_id})
    
    if deleted == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return None


@router.get("/search/{query}")
async def search_users(query: str, db: DB = Depends(get_database)):
    """Search users by username or email."""
    results = db.query(
        "SELECT * FROM users WHERE username LIKE :query OR email LIKE :query",
        {"query": f"%{query}%"}
    )
    return results
```

---

## 🗄️ Database Configuration

### Environment Variables

**.env**
```bash
# Database Configuration
DATABASE_URL=postgresql://user:password@localhost:5432/mydb

# PostgreSQL specific
DB_POOL_SIZE=20
DB_MAX_OVERFLOW=40
DB_POOL_TIMEOUT=30
DB_SSL_MODE=require

# Application
DEBUG=false
LOG_LEVEL=INFO
```

### Configuration File

**config.py**
```python
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # Database
    database_url: str = "sqlite:///./app.db"
    db_pool_size: int = 10
    db_max_overflow: int = 20
    db_pool_timeout: int = 30
    db_ssl_mode: str = "prefer"
    
    # Application
    debug: bool = False
    log_level: str = "INFO"
    
    class Config:
        env_file = ".env"


@lru_cache()
def get_settings():
    return Settings()
```

### Database Factory

**database.py** (Advanced)
```python
from db_engine_prod import create_engine_safe
from db_helper_prod import DB
from app.config import get_settings

settings = get_settings()


def create_database_engine():
    """Create database engine based on configuration."""
    
    if settings.database_url.startswith("postgresql"):
        from db_engine_prod import create_postgresql_engine
        from urllib.parse import urlparse
        
        parsed = urlparse(settings.database_url)
        
        return create_postgresql_engine(
            host=parsed.hostname,
            port=parsed.port or 5432,
            user=parsed.username,
            password=parsed.password,
            database=parsed.path.lstrip('/'),
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_max_overflow,
            sslmode=settings.db_ssl_mode,
            application_name="fastapi_app",
            timezone="UTC"
        )
    
    elif settings.database_url.startswith("sqlite"):
        from db_engine_prod import create_sqlite_engine
        
        path = settings.database_url.replace("sqlite:///", "")
        
        return create_sqlite_engine(
            path=path,
            wal=True,
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_max_overflow
        )
    
    else:
        # Generic
        return create_engine_safe(
            settings.database_url,
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_max_overflow
        )


# Global instances
engine = create_database_engine()
db_helper = DB(engine=engine)
```

---

## 🎯 Advanced Usage

### 1. Complex Queries with Query Builder

```python
from fastapi import APIRouter, Depends, Query
from app.dependencies import get_database
from db_helper_prod import DB
from typing import Optional, List

router = APIRouter(prefix="/posts", tags=["posts"])


@router.get("/")
async def list_posts(
    user_id: Optional[int] = None,
    published: Optional[bool] = None,
    search: Optional[str] = None,
    tag: Optional[str] = None,
    skip: int = 0,
    limit: int = Query(default=20, le=100),
    db: DB = Depends(get_database)
):
    """List posts with advanced filtering."""
    
    query = db.table("posts")
    
    # Filter by user
    if user_id is not None:
        query = query.where(user_id=user_id)
    
    # Filter by published status
    if published is not None:
        query = query.where(published=published)
    
    # Full-text search
    if search:
        posts = db.fulltext_search("posts", search)
        return posts
    
    # Filter by tag (JSONB query)
    if tag:
        # PostgreSQL JSONB contains
        raw_posts = db.query(
            "SELECT * FROM posts WHERE tags @> :tag::jsonb",
            {"tag": f'["{tag}"]'}
        )
        return raw_posts
    
    # Default query
    posts = (query
             .order_by("created_at", desc=True)
             .offset(skip)
             .limit(limit)
             .all())
    
    return posts


@router.get("/analytics")
async def post_analytics(db: DB = Depends(get_database)):
    """Get post analytics."""
    
    # Total posts
    total = db.table("posts").count()
    
    # Published vs draft
    published = db.table("posts").where(published=True).count()
    draft = total - published
    
    # Posts by user
    by_user = db.query("""
        SELECT user_id, COUNT(*) as post_count
        FROM posts
        GROUP BY user_id
        ORDER BY post_count DESC
        LIMIT 10
    """)
    
    return {
        "total_posts": total,
        "published": published,
        "drafts": draft,
        "top_authors": by_user
    }
```

### 2. JSONB Operations

```python
@router.post("/{post_id}/tags")
async def add_tag(
    post_id: int,
    tag: str,
    db: DB = Depends(get_database)
):
    """Add tag to post (JSONB array)."""
    
    # Get current post
    post = db.table("posts").where(id=post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    
    # Update tags
    tags = post.get("tags", [])
    if tag not in tags:
        tags.append(tag)
    
    db.update("posts", {"tags": tags}, {"id": post_id})
    
    return {"message": "Tag added", "tags": tags}


@router.get("/by-profile")
async def filter_by_profile(
    city: str,
    db: DB = Depends(get_database)
):
    """Find users by profile data (JSONB)."""
    
    # PostgreSQL: JSONB query
    if db.db_type == "postgresql":
        users = db.query_json(
            "users",
            "profile->>'city'",
            city
        )
    else:
        # SQLite: JSON functions
        users = db.query(
            "SELECT * FROM users WHERE json_extract(profile, '$.city') = ?",
            [city]
        )
    
    return users
```

### 3. Transactions

```python
@router.post("/transfer")
async def transfer_post(
    post_id: int,
    from_user_id: int,
    to_user_id: int,
    db: DB = Depends(get_database)
):
    """Transfer post ownership (transactional)."""
    
    try:
        with db.transaction():
            # Verify post ownership
            post = db.table("posts").where(
                id=post_id,
                user_id=from_user_id
            ).first()
            
            if not post:
                raise HTTPException(
                    status_code=404,
                    detail="Post not found or not owned by user"
                )
            
            # Verify target user exists
            target_user = db.table("users").where(id=to_user_id).first()
            if not target_user:
                raise HTTPException(
                    status_code=404,
                    detail="Target user not found"
                )
            
            # Transfer ownership
            db.update("posts", {"user_id": to_user_id}, {"id": post_id})
            
            # Log transfer (if you have audit log table)
            db.insert("audit_log", {
                "action": "post_transfer",
                "post_id": post_id,
                "from_user": from_user_id,
                "to_user": to_user_id,
                "timestamp": "CURRENT_TIMESTAMP"
            })
            
            return {"message": "Post transferred successfully"}
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Transfer failed: {str(e)}"
        )
```

### 4. File Upload with BLOB Storage

```python
from fastapi import UploadFile, File

@router.post("/{user_id}/avatar")
async def upload_avatar(
    user_id: int,
    file: UploadFile = File(...),
    db: DB = Depends(get_database)
):
    """Upload user avatar (stored as BLOB)."""
    
    # Verify user exists
    user = db.table("users").where(id=user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Read file content
    content = await file.read()
    
    # Validate file size (5MB limit)
    if len(content) > 5 * 1024 * 1024:
        raise HTTPException(
            status_code=400,
            detail="File too large (max 5MB)"
        )
    
    # Store in database (automatically compressed)
    db.create_table("avatars", {
        "id": "serial primary",
        "user_id": "int unique not null",
        "filename": "str not null",
        "content_type": "str",
        "data": "blob",
        "size": "int"
    }, if_not_exists=True)
    
    # Check if avatar exists
    existing = db.table("avatars").where(user_id=user_id).first()
    
    if existing:
        # Update existing
        db.update("avatars", {
            "filename": file.filename,
            "content_type": file.content_type,
            "data": content,
            "size": len(content)
        }, {"user_id": user_id})
    else:
        # Insert new
        db.insert("avatars", {
            "user_id": user_id,
            "filename": file.filename,
            "content_type": file.content_type,
            "data": content,
            "size": len(content)
        })
    
    return {
        "message": "Avatar uploaded",
        "filename": file.filename,
        "size": len(content)
    }


@router.get("/{user_id}/avatar")
async def get_avatar(user_id: int, db: DB = Depends(get_database)):
    """Get user avatar."""
    from fastapi.responses import Response
    
    avatar_data = db.get_blob("avatars", "data", {"user_id": user_id})
    
    if not avatar_data:
        raise HTTPException(status_code=404, detail="Avatar not found")
    
    # Get metadata
    avatar = db.table("avatars").where(user_id=user_id).first()
    
    return Response(
        content=avatar_data,
        media_type=avatar.get("content_type", "image/jpeg")
    )
```

---

## 📊 Monitoring & Health Checks

### Detailed Health Endpoint

```python
from fastapi import APIRouter
from app.database import get_db_health, engine
from db_engine_prod import get_pool_status

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/health/detailed")
async def detailed_health():
    """Comprehensive health check."""
    
    health = get_db_health()
    pool_status = get_pool_status(engine)
    
    return {
        "status": health['status'],
        "timestamp": health['timestamp'],
        "database": {
            "engine": health['engine_name'],
            "connection_test": health['connection_test'],
            "sqlalchemy_version": health['sqlalchemy_version']
        },
        "pool": {
            "size": pool_status.size,
            "checked_out": pool_status.checked_out,
            "overflow": pool_status.overflow,
            "utilization_percent": round(pool_status.utilization_percent, 2),
            "total_connections": pool_status.total_connections,
            "failed_connections": pool_status.failed_connections,
            "failure_rate_percent": round(pool_status.failure_rate * 100, 2)
        },
        "issues": health.get('issues', []),
        "circuit_breaker": health.get('circuit_breaker')
    }


@router.get("/metrics")
async def metrics():
    """Prometheus-style metrics."""
    from app.database import db_helper
    
    # Table statistics
    tables = db_helper.list_tables()
    table_stats = {}
    
    for table in tables:
        stats = db_helper.analyze_table(table)
        table_stats[table] = {
            "row_count": stats.get("row_count", 0)
        }
    
    pool_status = get_pool_status(engine)
    
    return {
        "database_pool_size": pool_status.size,
        "database_connections_checked_out": pool_status.checked_out,
        "database_pool_utilization": pool_status.utilization_percent,
        "database_connections_total": pool_status.total_connections,
        "database_connections_failed": pool_status.failed_connections,
        "tables": table_stats
    }
```

### Middleware for Request Logging

```python
from fastapi import Request
from time import time
import logging

logger = logging.getLogger(__name__)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all requests with timing."""
    
    start_time = time()
    
    # Process request
    response = await call_next(request)
    
    # Calculate duration
    duration = time() - start_time
    
    # Log
    logger.info(
        f"{request.method} {request.url.path} "
        f"status={response.status_code} "
        f"duration={duration:.3f}s"
    )
    
    # Add header
    response.headers["X-Process-Time"] = str(duration)
    
    return response
```

---

## 🏭 Production Deployment

### Docker Configuration

**Dockerfile**
```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create non-root user
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/health')"

# Run application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

**docker-compose.yml**
```yaml
version: '3.8'

services:
  api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://postgres:password@db:5432/myapp
      - DB_POOL_SIZE=20
      - DB_MAX_OVERFLOW=40
    depends_on:
      db:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 3s
      retries: 3
    restart: unless-stopped

  db:
    image: postgres:15-alpine
    environment:
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
      - POSTGRES_DB=myapp
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 10s
      timeout: 5s
      retries: 5
    restart: unless-stopped

volumes:
  postgres_data:
```

### Kubernetes Configuration

**deployment.yaml**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fastapi-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: fastapi-app
  template:
    metadata:
      labels:
        app: fastapi-app
    spec:
      containers:
      - name: api
        image: your-registry/fastapi-app:latest
        ports:
        - containerPort: 8000
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: db-credentials
              key: url
        - name: DB_POOL_SIZE
          value: "20"
        - name: DB_MAX_OVERFLOW
          value: "40"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
```

---

## 🎓 Best Practices

### 1. Connection Management

```python
# ✅ GOOD: Use dependency injection
@app.get("/users")
async def get_users(db: DB = Depends(get_database)):
    users = db.table("users").all()
    return users


# ❌ BAD: Creating new DB instance per request
@app.get("/users")
async def get_users():
    db = DB("./app.db")  # Don't do this!
    users = db.table("users").all()
    db.close()
    return users


# ✅ GOOD: Reuse engine across application
# In database.py
engine = create_engine_safe(DATABASE_URL)
db_helper = DB(engine=engine)

# In routes
def get_db():
    yield db_helper


# ❌ BAD: Creating engine per request
def get_db():
    engine = create_engine_safe(DATABASE_URL)  # Don't do this!
    yield DB(engine=engine)
```

### 2. Transaction Handling

```python
# ✅ GOOD: Use transaction context for atomic operations
@app.post("/transfer")
async def transfer_funds(transfer: Transfer, db: DB = Depends(get_database)):
    with db.transaction():
        # Deduct from sender
        db.execute(
            "UPDATE accounts SET balance = balance - :amount WHERE id = :id",
            {"amount": transfer.amount, "id": transfer.from_account}
        )
        
        # Add to receiver
        db.execute(
            "UPDATE accounts SET balance = balance + :amount WHERE id = :id",
            {"amount": transfer.amount, "id": transfer.to_account}
        )
        
        # Log transaction
        db.insert("transactions", {
            "from_account": transfer.from_account,
            "to_account": transfer.to_account,
            "amount": transfer.amount
        })
    
    return {"status": "success"}


# ❌ BAD: No transaction (not atomic)
@app.post("/transfer")
async def transfer_funds(transfer: Transfer, db: DB = Depends(get_database)):
    # If this succeeds but next fails, money is lost!
    db.execute(
        "UPDATE accounts SET balance = balance - :amount WHERE id = :id",
        {"amount": transfer.amount, "id": transfer.from_account}
    )
    
    # Error here = inconsistent state
    db.execute(
        "UPDATE accounts SET balance = balance + :amount WHERE id = :id",
        {"amount": transfer.amount, "id": transfer.to_account}
    )
```

### 3. Error Handling

```python
# ✅ GOOD: Proper error handling with specific exceptions
from db_helper_prod import DBError, ValidationError, SecurityError

@app.post("/users")
async def create_user(user: UserCreate, db: DB = Depends(get_database)):
    try:
        user_id = db.insert("users", {
            "email": user.email,
            "username": user.username,
            "hashed_password": hash_password(user.password)
        }, return_id=True)
        
        return {"id": user_id, "message": "User created"}
        
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Validation error: {str(e)}"
        )
    except SecurityError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Security error: {str(e)}"
        )
    except DBError as e:
        # Log the error
        logger.error(f"Database error: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database operation failed"
        )


# ❌ BAD: Generic exception handling
@app.post("/users")
async def create_user(user: UserCreate, db: DB = Depends(get_database)):
    try:
        user_id = db.insert("users", user.dict(), return_id=True)
        return {"id": user_id}
    except Exception as e:  # Too broad!
        return {"error": str(e)}  # Exposes internal details!
```

### 4. Query Optimization

```python
# ✅ GOOD: Use indexes and efficient queries
@app.get("/users/search")
async def search_users(
    email: str,
    db: DB = Depends(get_database)
):
    # Assumes index exists on email column
    users = db.table("users").where(email=email).all()
    return users


# ✅ GOOD: Pagination for large datasets
@app.get("/posts")
async def list_posts(
    skip: int = 0,
    limit: int = Query(default=20, le=100),
    db: DB = Depends(get_database)
):
    posts = (db.table("posts")
             .order_by("created_at", desc=True)
             .offset(skip)
             .limit(limit)
             .all())
    
    total = db.table("posts").count()
    
    return {
        "items": posts,
        "total": total,
        "skip": skip,
        "limit": limit
    }


# ❌ BAD: No pagination, fetching everything
@app.get("/posts")
async def list_posts(db: DB = Depends(get_database)):
    posts = db.table("posts").all()  # Could be millions of rows!
    return posts


# ✅ GOOD: Select only needed columns
@app.get("/users/minimal")
async def list_users_minimal(db: DB = Depends(get_database)):
    users = (db.table("users")
             .select("id", "email", "username")  # Only what we need
             .all())
    return users


# ❌ BAD: Fetching all columns when not needed
@app.get("/users/minimal")
async def list_users_minimal(db: DB = Depends(get_database)):
    users = db.table("users").all()  # Gets everything including BLOBs!
    return users
```

### 5. Security Best Practices

```python
# ✅ GOOD: Parameterized queries (automatic with query builder)
@app.get("/users/search")
async def search_users(email: str, db: DB = Depends(get_database)):
    users = db.table("users").where(email=email).all()
    return users


# ✅ GOOD: Even for raw SQL, use parameters
@app.get("/users/search")
async def search_users(email: str, db: DB = Depends(get_database)):
    users = db.query(
        "SELECT * FROM users WHERE email = :email",
        {"email": email}
    )
    return users


# ❌ BAD: SQL injection vulnerability!
@app.get("/users/search")
async def search_users(email: str, db: DB = Depends(get_database)):
    # NEVER DO THIS!
    users = db.query(f"SELECT * FROM users WHERE email = '{email}'")
    return users


# ✅ GOOD: Validate input
from pydantic import validator

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    
    @validator('username')
    def username_alphanumeric(cls, v):
        if not v.replace('_', '').isalnum():
            raise ValueError('Username must be alphanumeric')
        return v


# ✅ GOOD: Don't expose sensitive data
@app.get("/users/{user_id}")
async def get_user(user_id: int, db: DB = Depends(get_database)):
    user = db.table("users").where(id=user_id).first()
    
    if not user:
        raise HTTPException(status_code=404)
    
    # Remove sensitive fields
    user.pop('hashed_password', None)
    user.pop('reset_token', None)
    
    return user
```

### 6. Background Tasks

```python
from fastapi import BackgroundTasks

# ✅ GOOD: Use background tasks for non-critical operations
@app.post("/users/{user_id}/send-welcome")
async def send_welcome_email(
    user_id: int,
    background_tasks: BackgroundTasks,
    db: DB = Depends(get_database)
):
    user = db.table("users").where(id=user_id).first()
    
    if not user:
        raise HTTPException(status_code=404)
    
    # Add background task
    background_tasks.add_task(send_email, user['email'], "Welcome!")
    
    return {"message": "Welcome email queued"}


def send_email(email: str, message: str):
    """Background task - runs after response is sent."""
    # Send email logic here
    pass


# ✅ GOOD: Logging database operations in background
@app.post("/posts")
async def create_post(
    post: PostCreate,
    background_tasks: BackgroundTasks,
    db: DB = Depends(get_database)
):
    post_id = db.insert("posts", post.dict(), return_id=True)
    
    # Log asynchronously
    background_tasks.add_task(log_post_creation, post_id, db)
    
    return {"id": post_id}


def log_post_creation(post_id: int, db: DB):
    """Log post creation event."""
    db.insert("audit_log", {
        "event": "post_created",
        "post_id": post_id,
        "timestamp": "CURRENT_TIMESTAMP"
    })
```

---

## 🔧 Troubleshooting

### Common Issues

#### 1. Connection Pool Exhausted

**Symptom:**
```
TimeoutError: QueuePool limit of size 5 overflow 10 reached
```

**Solution:**
```python
# Increase pool size in configuration
engine = create_engine_safe(
    DATABASE_URL,
    pool_size=20,      # Increase from default 5
    max_overflow=40,   # Increase from default 10
    pool_timeout=60    # Increase timeout
)
```

#### 2. Memory Database Issues

**Symptom:**
```
Table not found after creation
```

**Solution:**
```python
# For :memory: databases, the fix is already applied in db_helper_prod.py
# But ensure you're not creating multiple DB instances

# ✅ GOOD
db = DB(":memory:")
db.create_table("users", {...})
users = db.table("users").all()  # Works!

# ❌ BAD
db1 = DB(":memory:")
db1.create_table("users", {...})
db2 = DB(":memory:")  # Different database!
users = db2.table("users").all()  # Table not found!
```

#### 3. Transaction Deadlocks

**Symptom:**
```
database is locked
```

**Solution:**
```python
# For SQLite: Increase busy timeout
engine = create_sqlite_engine(
    "app.db",
    wal=True  # Enable WAL mode for better concurrency
)

# For PostgreSQL: Use proper isolation levels
engine = create_postgresql_engine(
    host="localhost",
    database="mydb",
    # ... other params
)

# In your code: Keep transactions short
with db.transaction():
    # Do minimal work here
    db.insert("table", data)
    # Don't do expensive operations inside transaction
```

#### 4. Slow Queries

**Symptom:**
```
Slow query (2.34s): SELECT * FROM posts WHERE ...
```

**Solution:**
```python
# Create indexes
db.create_index("idx_posts_user", "posts", "user_id")
db.create_index("idx_posts_created", "posts", "created_at")

# Composite indexes for common queries
db.create_index(
    "idx_posts_user_created",
    "posts",
    ["user_id", "created_at"]
)

# For JSONB queries (PostgreSQL)
db.create_index(
    "idx_posts_tags",
    "posts",
    "tags",
    index_type="gin"
)

# Use EXPLAIN to analyze queries
results = db.query("EXPLAIN ANALYZE SELECT * FROM posts WHERE user_id = 1")
print(results)
```

#### 5. Circuit Breaker Opens

**Symptom:**
```
Circuit breaker OPEN - retry in 60s
```

**Solution:**
```python
from db_engine_prod import connection_circuit_breaker

# Check database health
health = get_db_health()
print(f"Status: {health['status']}")
print(f"Issues: {health['issues']}")

# If circuit is open, wait for recovery or reset manually
# The circuit will automatically attempt recovery after timeout

# To prevent circuit breaker opening:
# 1. Ensure database is reachable
# 2. Check connection limits
# 3. Monitor pool utilization
# 4. Scale database if needed
```

### Debugging Tips

#### Enable SQL Logging

```python
import logging

# Set SQLAlchemy logging to DEBUG
logging.basicConfig()
logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)

# Or enable echo in engine
engine = create_engine_safe(DATABASE_URL, echo=True)
```

#### Check Pool Status

```python
from db_engine_prod import get_pool_status

@app.get("/debug/pool")
async def debug_pool():
    status = get_pool_status(engine)
    return {
        "size": status.size,
        "checked_out": status.checked_out,
        "overflow": status.overflow,
        "utilization": f"{status.utilization_percent:.2f}%",
        "total_connections": status.total_connections,
        "failed_connections": status.failed_connections
    }
```

#### Monitor Slow Queries

```python
# Already built-in! Check logs for warnings:
# WARNING: Slow query (2.34s): SELECT ...

# To adjust threshold, modify SLOW_QUERY_THRESHOLD in db_engine_prod.py
```

---

## 📚 API Examples

### Complete CRUD Example

```python
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import List, Optional
from app.dependencies import get_database
from db_helper_prod import DB

router = APIRouter(prefix="/api/v1/products", tags=["products"])


# Pydantic Models
class ProductBase(BaseModel):
    name: str
    description: Optional[str] = None
    price: float
    stock: int
    metadata: Optional[dict] = None


class ProductCreate(ProductBase):
    pass


class ProductUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    price: Optional[float] = None
    stock: Optional[int] = None
    metadata: Optional[dict] = None


class ProductResponse(ProductBase):
    id: int
    created_at: str


# Initialize table
def init_products_table(db: DB):
    db.create_table("products", {
        "id": "serial primary",
        "name": "str not null",
        "description": "text",
        "price": "float not null",
        "stock": "int default 0",
        "metadata": "jsonb",
        "created_at": "datetime default CURRENT_TIMESTAMP"
    }, if_not_exists=True)
    
    # Create indexes
    db.create_index("idx_products_name", "products", "name")
    db.create_index("idx_products_price", "products", "price")


# CREATE
@router.post("/", response_model=ProductResponse, status_code=status.HTTP_201_CREATED)
async def create_product(
    product: ProductCreate,
    db: DB = Depends(get_database)
):
    """Create a new product."""
    product_id = db.insert("products", product.dict(), return_id=True)
    created = db.table("products").where(id=product_id).first()
    return created


# READ (single)
@router.get("/{product_id}", response_model=ProductResponse)
async def get_product(product_id: int, db: DB = Depends(get_database)):
    """Get product by ID."""
    product = db.table("products").where(id=product_id).first()
    
    if not product:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Product {product_id} not found"
        )
    
    return product


# READ (list with filters)
@router.get("/", response_model=List[ProductResponse])
async def list_products(
    skip: int = 0,
    limit: int = 100,
    min_price: Optional[float] = None,
    max_price: Optional[float] = None,
    in_stock: Optional[bool] = None,
    search: Optional[str] = None,
    db: DB = Depends(get_database)
):
    """List products with optional filters."""
    query = db.table("products")
    
    # Price filters
    if min_price is not None:
        query = query.where_raw("price >= ?", [min_price])
    if max_price is not None:
        query = query.where_raw("price <= ?", [max_price])
    
    # Stock filter
    if in_stock is not None:
        if in_stock:
            query = query.where_raw("stock > 0")
        else:
            query = query.where_raw("stock = 0")
    
    # Search
    if search:
        query = query.where_raw(
            "name LIKE ? OR description LIKE ?",
            [f"%{search}%", f"%{search}%"]
        )
    
    products = query.offset(skip).limit(limit).all()
    return products


# UPDATE
@router.patch("/{product_id}", response_model=ProductResponse)
async def update_product(
    product_id: int,
    product_update: ProductUpdate,
    db: DB = Depends(get_database)
):
    """Update product."""
    # Check if exists
    existing = db.table("products").where(id=product_id).first()
    if not existing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Product {product_id} not found"
        )
    
    # Build update data (only provided fields)
    update_data = product_update.dict(exclude_unset=True)
    
    if update_data:
        db.update("products", update_data, {"id": product_id})
    
    # Return updated product
    updated = db.table("products").where(id=product_id).first()
    return updated


# DELETE
@router.delete("/{product_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_product(product_id: int, db: DB = Depends(get_database)):
    """Delete product."""
    deleted = db.delete("products", {"id": product_id})
    
    if deleted == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Product {product_id} not found"
        )
    
    return None


# BULK OPERATIONS
@router.post("/bulk", status_code=status.HTTP_201_CREATED)
async def bulk_create_products(
    products: List[ProductCreate],
    db: DB = Depends(get_database)
):
    """Bulk create products."""
    count = db.insert_many("products", [p.dict() for p in products])
    return {"message": f"Created {count} products"}


@router.post("/{product_id}/adjust-stock")
async def adjust_stock(
    product_id: int,
    adjustment: int,
    db: DB = Depends(get_database)
):
    """Adjust product stock (transactional)."""
    with db.transaction():
        product = db.table("products").where(id=product_id).first()
        
        if not product:
            raise HTTPException(status_code=404, detail="Product not found")
        
        new_stock = product["stock"] + adjustment
        
        if new_stock < 0:
            raise HTTPException(
                status_code=400,
                detail="Insufficient stock"
            )
        
        db.update("products", {"stock": new_stock}, {"id": product_id})
        
        # Log adjustment
        db.insert("stock_adjustments", {
            "product_id": product_id,
            "adjustment": adjustment,
            "old_stock": product["stock"],
            "new_stock": new_stock
        })
    
    return {"stock": new_stock}
```

---

## 🎯 Performance Tips

### 1. Connection Pooling

```python
# Optimal pool settings for different workloads

# Low traffic API (< 100 req/s)
engine = create_engine_safe(
    DATABASE_URL,
    pool_size=5,
    max_overflow=10
)

# Medium traffic API (100-500 req/s)
engine = create_engine_safe(
    DATABASE_URL,
    pool_size=20,
    max_overflow=40
)

# High traffic API (> 500 req/s)
engine = create_engine_safe(
    DATABASE_URL,
    pool_size=50,
    max_overflow=100
)
```

### 2. Query Optimization

```python
# Use indexes
db.create_index("idx_orders_user_date", "orders", ["user_id", "created_at"])

# Analyze query plans
db.query("EXPLAIN ANALYZE SELECT * FROM orders WHERE user_id = 1")

# Use connection pooling effectively
# Keep queries fast (< 100ms)
# Avoid N+1 queries

# ❌ BAD: N+1 query problem
users = db.table("users").all()
for user in users:
    posts = db.table("posts").where(user_id=user['id']).all()  # N queries!

# ✅ GOOD: Single query with JOIN
results = db.query("""
    SELECT users.*, 
           json_agg(posts.*) as posts
    FROM users
    LEFT JOIN posts ON posts.user_id = users.id
    GROUP BY users.id
""")
```

### 3. Caching Strategy

```python
from functools import lru_cache
from fastapi_cache import FastAPICache
from fastapi_cache.decorator import cache

# In-memory cache for static data
@lru_cache(maxsize=128)
def get_categories(db: DB):
    return db.table("categories").all()

# Redis cache for frequently accessed data
@app.get("/products/{product_id}")
@cache(expire=300)  # 5 minutes
async def get_product(product_id: int, db: DB = Depends(get_database)):
    return db.table("products").where(id=product_id).first()
```

---

## 🔗 Additional Resources

- **SQLAlchemy Documentation**: https://docs.sqlalchemy.org/
- **FastAPI Documentation**: https://fastapi.tiangolo.com/
- **PostgreSQL Best Practices**: https://wiki.postgresql.org/wiki/Performance_Optimization
- **Database Design Patterns**: https://martinfowler.com/articles/patterns-of-enterprise-application-architecture.html

---

## 📄 License

MIT License - Use freely in your projects!

---

## 🤝 Contributing

Issues and pull requests welcome! This is production-tested code used in real applications.

---

## 📞 Support

For questions or issues:
- Check the troubleshooting section
- Review the examples
- Open an issue with detailed error logs

---

**Built with ❤️ for production FastAPI applications**