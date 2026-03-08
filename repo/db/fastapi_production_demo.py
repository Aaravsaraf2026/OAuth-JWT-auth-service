"""
FastAPI Production Demo - Complete REST API with Database Layer

A production-ready FastAPI application demonstrating:
✓ RESTful API with full CRUD operations
✓ Database integration (db_engine.py + db_helper.py)
✓ Request validation with Pydantic
✓ JWT authentication & authorization
✓ CORS configuration
✓ Rate limiting
✓ Health checks & monitoring
✓ Error handling
✓ Swagger/OpenAPI documentation
✓ Async operations
✓ File uploads (BLOB)
✓ Full-text search
✓ JSONB queries

Requirements:
    pip install fastapi uvicorn python-jose[cryptography] passlib[bcrypt] python-multipart slowapi

Run:
    uvicorn fastapi_demo:app --reload --host 0.0.0.0 --port 8000

API Documentation:
    http://localhost:8000/docs (Swagger UI)
    http://localhost:8000/redoc (ReDoc)

Author: Production Team
Version: 1.0.0
"""

from fastapi import (
    FastAPI, HTTPException, Depends, status, 
    UploadFile, File, Query, Path, Body
)
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
import logging
import io
import os

# JWT & Password
from jose import JWTError, jwt
from passlib.context import CryptContext

# Rate limiting
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Database imports
from db_engine import create_engine_safe, get_health_report, shutdown_engine
from db_helper import DB

# ============================================================================
# CONFIGURATION
# ============================================================================

# JWT Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Database Configuration
DATABASE_URL = os.getenv("DATABASE_URL", "./fastapi_demo.db")

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Rate limiter
limiter = Limiter(key_func=get_remote_address)

# Security
security = HTTPBearer()


# ============================================================================
# GLOBAL STATE & LIFECYCLE
# ============================================================================

# Global database instance
db: Optional[DB] = None
engine = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    global db, engine
    
    # Startup
    logger.info("Starting up FastAPI application...")
    
    # Initialize database engine
    engine = create_engine_safe(DATABASE_URL, wal=True)
    db = DB(engine=engine)
    
    # Create tables
    init_database(db)
    
    logger.info("Database initialized successfully")
    logger.info(f"API running at http://localhost:8000")
    logger.info(f"Docs at http://localhost:8000/docs")
    
    yield
    
    # Shutdown
    logger.info("Shutting down...")
    if db:
        db.close()
    if engine:
        shutdown_engine(engine)
    logger.info("Shutdown complete")


# ============================================================================
# FASTAPI APP
# ============================================================================

app = FastAPI(
    title="Production FastAPI Demo",
    description="Complete REST API with database integration, auth, and monitoring",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add rate limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production: specify actual origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# PYDANTIC MODELS
# ============================================================================

class UserCreate(BaseModel):
    """User registration model."""
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)
    full_name: str = Field(..., min_length=1, max_length=100)
    
    @validator('username')
    def username_alphanumeric(cls, v):
        assert v.isalnum(), 'must be alphanumeric'
        return v


class UserLogin(BaseModel):
    """User login model."""
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    """User response model."""
    id: int
    email: str
    username: str
    full_name: str
    is_active: bool
    created_at: str


class Token(BaseModel):
    """JWT token response."""
    access_token: str
    token_type: str = "bearer"


class ProductCreate(BaseModel):
    """Product creation model."""
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    price: float = Field(..., gt=0)
    category: str
    metadata: Optional[Dict[str, Any]] = None
    tags: List[str] = []


class ProductUpdate(BaseModel):
    """Product update model."""
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = None
    price: Optional[float] = Field(None, gt=0)
    category: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    tags: Optional[List[str]] = None


class ProductResponse(BaseModel):
    """Product response model."""
    id: int
    name: str
    description: Optional[str]
    price: float
    category: str
    metadata: Optional[Dict[str, Any]]
    tags: List[str]
    created_at: str
    updated_at: str


class ArticleCreate(BaseModel):
    """Article creation model."""
    title: str = Field(..., min_length=1, max_length=500)
    content: str = Field(..., min_length=1)
    author: str
    category: str
    tags: List[str] = []


class ArticleResponse(BaseModel):
    """Article response model."""
    id: int
    title: str
    content: str
    author: str
    category: str
    tags: List[str]
    published_at: str


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    timestamp: str
    database: Dict[str, Any]
    version: str


# ============================================================================
# DATABASE INITIALIZATION
# ============================================================================

def init_database(db: DB):
    """Initialize database tables."""
    
    # Users table
    db.create_table("users", {
        "id": "serial primary",
        "email": "str unique not null",
        "username": "str unique not null",
        "full_name": "str not null",
        "hashed_password": "str not null",
        "is_active": "bool default 1",
        "created_at": "datetime default CURRENT_TIMESTAMP"
    })
    
    # Products table with JSONB
    db.create_table("products", {
        "id": "serial primary",
        "name": "str not null",
        "description": "text",
        "price": "float not null",
        "category": "str not null",
        "metadata": "jsonb",
        "tags": "jsonb",
        "created_at": "datetime default CURRENT_TIMESTAMP",
        "updated_at": "datetime default CURRENT_TIMESTAMP"
    })
    
    # Articles table for full-text search
    db.create_table("articles", {
        "id": "serial primary",
        "title": "str not null",
        "content": "text not null",
        "author": "str not null",
        "category": "str",
        "tags": "jsonb",
        "published_at": "datetime default CURRENT_TIMESTAMP"
    })
    
    # Files table with BLOB
    db.create_table("files", {
        "id": "serial primary",
        "filename": "str not null",
        "content_type": "str",
        "data": "blob",
        "size": "int",
        "uploaded_by": "int",
        "uploaded_at": "datetime default CURRENT_TIMESTAMP"
    })
    
    # Create indexes
    db.create_index("idx_users_email", "users", "email", unique=True)
    db.create_index("idx_products_category", "products", "category")
    db.create_index("idx_articles_author", "articles", "author")
    
    # Full-text search index
    db.create_fulltext_index("idx_articles_fts", "articles", ["title", "content"])
    
    logger.info("Database tables and indexes created")


# ============================================================================
# AUTHENTICATION & AUTHORIZATION
# ============================================================================

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash password."""
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current authenticated user."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = db.query("SELECT * FROM users WHERE email = ?", [email], one=True)
    if user is None:
        raise credentials_exception
    
    return user


# ============================================================================
# ROOT & HEALTH ENDPOINTS
# ============================================================================

@app.get("/", tags=["Root"])
async def root():
    """Root endpoint."""
    return {
        "message": "FastAPI Production Demo API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health"
    }


@app.get("/health", response_model=HealthResponse, tags=["Health"])
@limiter.limit("60/minute")
async def health_check():
    """Health check endpoint with database status."""
    try:
        # Test database connection
        db.query("SELECT 1", one=True)
        
        # Get engine health
        health = get_health_report(engine)
        
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "database": {
                "status": health["status"],
                "pool_utilization": health["pool_utilization"],
                "connection_test": health["connection_test"]
            },
            "version": "1.0.0"
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "timestamp": datetime.utcnow().isoformat(),
                "error": str(e)
            }
        )


# ============================================================================
# AUTHENTICATION ENDPOINTS
# ============================================================================

@app.post("/auth/register", response_model=UserResponse, status_code=201, tags=["Authentication"])
@limiter.limit("5/minute")
async def register(user: UserCreate):
    """Register a new user."""
    
    # Check if user exists
    existing = db.query("SELECT id FROM users WHERE email = ? OR username = ?", 
                       [user.email, user.username], one=True)
    if existing:
        raise HTTPException(status_code=400, detail="Email or username already registered")
    
    # Hash password
    hashed_password = get_password_hash(user.password)
    
    # Create user
    user_id = db.insert("users", {
        "email": user.email,
        "username": user.username,
        "full_name": user.full_name,
        "hashed_password": hashed_password
    }, return_id=True)
    
    # Return user
    created_user = db.query("SELECT * FROM users WHERE id = ?", [user_id], one=True)
    
    return {
        "id": created_user["id"],
        "email": created_user["email"],
        "username": created_user["username"],
        "full_name": created_user["full_name"],
        "is_active": bool(created_user["is_active"]),
        "created_at": created_user["created_at"]
    }


@app.post("/auth/login", response_model=Token, tags=["Authentication"])
@limiter.limit("10/minute")
async def login(user: UserLogin):
    """Login and get JWT token."""
    
    # Find user
    db_user = db.query("SELECT * FROM users WHERE email = ?", [user.email], one=True)
    
    if not db_user or not verify_password(user.password, db_user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )
    
    if not db_user["is_active"]:
        raise HTTPException(status_code=400, detail="Inactive user")
    
    # Create token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": db_user["email"]},
        expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/auth/me", response_model=UserResponse, tags=["Authentication"])
async def get_me(current_user = Depends(get_current_user)):
    """Get current user info."""
    return {
        "id": current_user["id"],
        "email": current_user["email"],
        "username": current_user["username"],
        "full_name": current_user["full_name"],
        "is_active": bool(current_user["is_active"]),
        "created_at": current_user["created_at"]
    }


# ============================================================================
# PRODUCTS ENDPOINTS (CRUD with JSONB)
# ============================================================================

@app.post("/products", response_model=ProductResponse, status_code=201, tags=["Products"])
@limiter.limit("30/minute")
async def create_product(
    product: ProductCreate,
    current_user = Depends(get_current_user)
):
    """Create a new product with JSONB metadata."""
    
    product_id = db.insert("products", {
        "name": product.name,
        "description": product.description,
        "price": product.price,
        "category": product.category,
        "metadata": product.metadata or {},
        "tags": product.tags
    }, return_id=True)
    
    created = db.query("SELECT * FROM products WHERE id = ?", [product_id], one=True)
    
    return {
        "id": created["id"],
        "name": created["name"],
        "description": created["description"],
        "price": created["price"],
        "category": created["category"],
        "metadata": created["metadata"],
        "tags": created["tags"],
        "created_at": created["created_at"],
        "updated_at": created["updated_at"]
    }


@app.get("/products", response_model=List[ProductResponse], tags=["Products"])
@limiter.limit("60/minute")
async def list_products(
    skip: int = Query(0, ge=0),
    limit: int = Query(10, ge=1, le=100),
    category: Optional[str] = None,
    min_price: Optional[float] = None,
    max_price: Optional[float] = None
):
    """List products with filters."""
    
    query = db.table("products")
    
    if category:
        query = query.where(category=category)
    
    if min_price is not None or max_price is not None:
        conditions = []
        if min_price is not None:
            conditions.append(f"price >= {min_price}")
        if max_price is not None:
            conditions.append(f"price <= {max_price}")
        query = query.where_raw(" AND ".join(conditions))
    
    products = query.order_by("created_at", desc=True).offset(skip).limit(limit).all()
    
    return [
        {
            "id": p["id"],
            "name": p["name"],
            "description": p["description"],
            "price": p["price"],
            "category": p["category"],
            "metadata": p["metadata"],
            "tags": p["tags"],
            "created_at": p["created_at"],
            "updated_at": p["updated_at"]
        }
        for p in products
    ]


@app.get("/products/{product_id}", response_model=ProductResponse, tags=["Products"])
@limiter.limit("60/minute")
async def get_product(product_id: int = Path(..., ge=1)):
    """Get product by ID."""
    
    product = db.query("SELECT * FROM products WHERE id = ?", [product_id], one=True)
    
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    
    return {
        "id": product["id"],
        "name": product["name"],
        "description": product["description"],
        "price": product["price"],
        "category": product["category"],
        "metadata": product["metadata"],
        "tags": product["tags"],
        "created_at": product["created_at"],
        "updated_at": product["updated_at"]
    }


@app.put("/products/{product_id}", response_model=ProductResponse, tags=["Products"])
@limiter.limit("30/minute")
async def update_product(
    product_id: int = Path(..., ge=1),
    product: ProductUpdate = Body(...),
    current_user = Depends(get_current_user)
):
    """Update product."""
    
    # Check if exists
    existing = db.query("SELECT id FROM products WHERE id = ?", [product_id], one=True)
    if not existing:
        raise HTTPException(status_code=404, detail="Product not found")
    
    # Build update data
    update_data = {}
    if product.name is not None:
        update_data["name"] = product.name
    if product.description is not None:
        update_data["description"] = product.description
    if product.price is not None:
        update_data["price"] = product.price
    if product.category is not None:
        update_data["category"] = product.category
    if product.metadata is not None:
        update_data["metadata"] = product.metadata
    if product.tags is not None:
        update_data["tags"] = product.tags
    
    update_data["updated_at"] = datetime.utcnow().isoformat()
    
    # Update
    db.update("products", update_data, {"id": product_id})
    
    # Return updated
    updated = db.query("SELECT * FROM products WHERE id = ?", [product_id], one=True)
    
    return {
        "id": updated["id"],
        "name": updated["name"],
        "description": updated["description"],
        "price": updated["price"],
        "category": updated["category"],
        "metadata": updated["metadata"],
        "tags": updated["tags"],
        "created_at": updated["created_at"],
        "updated_at": updated["updated_at"]
    }


@app.delete("/products/{product_id}", status_code=204, tags=["Products"])
@limiter.limit("30/minute")
async def delete_product(
    product_id: int = Path(..., ge=1),
    current_user = Depends(get_current_user)
):
    """Delete product."""
    
    deleted = db.delete("products", {"id": product_id})
    
    if deleted == 0:
        raise HTTPException(status_code=404, detail="Product not found")
    
    return None


# ============================================================================
# ARTICLES ENDPOINTS (FULL-TEXT SEARCH)
# ============================================================================

@app.post("/articles", response_model=ArticleResponse, status_code=201, tags=["Articles"])
@limiter.limit("20/minute")
async def create_article(
    article: ArticleCreate,
    current_user = Depends(get_current_user)
):
    """Create a new article."""
    
    article_id = db.insert("articles", {
        "title": article.title,
        "content": article.content,
        "author": article.author,
        "category": article.category,
        "tags": article.tags
    }, return_id=True)
    
    created = db.query("SELECT * FROM articles WHERE id = ?", [article_id], one=True)
    
    return {
        "id": created["id"],
        "title": created["title"],
        "content": created["content"],
        "author": created["author"],
        "category": created["category"],
        "tags": created["tags"],
        "published_at": created["published_at"]
    }


@app.get("/articles/search", response_model=List[ArticleResponse], tags=["Articles"])
@limiter.limit("60/minute")
async def search_articles(q: str = Query(..., min_length=1)):
    """Full-text search articles."""
    
    results = db.fulltext_search("articles", q)
    
    return [
        {
            "id": r["id"],
            "title": r["title"],
            "content": r["content"],
            "author": r["author"],
            "category": r["category"],
            "tags": r["tags"],
            "published_at": r["published_at"]
        }
        for r in results
    ]


@app.get("/articles", response_model=List[ArticleResponse], tags=["Articles"])
@limiter.limit("60/minute")
async def list_articles(
    skip: int = Query(0, ge=0),
    limit: int = Query(10, ge=1, le=100),
    author: Optional[str] = None,
    category: Optional[str] = None
):
    """List articles with filters."""
    
    query = db.table("articles")
    
    if author:
        query = query.where(author=author)
    if category:
        query = query.where(category=category)
    
    articles = query.order_by("published_at", desc=True).offset(skip).limit(limit).all()
    
    return [
        {
            "id": a["id"],
            "title": a["title"],
            "content": a["content"],
            "author": a["author"],
            "category": a["category"],
            "tags": a["tags"],
            "published_at": a["published_at"]
        }
        for a in articles
    ]


# ============================================================================
# FILE UPLOAD ENDPOINTS (BLOB)
# ============================================================================

@app.post("/files/upload", status_code=201, tags=["Files"])
@limiter.limit("10/minute")
async def upload_file(
    file: UploadFile = File(...),
    current_user = Depends(get_current_user)
):
    """Upload a file (stored as BLOB)."""
    
    # Read file content
    content = await file.read()
    
    # Validate size (max 10MB)
    if len(content) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large (max 10MB)")
    
    # Store file
    file_id = db.insert("files", {
        "filename": file.filename,
        "content_type": file.content_type,
        "data": content,
        "size": len(content),
        "uploaded_by": current_user["id"]
    }, return_id=True)
    
    return {
        "id": file_id,
        "filename": file.filename,
        "content_type": file.content_type,
        "size": len(content),
        "message": "File uploaded successfully"
    }


@app.get("/files/{file_id}", tags=["Files"])
@limiter.limit("60/minute")
async def download_file(file_id: int = Path(..., ge=1)):
    """Download a file."""
    
    file = db.query(
        "SELECT filename, content_type, data FROM files WHERE id = ?",
        [file_id],
        one=True
    )
    
    if not file:
        raise HTTPException(status_code=404, detail="File not found")
    
    # Decode BLOB
    content = db.get_blob("files", "data", {"id": file_id})
    
    return StreamingResponse(
        io.BytesIO(content),
        media_type=file["content_type"],
        headers={"Content-Disposition": f'attachment; filename="{file["filename"]}"'}
    )


@app.get("/files", tags=["Files"])
@limiter.limit("60/minute")
async def list_files(
    skip: int = Query(0, ge=0),
    limit: int = Query(10, ge=1, le=100),
    current_user = Depends(get_current_user)
):
    """List uploaded files (metadata only)."""
    
    files = db.query("""
        SELECT id, filename, content_type, size, uploaded_at
        FROM files
        WHERE uploaded_by = ?
        ORDER BY uploaded_at DESC
        LIMIT ? OFFSET ?
    """, [current_user["id"], limit, skip])
    
    return files


# ============================================================================
# STATISTICS & ANALYTICS
# ============================================================================

@app.get("/stats/products", tags=["Statistics"])
@limiter.limit("30/minute")
async def product_statistics():
    """Get product statistics."""
    
    stats = db.query("""
        SELECT 
            category,
            COUNT(*) as count,
            AVG(price) as avg_price,
            MIN(price) as min_price,
            MAX(price) as max_price
        FROM products
        GROUP BY category
        ORDER BY count DESC
    """)
    
    total = db.query("SELECT COUNT(*) as total FROM products", one=True)
    
    return {
        "total_products": total["total"],
        "by_category": [
            {
                "category": s["category"],
                "count": s["count"],
                "avg_price": float(s["avg_price"]),
                "min_price": float(s["min_price"]),
                "max_price": float(s["max_price"])
            }
            for s in stats
        ]
    }


@app.get("/stats/articles", tags=["Statistics"])
@limiter.limit("30/minute")
async def article_statistics():
    """Get article statistics."""
    
    stats = db.query("""
        SELECT 
            author,
            COUNT(*) as article_count
        FROM articles
        GROUP BY author
        ORDER BY article_count DESC
    """)
    
    total = db.query("SELECT COUNT(*) as total FROM articles", one=True)
    
    return {
        "total_articles": total["total"],
        "by_author": [
            {
                "author": s["author"],
                "article_count": s["article_count"]
            }
            for s in stats
        ]
    }


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    
    print("=" * 80)
    print("FastAPI Production Demo")
    print("=" * 80)
    print()
    print("Starting server...")
    print("API: http://localhost:8000")
    print("Docs: http://localhost:8000/docs")
    print("ReDoc: http://localhost:8000/redoc")
    print()
    
    uvicorn.run(
        "fastapi_demo:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
