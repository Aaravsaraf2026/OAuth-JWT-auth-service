import os
import logging
from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    DateTime,
    JSON,
    ForeignKey
)
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.sql import func

from repo.db import shutdown_engine, get_health_report

logger = logging.getLogger(__name__)

# ============================================================================
# DATABASE CONNECTION
# ============================================================================

# DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")
DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(
    DATABASE_URL,
    pool_size=20,
    max_overflow=40,
    echo=False,
    future=True
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()

logger.info(f"Database connected: {DATABASE_URL}")

# ============================================================================
# MODELS
# ============================================================================

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    username = Column(String, index=True, nullable=False)
    hashed_password = Column(String)
    profile = Column(JSON)
    created_at = Column(DateTime, server_default=func.now())
    last_login = Column(DateTime)


class Session(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    access_token = Column(String, unique=True, nullable=False)
    refresh_token = Column(String, unique=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, server_default=func.now())

# ============================================================================
# SCHEMA INITIALIZATION
# ============================================================================

async def init_schema():

    logger.info("Initializing database schema...")
    Base.metadata.create_all(bind=engine)
    logger.info("Schema initialized")

# ============================================================================
# FASTAPI DEPENDENCY
# ============================================================================

def get_db():

    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()

# ============================================================================
# SHUTDOWN
# ============================================================================

async def close_db():

    logger.info("Closing database...")
    shutdown_engine(engine)
    logger.info("Database closed")

# ============================================================================
# HEALTH CHECK
# ============================================================================

def get_db_health():
    return get_health_report(engine)