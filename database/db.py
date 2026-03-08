import os
import logging
import asyncio

from repo.db import (
    shutdown_engine,
    create_engine_safe,
    DB,
    get_health_report
)

logger = logging.getLogger(__name__)


# ============================================================================
# DATABASE CONNECTION
# ============================================================================

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")

engine = create_engine_safe(
    DATABASE_URL,
    pool_size=20,
    max_overflow=40,
    echo=False
)

db = DB(engine=engine)

logger.info(f"Database connected: {DATABASE_URL}")


# ============================================================================
# SCHEMA INITIALIZATION
# ============================================================================

async def init_schema():

    logger.info("Initializing database schema...")
    await asyncio.to_thread(_create_tables)
    logger.info("Schema initialized")

    tables = db.list_tables()
    logger.info(f"Tables: {tables}")


def _create_tables():

    db.create_table("users", {
        "id": "serial primary",
        "email": "str unique not null",
        "username": "str not null",
        "hashed_password": "str",
        "profile": "jsonb",
        "created_at": "datetime default CURRENT_TIMESTAMP",
        "last_login": "datetime"
    }, if_not_exists=True)

    db.create_index("idx_users_email", "users", "email", unique=True)
    db.create_index("idx_users_username", "users", "username")

    db.create_table("sessions", {
        "id": "serial primary",
        "user_id": "int not null",
        "access_token": "str unique not null",
        "refresh_token": "str unique not null",
        "expires_at": "datetime not null",
        "created_at": "datetime default CURRENT_TIMESTAMP"
    }, if_not_exists=True)

    db.create_index("idx_sessions_user", "sessions", "user_id")


# ============================================================================
# FASTAPI DEPENDENCY
# ============================================================================

def get_db() -> DB:
    return db


# ============================================================================
# SHUTDOWN
# ============================================================================

async def close_db():

    logger.info("Closing database...")
    await asyncio.to_thread(shutdown_engine, engine)
    logger.info("Database closed")


# ============================================================================
# HEALTH CHECK
# ============================================================================

def get_db_health():
    return get_health_report(engine)