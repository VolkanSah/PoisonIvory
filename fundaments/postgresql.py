# PyFundaments: A Secure Python Architecture
# Copyright 2008-2025 - Volkan Kücükbudak
# Apache License V. 2
# Repo: https://github.com/VolkanSah/PyFundaments
# fundaments/postgresql.py
import os
import logging
import asyncpg
import ssl
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

_db_pool: Optional[asyncpg.Pool] = None

def enforce_cloud_security(dsn_url: str) -> str:
    """
    Enforces security settings for cloud environments.
    - Ensures SSL mode is at least 'require'
    - Removes unsupported options for cloud providers (e.g. statement_timeout for Neon)
    - Sets connect_timeout and keepalives_idle defaults
    """
    parsed = urlparse(dsn_url)
    query_params = parse_qs(parsed.query)

    # Enforce SSL (at least 'require')
    sslmode = query_params.get('sslmode', ['prefer'])[0].lower()
    if sslmode not in ['require', 'verify-ca', 'verify-full']:
        query_params['sslmode'] = ['require']

    # Set timeouts and keep-alives if not present
    if 'connect_timeout' not in query_params:
        query_params['connect_timeout'] = ['5']
    if 'keepalives_idle' not in query_params:
        query_params['keepalives_idle'] = ['60']

    # Remove statement_timeout option for Neon
    if 'neon.tech' in parsed.netloc:
        if 'options' in query_params:
            options_clean = []
            for opt in query_params['options']:
                if 'statement_timeout' not in opt:
                    options_clean.append(opt)
            if options_clean:
                query_params['options'] = options_clean
            else:
                query_params.pop('options')
            logger.info("Removed unsupported 'statement_timeout' option for Neon.tech.")
        # Optionally, set a supported option for Neon (usually none)
    
    # TODO: Extend here for further providers...

    # Rebuild DSN
    new_query = urlencode(query_params, doseq=True)
    new_url = parsed._replace(query=new_query)
    return urlunparse(new_url)

def mask_dsn(dsn_url: str) -> str:
    """
    Masks username/password from DSN so they are not exposed in logs.
    """
    parsed = urlparse(dsn_url)
    safe_netloc = f"{parsed.hostname}:{parsed.port}" if parsed.port else parsed.hostname
    return parsed._replace(netloc=safe_netloc).geturl()

async def ssl_runtime_check(conn: asyncpg.Connection):
    """
    Performs a cloud-aware SSL runtime check on an active connection.
    For Neon/Supabase (or unknown cloud) only log a warning if pg_stat_ssl is unavailable.
    """
    dsn = os.getenv("DATABASE_URL", "")
    try:
        ssl_status = await conn.fetchval("""
            SELECT CASE WHEN ssl THEN 'active' ELSE 'INACTIVE' END
            FROM pg_stat_ssl WHERE pid = pg_backend_pid()
        """)
        if ssl_status != 'active':
            logger.critical("CRITICAL ERROR: SSL connection is not active!")
            raise RuntimeError("SSL connection failed")
        logger.info("SSL connection is active.")
    except Exception as e:
        # Cloud: If pg_stat_ssl is not available, don't fail hard.
        if "neon.tech" in dsn or "supabase" in dsn:
            logger.warning("SSL check via pg_stat_ssl not possible (cloud restriction). Assuming SSL is active due to sslmode=require.")
        else:
            logger.critical(f"SSL runtime check failed: {e}")
            raise

async def init_db_pool(dsn_url: Optional[str] = None) -> Optional[asyncpg.Pool]:
    """Initializes the asynchronous database connection pool."""
    global _db_pool
    if _db_pool:
        return _db_pool

    if not dsn_url:
        dsn_url = os.getenv("DATABASE_URL") or os.getenv("PG_DSN")
        if not dsn_url:
            logger.warning("No DATABASE_URL or PG_DSN found. Skipping DB pool initialization.")
            return None

    # Enforce cloud security and remove unsupported options
    secured_dsn = enforce_cloud_security(dsn_url)

    # ⚠ WARNING: This logs full credentials — keep only for secure DEV debugging
    logger.debug(f"[DEV ONLY] Full DSN used for DB connection: {secured_dsn}")

    # Always log a masked DSN for production safety
    logger.info(f"DSN used for DB connection (masked): {mask_dsn(secured_dsn)}")

    ssl_context = None
    if 'sslmode=verify-full' in secured_dsn:
        ssl_context = ssl.create_default_context()

    try:
        logger.info("Initializing secure database pool...")
        _db_pool = await asyncpg.create_pool(
            dsn=secured_dsn,
            min_size=1,
            max_size=10,
            timeout=5,
            command_timeout=30,
            ssl=ssl_context
        )
        # Post-init checks
        async with _db_pool.acquire() as conn:
            await ssl_runtime_check(conn)
        logger.info("Secure database pool initialized.")
        return _db_pool
    except Exception as e:
        logger.critical(f"Pool initialization failed: {str(e)}")
        _db_pool = None
        return None  # Fallback: allow app to run without DB

async def close_db_pool():
    """Gracefully closes the database connection pool."""
    global _db_pool
    if _db_pool:
        await _db_pool.close()
        _db_pool = None
        logger.info("Database pool closed successfully.")

async def execute_secured_query(query: str, *params, fetch_method='fetch'):
    """
    Executes a parameterized query with integrated security checks.
    """
    global _db_pool
    if not _db_pool:
        raise RuntimeError("Database pool not initialized")

    try:
        async with _db_pool.acquire() as conn:
            if fetch_method == 'fetch':
                return await conn.fetch(query, *params)
            elif fetch_method == 'fetchrow':
                return await conn.fetchrow(query, *params)
            elif fetch_method == 'execute':
                return await conn.execute(query, *params)
            else:
                raise ValueError("Invalid fetch_method")
    except asyncpg.PostgresError as e:
        error_type = "Security violation" if getattr(e, 'sqlstate', None) == '42501' else "Database error"
        
        if os.getenv('APP_ENV') == 'production':
            logger.error(f"{error_type} [Code: {getattr(e, 'sqlstate', '?')}]")
        else:
            logger.error(f"{error_type}: {e}")
        
        # Neon: Reconnect if connection terminated (optional)
        if getattr(e, 'sqlstate', None) == '08006' and 'neon.tech' in (os.getenv("DATABASE_URL") or ''):
            logger.warning("Neon.tech connection terminated. Restarting pool...")
            await close_db_pool()
            await init_db_pool(os.getenv("DATABASE_URL"))
        
        raise
