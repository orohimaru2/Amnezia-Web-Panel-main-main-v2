"""PostgreSQL connection pool for Amnezia Web Panel."""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

DEFAULT_DATABASE_URL = 'postgresql://amnezia:amnezia@localhost:5432/amnezia_panel'

_pool = None
_pool_lock = threading.Lock()
_schema_ready = False


def get_database_url() -> str:
    return os.environ.get('DATABASE_URL', DEFAULT_DATABASE_URL).strip()


def get_pg_connection_params() -> dict[str, str]:
    """Connection parameters for pg_dump/psql (same source as the app pool)."""
    from psycopg.conninfo import conninfo_to_dict

    url = get_database_url()
    scheme, _, rest = url.partition('://')
    if scheme.startswith('postgresql'):
        url = f'postgresql://{rest}'

    info = conninfo_to_dict(url)
    params = {
        'host': str(info.get('host') or 'localhost'),
        'port': str(info.get('port') or '5432'),
        'user': str(info.get('user') or 'amnezia'),
        'password': str(info.get('password') or ''),
        'dbname': str(info.get('dbname') or 'amnezia_panel'),
    }

    # Prefer discrete env vars when set (Dokploy / compose); avoids URL encoding issues.
    if os.environ.get('POSTGRES_USER', '').strip():
        params['user'] = os.environ['POSTGRES_USER'].strip()
    if os.environ.get('POSTGRES_PASSWORD', '').strip():
        params['password'] = os.environ['POSTGRES_PASSWORD'].strip()
    if os.environ.get('POSTGRES_DB', '').strip():
        params['dbname'] = os.environ['POSTGRES_DB'].strip()
    if os.environ.get('POSTGRES_PORT', '').strip():
        params['port'] = os.environ['POSTGRES_PORT'].strip()

    return params


def get_pool():
    global _pool
    if _pool is not None:
        return _pool
    with _pool_lock:
        if _pool is not None:
            return _pool
        from psycopg.rows import dict_row
        from psycopg_pool import ConnectionPool

        url = get_database_url()
        logger.info('Connecting to PostgreSQL…')
        _pool = ConnectionPool(
            conninfo=url,
            min_size=1,
            max_size=10,
            kwargs={
                'autocommit': False,
                'row_factory': dict_row,
            },
            open=True,
        )
        return _pool


def close_pool():
    global _pool, _schema_ready
    with _pool_lock:
        if _pool is not None:
            _pool.close()
            _pool = None
        _schema_ready = False


def init_schema():
    """Create tables if they do not exist."""
    global _schema_ready
    if _schema_ready:
        return
    schema_path = Path(__file__).with_name('schema.sql')
    sql = schema_path.read_text(encoding='utf-8')
    pool = get_pool()
    with pool.connection() as conn:
        with conn.cursor() as cur:
            # psycopg3 executes one statement per execute()
            for raw in sql.split(';'):
                lines = [
                    ln for ln in raw.splitlines()
                    if ln.strip() and not ln.strip().startswith('--')
                ]
                stmt = '\n'.join(lines).strip()
                if stmt:
                    cur.execute(stmt)

            # Soft migrations: CREATE TABLE IF NOT EXISTS does not add new columns
            # to existing tables, so alter after base schema is applied.
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS xui_email TEXT")
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_users_xui_email ON users(xui_email)"
            )
            cur.execute(
                "ALTER TABLE invite_links ADD COLUMN IF NOT EXISTS duration_days INTEGER NOT NULL DEFAULT 0"
            )
            cur.execute(
                "ALTER TABLE invite_links ADD COLUMN IF NOT EXISTS xui_panel_id TEXT NOT NULL DEFAULT ''"
            )
            cur.execute(
                "ALTER TABLE user_connections ADD COLUMN IF NOT EXISTS xui_panel_id TEXT NOT NULL DEFAULT ''"
            )
            cur.execute(
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS expire_after_first_use BOOLEAN NOT NULL DEFAULT FALSE"
            )
            cur.execute(
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS expiration_days INTEGER NOT NULL DEFAULT 0"
            )
        conn.commit()
    _schema_ready = True
    logger.info('PostgreSQL schema ready')
