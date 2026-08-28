"""PostgreSQL backup/restore for the panel database."""

from __future__ import annotations

import gzip
import logging
import os
import subprocess
from datetime import datetime, timezone

from .connection import close_pool, get_pg_connection_params
from .store import invalidate_data_cache

logger = logging.getLogger(__name__)


def _pg_cli_env(password: str) -> dict[str, str]:
    env = os.environ.copy()
    if password:
        env['PGPASSWORD'] = password
    return env


def backup_filename() -> str:
    stamp = datetime.now(timezone.utc).strftime('%Y-%m-%d_%H%M%S')
    return f'amnezia_panel_backup_{stamp}.sql'


def _decode_backup_bytes(data: bytes) -> bytes:
    """Accept plain .sql or gzip-compressed dumps (.sql.gz / gzip magic)."""
    if not data:
        return data
    if data[:2] == b'\x1f\x8b':
        try:
            return gzip.decompress(data)
        except OSError as e:
            raise ValueError(f'Invalid gzip backup: {e}') from e
    return data


def export_database_sql() -> bytes:
    """Create a plain SQL dump of the panel PostgreSQL database."""
    params = get_pg_connection_params()
    proc = subprocess.run(
        [
            'pg_dump',
            '-h', params['host'],
            '-p', params['port'],
            '-U', params['user'],
            '-d', params['dbname'],
            '--no-owner',
            '--no-acl',
            '--clean',
            '--if-exists',
        ],
        capture_output=True,
        check=False,
        env=_pg_cli_env(params['password']),
    )
    if proc.returncode != 0:
        err = proc.stderr.decode('utf-8', errors='replace').strip()
        raise RuntimeError(err or 'pg_dump failed')
    if not proc.stdout:
        raise RuntimeError('pg_dump returned empty dump')
    return proc.stdout


def restore_database_sql(data: bytes) -> None:
    """Restore panel data from a plain SQL dump produced by pg_dump."""
    data = _decode_backup_bytes(data)
    if not data or not data.strip():
        raise ValueError('Empty backup file')

    # Drop live pool connections so --clean DROP TABLE is not blocked.
    try:
        close_pool()
    except Exception as e:
        logger.warning('close_pool before restore failed: %s', e)

    params = get_pg_connection_params()
    proc = subprocess.run(
        [
            'psql',
            '-h', params['host'],
            '-p', params['port'],
            '-U', params['user'],
            '-d', params['dbname'],
            '-v', 'ON_ERROR_STOP=1',
            '-q',
        ],
        input=data,
        capture_output=True,
        check=False,
        env=_pg_cli_env(params['password']),
    )
    invalidate_data_cache()
    if proc.returncode != 0:
        err = proc.stderr.decode('utf-8', errors='replace').strip()
        out = proc.stdout.decode('utf-8', errors='replace').strip()
        raise RuntimeError(err or out or 'psql restore failed')
    logger.info('PostgreSQL backup restored successfully')
