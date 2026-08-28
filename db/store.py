"""Panel data store backed by PostgreSQL 17.

Preserves the same dict shape that used to live in data.json so existing
FastAPI handlers keep working without a full rewrite.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import secrets
import shutil
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from uuid import UUID

from psycopg.types.json import Jsonb

from .connection import get_pool, init_schema

logger = logging.getLogger(__name__)

# Process-wide snapshot cache. load_data() returns a deep copy so callers can
# mutate safely; save_data() refreshes the cache after a successful write.
_DATA_CACHE: Optional[dict] = None
_DATA_CACHE_LOCK = threading.RLock()
# Serializes full-document rewrites with token insert/delete so a stale
# snapshot cannot drop a token created during the same window.
_WRITE_LOCK = threading.RLock()

DEFAULT_SETTINGS = {
    'appearance': {
        'title': 'Amnezia',
        'logo': '❤️',
        'subtitle': 'Web Panel',
    },
    'sync': {
        'remnawave_url': '',
        'remnawave_api_key': '',
        'remnawave_sync': False,
        'remnawave_sync_users': False,
        'remnawave_create_conns': False,
        'remnawave_server_id': 0,
        'remnawave_protocol': 'awg',
    },
    'guest': {
        'enabled': False,
        'token': '',
        'password_hash': None,
        'user_id': '',
        'allow_create': False,
        'create_protocol': 'awg',
        'create_server_id': 0,
    },
    'donate': {
        'enabled': True,
        'intro': '',
        'sbp': {'enabled': True, 'title': '', 'details': ''},
        'card': {'enabled': True, 'title': '', 'details': ''},
        'crypto': {'enabled': True, 'title': '', 'details': ''},
    },
}


def _parse_ts(value: Any) -> Optional[datetime]:
    if value is None or value == '':
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).strip()
    if not text:
        return None
    if text.endswith('Z'):
        text = text[:-1] + '+00:00'
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _ts_iso(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _as_uuid(value: Any) -> UUID:
    return UUID(str(value))


def _is_valid_uuid(value: Any) -> bool:
    if value is None:
        return False
    try:
        UUID(str(value))
        return True
    except (ValueError, AttributeError, TypeError):
        return False


def _coerce_uuid(value: Any, *, default: Optional[str] = None) -> str:
    if _is_valid_uuid(value):
        return str(UUID(str(value)))
    if default is not None:
        return default
    return str(uuid.uuid4())


def _as_list(value: Any) -> list:
    return list(value) if isinstance(value, list) else []


def normalize_import_data(data: dict) -> dict:
    """Prepare legacy data.json (or partial exports) for PostgreSQL constraints."""
    data = copy.deepcopy(data or {})
    data['servers'] = [s for s in _as_list(data.get('servers')) if isinstance(s, dict)]
    data['users'] = [u for u in _as_list(data.get('users')) if isinstance(u, dict)]
    data['user_connections'] = [c for c in _as_list(data.get('user_connections')) if isinstance(c, dict)]
    data['api_tokens'] = [t for t in _as_list(data.get('api_tokens')) if isinstance(t, dict)]
    data['invite_links'] = [l for l in _as_list(data.get('invite_links')) if isinstance(l, dict)]
    if not isinstance(data.get('settings'), dict):
        data['settings'] = {}

    id_map: dict[str, str] = {}

    def map_user_id(value: Any) -> Optional[str]:
        if value is None or value == '':
            return None
        key = str(value)
        if _is_valid_uuid(key):
            resolved = str(UUID(key))
            id_map.setdefault(key, resolved)
            return resolved
        if key not in id_map:
            id_map[key] = str(uuid.uuid4())
        return id_map[key]

    used_usernames: set[str] = set()
    for index, user in enumerate(data['users']):
        if not isinstance(user, dict):
            continue
        old_id = user.get('id')
        if old_id is None or old_id == '':
            user['id'] = str(uuid.uuid4())
        else:
            key = str(old_id)
            if _is_valid_uuid(key):
                user['id'] = str(UUID(key))
                id_map.setdefault(key, user['id'])
            else:
                user['id'] = map_user_id(key) or str(uuid.uuid4())

        username = (user.get('username') or '').strip() or f'user{index + 1}'
        base = username
        suffix = 2
        while username.lower() in used_usernames:
            username = f'{base}_{suffix}'
            suffix += 1
        user['username'] = username
        used_usernames.add(username.lower())

        user.setdefault('password_hash', '')
        user.setdefault('role', 'user')
        user.setdefault('enabled', True)

    valid_user_ids = {str(u['id']) for u in data['users'] if isinstance(u, dict) and u.get('id')}

    for server in data['servers']:
        if not isinstance(server, dict):
            continue
        server['server_info'] = _as_dict(server.get('server_info'))
        server['protocols'] = _as_dict(server.get('protocols'))

    for conn in data['user_connections']:
        if not isinstance(conn, dict):
            continue
        conn['id'] = _coerce_uuid(conn.get('id'))
        mapped_uid = map_user_id(conn.get('user_id'))
        if mapped_uid:
            conn['user_id'] = mapped_uid

    data['user_connections'] = [
        c for c in data['user_connections']
        if isinstance(c, dict) and str(c.get('user_id')) in valid_user_ids
    ]

    seen_hashes: set[str] = set()
    normalized_tokens = []
    for token in data['api_tokens']:
        if not isinstance(token, dict):
            continue
        mapped_uid = map_user_id(token.get('user_id'))
        if not mapped_uid or mapped_uid not in valid_user_ids:
            continue
        token['id'] = _coerce_uuid(token.get('id'))
        token['user_id'] = mapped_uid
        token_hash = (token.get('token_hash') or '').strip()
        # Never invent a new hash: the bearer secret is shown once at create
        # time. A random hash here would leave the token listed but unusable.
        if not token_hash or token_hash in seen_hashes:
            continue
        token['token_hash'] = token_hash
        seen_hashes.add(token_hash)
        token.setdefault('token_prefix', token.get('token_prefix') or '')
        normalized_tokens.append(token)
    data['api_tokens'] = normalized_tokens

    seen_invite_tokens: set[str] = set()
    for link in data['invite_links']:
        if not isinstance(link, dict):
            continue
        link['id'] = _coerce_uuid(link.get('id'))
        mapped_uid = map_user_id(link.get('user_id'))
        link['user_id'] = mapped_uid if mapped_uid in valid_user_ids else ''
        token = (link.get('token') or '').strip()
        if not token or token in seen_invite_tokens:
            token = secrets.token_urlsafe(16)
        while token in seen_invite_tokens:
            token = secrets.token_urlsafe(16)
        link['token'] = token
        seen_invite_tokens.add(token)

    guest = data['settings'].get('guest')
    if isinstance(guest, dict):
        mapped_guest = map_user_id(guest.get('user_id'))
        if mapped_guest in valid_user_ids:
            guest['user_id'] = mapped_guest
        elif guest.get('user_id'):
            guest['user_id'] = ''

    return data


def _merge_settings(raw: Optional[dict]) -> dict:
    settings = json.loads(json.dumps(DEFAULT_SETTINGS))
    if not isinstance(raw, dict):
        return settings
    for section, defaults in DEFAULT_SETTINGS.items():
        incoming = raw.get(section)
        if isinstance(incoming, dict) and isinstance(defaults, dict):
            merged = dict(defaults)
            merged.update(incoming)
            settings[section] = merged
        elif section in raw:
            settings[section] = raw[section]
    for key, value in raw.items():
        if key not in settings:
            settings[key] = value
    return settings


def _as_dict(value, default=None):
    """Coerce JSONB / legacy values to a plain dict."""
    if default is None:
        default = {}
    if value is None:
        return dict(default)
    if isinstance(value, dict):
        return dict(value)
    # Legacy: ssh.test_connection() used to return a plain string
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return dict(default)
        if text.startswith('{') or text.startswith('['):
            try:
                parsed = json.loads(text)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                pass
        return {'raw': text}
    try:
        return dict(value)
    except Exception:
        return {'raw': str(value)}


def _row_to_server(row) -> dict:
    return {
        'name': row['name'] or '',
        'host': row['host'] or '',
        'ssh_port': int(row['ssh_port'] or 22),
        'username': row['username'] or '',
        'password': row['password'],
        'private_key': row['private_key'],
        'server_info': _as_dict(row['server_info']),
        'protocols': _as_dict(row['protocols']),
    }


def _row_to_user(row) -> dict:
    return {
        'id': str(row['id']),
        'username': row['username'],
        'password_hash': row['password_hash'] or '',
        'role': row['role'] or 'user',
        'enabled': bool(row['enabled']),
        'created_at': _ts_iso(row['created_at']),
        'telegramId': row['telegram_id'],
        'email': row['email'],
        'description': row['description'],
        'traffic_limit': int(row['traffic_limit'] or 0),
        'traffic_used': int(row['traffic_used'] or 0),
        'traffic_total': int(row['traffic_total'] or 0),
        'traffic_reset_strategy': row['traffic_reset_strategy'] or 'never',
        'last_reset_at': _ts_iso(row['last_reset_at']),
        'expiration_date': _ts_iso(row['expiration_date']),
        'expire_after_first_use': bool(row.get('expire_after_first_use') if hasattr(row, 'get') else row['expire_after_first_use']),
        'expiration_days': int((row.get('expiration_days') if hasattr(row, 'get') else row['expiration_days']) or 0),
        'remnawave_uuid': row['remnawave_uuid'],
        'xui_email': row.get('xui_email'),
        'share_enabled': bool(row['share_enabled']),
        'share_token': row['share_token'],
        'share_password_hash': row['share_password_hash'],
    }


def _row_to_connection(row) -> dict:
    return {
        'id': str(row['id']),
        'user_id': str(row['user_id']),
        'server_id': int(row['server_id'] or 0),
        'protocol': row['protocol'] or '',
        'client_id': row['client_id'] or '',
        'name': row['name'] or '',
        'xui_panel_id': (row.get('xui_panel_id') or '') if hasattr(row, 'get') else (row['xui_panel_id'] if 'xui_panel_id' in row else ''),
        'created_at': _ts_iso(row['created_at']),
        'last_bytes': int(row['last_bytes'] or 0),
    }


def _row_to_token(row) -> dict:
    return {
        'id': str(row['id']),
        'name': row['name'] or '',
        'token_hash': row['token_hash'] or '',
        'token_prefix': row['token_prefix'] or '',
        'user_id': str(row['user_id']),
        'created_at': _ts_iso(row['created_at']),
        'last_used_at': _ts_iso(row['last_used_at']),
    }


def _row_to_invite(row) -> dict:
    return {
        'id': str(row['id']),
        'name': row['name'] or '',
        'token': row['token'] or '',
        'enabled': bool(row['enabled']),
        'max_uses': int(row['max_uses'] or 0),
        'used_count': int(row['used_count'] or 0),
        'user_id': str(row['user_id']) if row['user_id'] else '',
        'protocol': row['protocol'] or 'awg',
        'server_id': int(row['server_id'] or 0),
        'xui_inbound_id': int(row['xui_inbound_id'] or 0),
        'xui_panel_id': (row.get('xui_panel_id') or '') if hasattr(row, 'get') else '',
        'password_hash': row['password_hash'],
        'expires_at': _ts_iso(row['expires_at']),
        'duration_days': int(row.get('duration_days') or 0),
        'note': row['note'] or '',
        'created_at': _ts_iso(row['created_at']),
    }


def invalidate_data_cache() -> None:
    global _DATA_CACHE
    with _DATA_CACHE_LOCK:
        _DATA_CACHE = None


def _fetch_data_from_db() -> dict:
    init_schema()
    pool = get_pool()
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                'SELECT position, name, host, ssh_port, username, password, '
                'private_key, server_info, protocols '
                'FROM servers ORDER BY position ASC'
            )
            servers = [_row_to_server(r) for r in cur.fetchall()]

            cur.execute(
                'SELECT id, username, password_hash, role, enabled, created_at, '
                'telegram_id, email, description, traffic_limit, traffic_used, '
                'traffic_total, traffic_reset_strategy, last_reset_at, '
                'expiration_date, expire_after_first_use, expiration_days, '
                'remnawave_uuid, xui_email, share_enabled, share_token, '
                'share_password_hash FROM users ORDER BY created_at NULLS LAST, username'
            )
            users = [_row_to_user(r) for r in cur.fetchall()]

            cur.execute(
                'SELECT id, user_id, server_id, protocol, client_id, name, '
                'xui_panel_id, created_at, last_bytes FROM user_connections '
                'ORDER BY created_at NULLS LAST, id'
            )
            user_connections = [_row_to_connection(r) for r in cur.fetchall()]

            cur.execute(
                'SELECT id, name, token_hash, token_prefix, user_id, '
                'created_at, last_used_at FROM api_tokens '
                'ORDER BY created_at NULLS LAST, id'
            )
            api_tokens = [_row_to_token(r) for r in cur.fetchall()]

            cur.execute(
                'SELECT id, name, token, enabled, max_uses, used_count, user_id, '
                'protocol, server_id, xui_inbound_id, xui_panel_id, password_hash, expires_at, '
                'duration_days, note, created_at FROM invite_links '
                'ORDER BY created_at DESC NULLS LAST, name'
            )
            invite_links = [_row_to_invite(r) for r in cur.fetchall()]

            cur.execute('SELECT data FROM settings WHERE id = 1')
            settings_row = cur.fetchone()
            settings = _merge_settings(settings_row['data'] if settings_row else None)

    return {
        'servers': servers,
        'users': users,
        'user_connections': user_connections,
        'api_tokens': api_tokens,
        'invite_links': invite_links,
        'settings': settings,
    }


def load_data() -> dict:
    """Return panel state. Uses an in-process cache; always returns a deep copy."""
    global _DATA_CACHE
    with _DATA_CACHE_LOCK:
        if _DATA_CACHE is not None:
            return copy.deepcopy(_DATA_CACHE)
        data = _fetch_data_from_db()
        _DATA_CACHE = data
        return copy.deepcopy(data)


def _restore_token_hashes(incoming: list, live: list) -> list:
    """Keep existing hashes when an import/replace row is missing one."""
    live_by_id = {str(t.get('id')): t for t in live}
    result = []
    seen: set[str] = set()
    for token in incoming:
        if not isinstance(token, dict):
            continue
        tid = str(token.get('id') or '')
        token_hash = (token.get('token_hash') or '').strip()
        if not token_hash and tid in live_by_id:
            token['token_hash'] = live_by_id[tid].get('token_hash') or ''
            if not token.get('token_prefix'):
                token['token_prefix'] = live_by_id[tid].get('token_prefix') or ''
            token_hash = token['token_hash']
        if not token_hash or token_hash in seen:
            continue
        token['token_hash'] = token_hash
        seen.add(token_hash)
        result.append(token)
    return result


def _insert_token_row(cur, token: dict) -> None:
    cur.execute(
        'INSERT INTO api_tokens ('
        'id, name, token_hash, token_prefix, user_id, created_at, last_used_at'
        ') VALUES (%s, %s, %s, %s, %s, %s, %s)',
        (
            _as_uuid(token['id']),
            token.get('name') or '',
            token.get('token_hash') or '',
            token.get('token_prefix') or '',
            _as_uuid(token['user_id']),
            _parse_ts(token.get('created_at')),
            _parse_ts(token.get('last_used_at')),
        ),
    )


def _cache_upsert_token(entry: dict) -> None:
    with _DATA_CACHE_LOCK:
        if _DATA_CACHE is None:
            return
        tokens = _DATA_CACHE.setdefault('api_tokens', [])
        for index, token in enumerate(tokens):
            if str(token.get('id')) == str(entry.get('id')):
                tokens[index] = copy.deepcopy(entry)
                return
        tokens.append(copy.deepcopy(entry))


def _cache_remove_token(token_id: str) -> None:
    with _DATA_CACHE_LOCK:
        if _DATA_CACHE is None:
            return
        _DATA_CACHE['api_tokens'] = [
            token for token in _DATA_CACHE.get('api_tokens', [])
            if str(token.get('id')) != str(token_id)
        ]


def _cache_touch_token(token_id: str, last_used_at: Optional[str]) -> None:
    with _DATA_CACHE_LOCK:
        if _DATA_CACHE is None:
            return
        for token in _DATA_CACHE.get('api_tokens', []):
            if str(token.get('id')) == str(token_id):
                token['last_used_at'] = last_used_at
                return


def insert_api_token(entry: dict) -> None:
    """Persist a newly issued token without rewriting the rest of panel state."""
    token_hash = (entry.get('token_hash') or '').strip()
    if not token_hash:
        raise ValueError('token_hash is required')
    token = {
        'id': str(entry['id']),
        'name': entry.get('name') or '',
        'token_hash': token_hash,
        'token_prefix': entry.get('token_prefix') or '',
        'user_id': str(entry['user_id']),
        'created_at': entry.get('created_at'),
        'last_used_at': entry.get('last_used_at'),
    }
    init_schema()
    with _WRITE_LOCK:
        pool = get_pool()
        with pool.connection() as conn:
            with conn.cursor() as cur:
                _insert_token_row(cur, token)
            conn.commit()
        _cache_upsert_token(token)


def delete_api_token(token_id: str) -> bool:
    """Revoke one token. Returns False if the id was not found."""
    init_schema()
    with _WRITE_LOCK:
        pool = get_pool()
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute('DELETE FROM api_tokens WHERE id = %s', (_as_uuid(token_id),))
                deleted = cur.rowcount > 0
            conn.commit()
        _cache_remove_token(token_id)
        return deleted


def update_api_token_last_used(token_id: str, last_used_at: str) -> None:
    """Touch last_used_at without a full document rewrite."""
    init_schema()
    with _WRITE_LOCK:
        pool = get_pool()
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    'UPDATE api_tokens SET last_used_at = %s WHERE id = %s',
                    (_parse_ts(last_used_at), _as_uuid(token_id)),
                )
            conn.commit()
        _cache_touch_token(token_id, last_used_at)


def save_data(data: dict, *, replace_tokens: bool = False) -> None:
    """Replace panel state in a single transaction (same semantics as rewriting data.json).

    API tokens are read from the live table and written back unless
    replace_tokens=True (JSON import / explicit token replace). A stale
    load_data() snapshot must not wipe tokens created after that load.
    """
    global _DATA_CACHE
    data = normalize_import_data(data)
    init_schema()
    servers = data.get('servers') or []
    users = data.get('users') or []
    connections = data.get('user_connections') or []
    incoming_tokens = data.get('api_tokens') or []
    invite_links = data.get('invite_links') or []
    settings = _merge_settings(data.get('settings'))

    # Keep only connections whose user still exists
    user_ids = {str(u.get('id')) for u in users if u.get('id')}
    connections = [c for c in connections if str(c.get('user_id')) in user_ids]
    # Clear holder if user was deleted
    for link in invite_links:
        if link.get('user_id') and str(link['user_id']) not in user_ids:
            link['user_id'] = ''

    with _WRITE_LOCK:
        pool = get_pool()
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    'SELECT id, name, token_hash, token_prefix, user_id, '
                    'created_at, last_used_at FROM api_tokens'
                )
                live_tokens = [_row_to_token(r) for r in cur.fetchall()]
                if replace_tokens:
                    tokens = _restore_token_hashes(incoming_tokens, live_tokens)
                else:
                    tokens = live_tokens
                tokens = [t for t in tokens if str(t.get('user_id')) in user_ids]

                # Order matters for FKs: children first on delete, parents first on insert
                cur.execute('DELETE FROM invite_links')
                cur.execute('DELETE FROM api_tokens')
                cur.execute('DELETE FROM user_connections')
                cur.execute('DELETE FROM users')
                cur.execute('DELETE FROM servers')

                for pos, server in enumerate(servers):
                    cur.execute(
                        'INSERT INTO servers (position, name, host, ssh_port, username, '
                        'password, private_key, server_info, protocols) '
                        'VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)',
                        (
                            pos,
                            server.get('name') or '',
                            server.get('host') or '',
                            int(server.get('ssh_port') or 22),
                            server.get('username') or '',
                            server.get('password'),
                            server.get('private_key'),
                            Jsonb(_as_dict(server.get('server_info'))),
                            Jsonb(_as_dict(server.get('protocols'))),
                        ),
                    )

                for user in users:
                    cur.execute(
                        'INSERT INTO users ('
                        'id, username, password_hash, role, enabled, created_at, '
                        'telegram_id, email, description, traffic_limit, traffic_used, '
                        'traffic_total, traffic_reset_strategy, last_reset_at, '
                        'expiration_date, expire_after_first_use, expiration_days, remnawave_uuid, xui_email, share_enabled, share_token, '
                        'share_password_hash'
                        ') VALUES ('
                        '%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s'
                        ')',
                        (
                            _as_uuid(user['id']),
                            user.get('username') or '',
                            user.get('password_hash') or '',
                            user.get('role') or 'user',
                            bool(user.get('enabled', True)),
                            _parse_ts(user.get('created_at')),
                            str(user['telegramId']) if user.get('telegramId') is not None else None,
                            user.get('email'),
                            user.get('description'),
                            int(user.get('traffic_limit') or 0),
                            int(user.get('traffic_used') or 0),
                            int(user.get('traffic_total') or 0),
                            user.get('traffic_reset_strategy') or 'never',
                            _parse_ts(user.get('last_reset_at')),
                            _parse_ts(user.get('expiration_date')),
                            bool(user.get('expire_after_first_use', False)),
                            int(user.get('expiration_days') or 0),
                            user.get('remnawave_uuid'),
                            user.get('xui_email'),
                            bool(user.get('share_enabled', False)),
                            user.get('share_token'),
                            user.get('share_password_hash'),
                        ),
                    )

                for conn_row in connections:
                    cur.execute(
                        'INSERT INTO user_connections ('
                        'id, user_id, server_id, protocol, client_id, name, xui_panel_id, created_at, last_bytes'
                        ') VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)',
                        (
                            _as_uuid(conn_row['id']),
                            _as_uuid(conn_row['user_id']),
                            int(conn_row.get('server_id') or 0),
                            conn_row.get('protocol') or '',
                            conn_row.get('client_id') or '',
                            conn_row.get('name') or '',
                            conn_row.get('xui_panel_id') or '',
                            _parse_ts(conn_row.get('created_at')),
                            int(conn_row.get('last_bytes') or 0),
                        ),
                    )

                for token in tokens:
                    _insert_token_row(cur, token)

                for link in invite_links:
                    uid = link.get('user_id') or None
                    cur.execute(
                        'INSERT INTO invite_links ('
                        'id, name, token, enabled, max_uses, used_count, user_id, '
                        'protocol, server_id, xui_inbound_id, xui_panel_id, password_hash, expires_at, '
                        'duration_days, note, created_at'
                        ') VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)',
                        (
                            _as_uuid(link['id']),
                            link.get('name') or '',
                            link.get('token') or '',
                            bool(link.get('enabled', True)),
                            int(link.get('max_uses') or 0),
                            int(link.get('used_count') or 0),
                            _as_uuid(uid) if uid else None,
                            link.get('protocol') or 'awg',
                            int(link.get('server_id') or 0),
                            int(link.get('xui_inbound_id') or 0),
                            link.get('xui_panel_id') or '',
                            link.get('password_hash'),
                            _parse_ts(link.get('expires_at')),
                            int(link.get('duration_days') or 0),
                            link.get('note') or '',
                            _parse_ts(link.get('created_at')),
                        ),
                    )

                cur.execute(
                    'INSERT INTO settings (id, data) VALUES (1, %s) '
                    'ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data',
                    (Jsonb(settings),),
                )
            conn.commit()

        # Keep caller dict and cache aligned with what was actually persisted
        data['servers'] = servers
        data['users'] = users
        data['user_connections'] = connections
        data['api_tokens'] = tokens
        data['invite_links'] = invite_links
        data['settings'] = settings
        with _DATA_CACHE_LOCK:
            _DATA_CACHE = copy.deepcopy(data)


def export_data_dict() -> dict:
    """Export current DB state as the legacy data.json document."""
    return load_data()


def is_database_empty() -> bool:
    init_schema()
    pool = get_pool()
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT COUNT(*) AS n FROM users')
            users = cur.fetchone()['n']
            cur.execute('SELECT COUNT(*) AS n FROM servers')
            servers = cur.fetchone()['n']
            return users == 0 and servers == 0


def import_from_json_file(path: str | os.PathLike, *, backup: bool = True) -> bool:
    """Import legacy data.json into Postgres. Returns True if import ran."""
    path = Path(path)
    if not path.exists():
        return False

    with path.open('r', encoding='utf-8') as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError(f'Invalid data.json: expected object, got {type(data).__name__}')

    data = normalize_import_data(data)

    save_data(data, replace_tokens=True)

    if backup:
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        backup_path = path.with_name(f'data.json.migrated.{stamp}.bak')
        try:
            shutil.copy2(path, backup_path)
            logger.info('Backed up legacy data.json to %s', backup_path)
        except OSError as e:
            logger.warning('Could not backup data.json: %s', e)

    logger.info(
        'Imported data.json → PostgreSQL (%s servers, %s users, %s connections)',
        len(data.get('servers', [])),
        len(data.get('users', [])),
        len(data.get('user_connections', [])),
    )
    return True


def load_tunnel_state() -> dict:
    init_schema()
    pool = get_pool()
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT provider, data FROM tunnel_state')
            rows = cur.fetchall()
    return {row['provider']: dict(row['data'] or {}) for row in rows}


def save_tunnel_state(state: dict) -> None:
    init_schema()
    pool = get_pool()
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute('DELETE FROM tunnel_state')
            for provider, payload in (state or {}).items():
                cur.execute(
                    'INSERT INTO tunnel_state (provider, data) VALUES (%s, %s)',
                    (str(provider), Jsonb(payload or {})),
                )
        conn.commit()


def update_tunnel_state(provider: str, **updates) -> None:
    state = load_tunnel_state()
    provider_state = state.get(provider, {})
    provider_state.update(updates)
    state[provider] = provider_state
    save_tunnel_state(state)


def clear_tunnel_state(provider: str) -> None:
    state = load_tunnel_state()
    if provider in state:
        state.pop(provider)
        save_tunnel_state(state)


def ensure_db_ready(legacy_data_file: Optional[str] = None) -> None:
    """Init schema and one-shot import from data.json when DB is empty."""
    init_schema()
    if legacy_data_file and is_database_empty() and os.path.exists(legacy_data_file):
        logger.info('Empty database — importing legacy %s', legacy_data_file)
        try:
            import_from_json_file(legacy_data_file)
        except Exception:
            logger.exception('Legacy data.json import failed — panel will start with empty DB')
            invalidate_data_cache()
