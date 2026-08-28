"""Multi-panel 3x-ui server registry stored in settings.xui_servers."""

from __future__ import annotations

import uuid
from typing import Any, Optional


def _new_id() -> str:
    return str(uuid.uuid4())


def normalize_server(raw: dict | None) -> dict:
    raw = raw or {}
    return {
        'id': str(raw.get('id') or _new_id()),
        'name': (raw.get('name') or '').strip() or '3x-ui',
        'url': (raw.get('url') or '').strip().rstrip('/'),
        'sub_url': (raw.get('sub_url') or '').strip().rstrip('/'),
        'api_token': (raw.get('api_token') or '').strip(),
        'username': (raw.get('username') or '').strip(),
        'password': raw.get('password') or '',
        'default_inbound_id': int(raw.get('default_inbound_id') or 0),
        'enabled': bool(raw.get('enabled', True)),
        'sync_users': bool(raw.get('sync_users', False)),
    }


def legacy_sync_to_server(sync: dict) -> Optional[dict]:
    """Build one xui_servers entry from old settings.sync.xui_* fields."""
    sync = sync or {}
    url = (sync.get('xui_url') or '').strip()
    if not url:
        return None
    return normalize_server({
        'id': 'legacy-default',
        'name': '3x-ui (default)',
        'url': url,
        'sub_url': sync.get('xui_sub_url') or '',
        'api_token': sync.get('xui_api_token') or '',
        'username': sync.get('xui_username') or '',
        'password': sync.get('xui_password') or '',
        'default_inbound_id': int(sync.get('xui_inbound_id') or 0),
        'enabled': True,
        'sync_users': bool(sync.get('xui_sync_users')),
    })


def ensure_xui_servers(settings: dict) -> list:
    """Ensure settings['xui_servers'] exists; migrate legacy sync fields once."""
    settings = settings if isinstance(settings, dict) else {}
    servers = settings.get('xui_servers')
    if not isinstance(servers, list):
        servers = []
    servers = [normalize_server(s) for s in servers if isinstance(s, dict)]

    if not servers:
        migrated = legacy_sync_to_server(settings.get('sync') or {})
        if migrated:
            servers = [migrated]
    settings['xui_servers'] = servers

    # Mirror primary into legacy sync.* for older code paths (no get_xui_server - avoids recursion)
    sync = settings.setdefault('sync', {})
    primary = None
    for s in servers:
        if s.get('enabled'):
            primary = s
            break
    if primary is None and servers:
        primary = servers[0]
    if primary and primary.get('url'):
        sync.setdefault('xui_url', primary.get('url') or '')
        sync.setdefault('xui_sub_url', primary.get('sub_url') or '')
        sync.setdefault('xui_api_token', primary.get('api_token') or '')
        sync.setdefault('xui_username', primary.get('username') or '')
        sync.setdefault('xui_password', primary.get('password') or '')
        sync.setdefault('xui_inbound_id', int(primary.get('default_inbound_id') or 0))
    return servers


def list_xui_servers(settings: dict, *, enabled_only: bool = False) -> list:
    servers = ensure_xui_servers(settings)
    if enabled_only:
        return [s for s in servers if s.get('enabled')]
    return servers


def get_xui_server(settings: dict, panel_id: Optional[str] = None) -> Optional[dict]:
    servers = ensure_xui_servers(settings)
    if not servers:
        return None
    if panel_id:
        for s in servers:
            if str(s.get('id')) == str(panel_id):
                return s
        return None
    for s in servers:
        if s.get('enabled'):
            return s
    return servers[0]


def public_server_view(server: dict) -> dict:
    """Safe view for UI (no password/token secrets in list if desired — we keep them for admin edit)."""
    return {
        'id': server.get('id'),
        'name': server.get('name') or '3x-ui',
        'url': server.get('url') or '',
        'sub_url': server.get('sub_url') or '',
        'api_token': server.get('api_token') or '',
        'username': server.get('username') or '',
        'password': server.get('password') or '',
        'default_inbound_id': int(server.get('default_inbound_id') or 0),
        'enabled': bool(server.get('enabled', True)),
        'sync_users': bool(server.get('sync_users', False)),
        'has_token': bool(server.get('api_token')),
        'has_password': bool(server.get('password')),
    }


def upsert_xui_server(settings: dict, payload: dict, *, panel_id: Optional[str] = None) -> dict:
    servers = ensure_xui_servers(settings)
    panel_id = panel_id or payload.get('id')
    existing = None
    if panel_id:
        for s in servers:
            if str(s.get('id')) == str(panel_id):
                existing = s
                break

    merged = dict(existing or {})
    for key in ('name', 'url', 'sub_url', 'api_token', 'username', 'password'):
        if key in payload and payload[key] is not None:
            # Empty password/token on edit means "keep previous" when editing
            if key in ('password', 'api_token') and existing and payload[key] == '':
                continue
            merged[key] = payload[key]
    if 'default_inbound_id' in payload and payload['default_inbound_id'] is not None:
        merged['default_inbound_id'] = int(payload['default_inbound_id'] or 0)
    if 'enabled' in payload and payload['enabled'] is not None:
        merged['enabled'] = bool(payload['enabled'])
    if 'sync_users' in payload and payload['sync_users'] is not None:
        merged['sync_users'] = bool(payload['sync_users'])
    if not merged.get('id'):
        merged['id'] = _new_id()

    server = normalize_server(merged)
    if not server['url']:
        raise ValueError('3x-ui URL is required')
    if not server['name']:
        server['name'] = server['url']

    if existing:
        for i, s in enumerate(servers):
            if str(s.get('id')) == str(existing.get('id')):
                servers[i] = server
                break
    else:
        servers.append(server)

    settings['xui_servers'] = servers
    _mirror_primary_to_sync(settings)
    return server


def delete_xui_server(settings: dict, panel_id: str) -> bool:
    servers = ensure_xui_servers(settings)
    new_list = [s for s in servers if str(s.get('id')) != str(panel_id)]
    if len(new_list) == len(servers):
        return False
    settings['xui_servers'] = new_list
    _mirror_primary_to_sync(settings)
    return True


def _mirror_primary_to_sync(settings: dict) -> None:
    sync = settings.setdefault('sync', {})
    primary = get_xui_server(settings, None)
    if not primary:
        sync['xui_url'] = ''
        sync['xui_sub_url'] = ''
        return
    sync['xui_url'] = primary.get('url') or ''
    sync['xui_sub_url'] = primary.get('sub_url') or ''
    sync['xui_api_token'] = primary.get('api_token') or ''
    sync['xui_username'] = primary.get('username') or ''
    sync['xui_password'] = primary.get('password') or ''
    sync['xui_inbound_id'] = int(primary.get('default_inbound_id') or 0)
    if any(s.get('sync_users') for s in settings.get('xui_servers') or []):
        sync['xui_sync_users'] = True


def server_to_settings_slice(server: dict) -> dict:
    """Shape expected by xui_api._settings_creds / from_panel_settings."""
    return {
        'sync': {
            'xui_url': server.get('url') or '',
            'xui_sub_url': server.get('sub_url') or '',
            'xui_api_token': server.get('api_token') or '',
            'xui_username': server.get('username') or '',
            'xui_password': server.get('password') or '',
            'xui_inbound_id': int(server.get('default_inbound_id') or 0),
        }
    }


def resolve_panel_settings(full_settings: dict, panel_id: Optional[str] = None) -> dict:
    """Return a settings-like dict scoped to one 3x-ui panel (fallback: primary / legacy)."""
    server = get_xui_server(full_settings, panel_id)
    if server:
        return server_to_settings_slice(server)
    # Fallback to legacy global sync
    return {'sync': (full_settings or {}).get('sync') or {}}
