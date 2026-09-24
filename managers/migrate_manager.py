"""Export/import server user data + protocol state for domain-preserving migration.

Use case: new VPS IP, same connect_domain. Users keep existing VPN configs if:
1. Protocol crypto state is restored on the new host
2. Panel user_connections keep the same client_id values
3. DNS A-record for connect_domain points to the new IP
"""

from __future__ import annotations

import io
import json
import logging
import secrets
import shlex
import uuid
import zipfile
from datetime import datetime, timezone
from typing import Any, Optional

from managers.backup_manager import BackupManager

logger = logging.getLogger(__name__)

MIGRATE_FORMAT = 'amnezia-web-panel-migrate-v1'


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_user_public(user: dict) -> dict:
    """User row suitable for re-import (keeps password_hash / share tokens)."""
    return {
        'id': user.get('id'),
        'username': user.get('username'),
        'password_hash': user.get('password_hash') or '',
        'role': user.get('role') or 'user',
        'enabled': bool(user.get('enabled', True)),
        'created_at': user.get('created_at'),
        'telegramId': user.get('telegramId'),
        'email': user.get('email'),
        'description': user.get('description'),
        'traffic_limit': user.get('traffic_limit', 0),
        'traffic_used': user.get('traffic_used', 0),
        'traffic_total': user.get('traffic_total', 0),
        'traffic_reset_strategy': user.get('traffic_reset_strategy', 'never'),
        'last_reset_at': user.get('last_reset_at'),
        'expiration_date': user.get('expiration_date'),
        'expire_after_first_use': bool(user.get('expire_after_first_use')),
        'expiration_days': int(user.get('expiration_days') or 0),
        'remnawave_uuid': user.get('remnawave_uuid'),
        'xui_email': user.get('xui_email'),
        'share_enabled': bool(user.get('share_enabled')),
        'share_token': user.get('share_token'),
        'share_password_hash': user.get('share_password_hash'),
    }


def _server_public_slice(server: dict, server_id: int) -> dict:
    info = dict(server.get('server_info') or {})
    protocols = {}
    for key, val in (server.get('protocols') or {}).items():
        if not isinstance(val, dict):
            continue
        protocols[key] = {
            'installed': bool(val.get('installed')),
            'port': val.get('port'),
            'connect_domain': val.get('connect_domain') or '',
            'container_name': val.get('container_name') or '',
        }
    return {
        'old_server_id': server_id,
        'name': server.get('name') or '',
        'host': server.get('host') or '',
        'ssh_port': int(server.get('ssh_port') or 22),
        'connect_domain': (info.get('connect_domain') or '').strip(),
        'ssl_domain': (info.get('ssl_domain') or '').strip(),
        'ssl_email': (info.get('ssl_email') or '').strip(),
        'protocols': protocols,
    }


def build_panel_payload(data: dict, server_id: int) -> dict:
    servers = data.get('servers') or []
    if server_id < 0 or server_id >= len(servers):
        raise ValueError('Server not found')
    server = servers[server_id]
    conns = [
        dict(c) for c in (data.get('user_connections') or [])
        if isinstance(c, dict) and int(c.get('server_id', -1)) == server_id
    ]
    user_ids = {c.get('user_id') for c in conns if c.get('user_id')}
    users = [
        _safe_user_public(u) for u in (data.get('users') or [])
        if isinstance(u, dict) and u.get('id') in user_ids
    ]
    invites = [
        dict(inv) for inv in (data.get('invite_links') or [])
        if isinstance(inv, dict) and int(inv.get('server_id', -1)) == server_id
    ]
    return {
        'format': MIGRATE_FORMAT,
        'exported_at': _now_iso(),
        'server': _server_public_slice(server, server_id),
        'users': users,
        'user_connections': conns,
        'invite_links': invites,
    }


def _upload_bytes_sudo(ssh, content: bytes, remote_path: str) -> None:
    tmp = f'/tmp/_amnz_mig_{secrets.token_hex(6)}'
    sftp = ssh.client.open_sftp()
    try:
        with sftp.file(tmp, 'wb') as f:
            f.write(content)
    finally:
        sftp.close()
    parent = remote_path.rsplit('/', 1)[0]
    ssh.run_sudo_command(
        f"mkdir -p {shlex.quote(parent)} && "
        f"mv {shlex.quote(tmp)} {shlex.quote(remote_path)} && "
        f"chmod 0644 {shlex.quote(remote_path)}"
    )


def _download_bytes(ssh, remote_path: str) -> bytes:
    tmp = f'/tmp/_amnz_dl_{secrets.token_hex(6)}'
    quoted_remote = shlex.quote(remote_path)
    quoted_tmp = shlex.quote(tmp)
    _, err, code = ssh.run_sudo_command(
        f"test -f {quoted_remote} && cp {quoted_remote} {quoted_tmp} && chmod 0644 {quoted_tmp}"
    )
    if code != 0:
        raise RuntimeError(err or f'Failed to stage {remote_path}')
    sftp = ssh.client.open_sftp()
    try:
        buf = io.BytesIO()
        with sftp.file(tmp, 'rb') as f:
            buf.write(f.read())
        return buf.getvalue()
    finally:
        sftp.close()
        ssh.run_sudo_command(f'rm -f {quoted_tmp}')


def export_migrate_zip(
    ssh,
    data: dict,
    server_id: int,
    *,
    include_protocol_backups: bool = True,
    protocol_container_name_fn=None,
) -> tuple[bytes, dict]:
    """Build a migrate ZIP. Returns (zip_bytes, summary)."""
    payload = build_panel_payload(data, server_id)
    server = data['servers'][server_id]
    protocols = server.get('protocols') or {}
    installed = [
        p for p, info in protocols.items()
        if isinstance(info, dict) and info.get('installed')
    ]

    buf = io.BytesIO()
    summary = {
        'users': len(payload['users']),
        'connections': len(payload['user_connections']),
        'invites': len(payload['invite_links']),
        'protocols': [],
        'protocol_errors': [],
        'connect_domain': payload['server'].get('connect_domain') or '',
    }

    with zipfile.ZipFile(buf, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('panel.json', json.dumps(payload, indent=2, ensure_ascii=False))
        protocol_files = []
        if include_protocol_backups and installed and ssh is not None:
            bm = BackupManager(ssh)
            for proto in installed:
                try:
                    container = ''
                    if protocol_container_name_fn:
                        container = protocol_container_name_fn(proto) or ''
                    info = protocols.get(proto) or {}
                    container = info.get('container_name') or container or ''
                    created = bm.create_backup(proto, container)
                    if created.get('status') != 'success':
                        summary['protocol_errors'].append({
                            'protocol': proto,
                            'error': created.get('message') or 'create backup failed',
                        })
                        continue
                    name = (created.get('backup') or {}).get('name')
                    path = (created.get('backup') or {}).get('path')
                    if not name or not path:
                        summary['protocol_errors'].append({
                            'protocol': proto,
                            'error': 'backup path missing',
                        })
                        continue
                    blob = _download_bytes(ssh, path)
                    arcname = f'protocols/{name}'
                    zf.writestr(arcname, blob)
                    protocol_files.append({
                        'protocol': proto,
                        'filename': name,
                        'archive': arcname,
                        'container': container,
                    })
                    summary['protocols'].append(proto)
                except Exception as e:
                    logger.exception('Protocol backup failed for %s', proto)
                    summary['protocol_errors'].append({
                        'protocol': proto,
                        'error': str(e),
                    })
        manifest = {
            'format': MIGRATE_FORMAT,
            'exported_at': payload['exported_at'],
            'server': payload['server'],
            'protocol_backups': protocol_files,
            'counts': {
                'users': summary['users'],
                'connections': summary['connections'],
                'protocol_backups': len(protocol_files),
            },
            'notes': [
                'Point DNS A-record for connect_domain to the new server IP.',
                'Import onto the new server after installing the same protocols.',
                'Do not use Move Connections — it regenerates client keys.',
            ],
        }
        zf.writestr('manifest.json', json.dumps(manifest, indent=2, ensure_ascii=False))

    return buf.getvalue(), summary


def _merge_users(data: dict, imported_users: list) -> dict[str, str]:
    """Merge users into panel data. Returns map old_user_id -> effective_user_id."""
    id_map: dict[str, str] = {}
    existing_by_id = {str(u.get('id')): u for u in data.get('users') or [] if u.get('id')}
    existing_by_name = {
        str(u.get('username') or '').lower(): u
        for u in data.get('users') or []
        if u.get('username')
    }

    for raw in imported_users:
        if not isinstance(raw, dict):
            continue
        old_id = str(raw.get('id') or '')
        username = (raw.get('username') or '').strip()
        if not old_id and not username:
            continue

        if old_id and old_id in existing_by_id:
            id_map[old_id] = old_id
            continue

        by_name = existing_by_name.get(username.lower()) if username else None
        if by_name:
            id_map[old_id] = str(by_name['id'])
            continue

        new_user = _safe_user_public(raw)
        if not new_user.get('id'):
            new_user['id'] = str(uuid.uuid4())
        # Avoid unique username collisions with empty/duplicate names.
        if not username:
            username = f'user_{str(new_user["id"])[:8]}'
            new_user['username'] = username
        base = username
        n = 2
        while username.lower() in existing_by_name:
            username = f'{base}_{n}'
            n += 1
            new_user['username'] = username
        if new_user.get('role') == 'admin':
            # Never import an extra admin silently — demote to user.
            new_user['role'] = 'user'
        data.setdefault('users', []).append(new_user)
        existing_by_id[str(new_user['id'])] = new_user
        existing_by_name[username.lower()] = new_user
        if old_id:
            id_map[old_id] = str(new_user['id'])
        id_map[str(new_user['id'])] = str(new_user['id'])

    return id_map


def _merge_connections(
    data: dict,
    imported_conns: list,
    *,
    target_server_id: int,
    user_id_map: dict[str, str],
) -> dict:
    existing = data.setdefault('user_connections', [])
    existing_keys = {
        (
            str(c.get('user_id')),
            str(c.get('client_id')),
            str(c.get('protocol')),
            int(c.get('server_id', -1)),
        )
        for c in existing
        if isinstance(c, dict)
    }
    added = 0
    skipped = 0
    for raw in imported_conns:
        if not isinstance(raw, dict):
            continue
        old_user = str(raw.get('user_id') or '')
        user_id = user_id_map.get(old_user, old_user)
        client_id = raw.get('client_id')
        protocol = raw.get('protocol')
        if not user_id or not client_id or not protocol:
            skipped += 1
            continue
        key = (str(user_id), str(client_id), str(protocol), int(target_server_id))
        if key in existing_keys:
            skipped += 1
            continue
        conn = {
            'id': raw.get('id') or str(uuid.uuid4()),
            'user_id': user_id,
            'server_id': target_server_id,
            'protocol': protocol,
            'client_id': client_id,
            'name': raw.get('name') or '',
            'xui_panel_id': raw.get('xui_panel_id') or '',
            'created_at': raw.get('created_at') or _now_iso(),
            'last_bytes': raw.get('last_bytes') or 0,
        }
        # Avoid id collisions
        if any(c.get('id') == conn['id'] for c in existing):
            conn['id'] = str(uuid.uuid4())
        existing.append(conn)
        existing_keys.add(key)
        added += 1
    return {'added': added, 'skipped': skipped}


def _apply_server_meta(target: dict, exported_server: dict) -> None:
    """Preserve connect_domain / protocol ports on target; never overwrite SSH host."""
    info = dict(target.get('server_info') or {})
    domain = (exported_server.get('connect_domain') or '').strip()
    if domain and not (info.get('connect_domain') or '').strip():
        info['connect_domain'] = domain
    for key in ('ssl_domain', 'ssl_email'):
        val = (exported_server.get(key) or '').strip()
        if val and not (info.get(key) or '').strip():
            info[key] = val
    target['server_info'] = info

    protocols = dict(target.get('protocols') or {})
    for proto, meta in (exported_server.get('protocols') or {}).items():
        if not isinstance(meta, dict):
            continue
        cur = dict(protocols.get(proto) or {})
        if meta.get('port') and not cur.get('port'):
            cur['port'] = meta.get('port')
        if meta.get('connect_domain') and not cur.get('connect_domain'):
            cur['connect_domain'] = meta.get('connect_domain')
        if meta.get('installed'):
            cur['installed'] = True
        if meta.get('container_name') and not cur.get('container_name'):
            cur['container_name'] = meta.get('container_name')
        protocols[proto] = cur
    target['protocols'] = protocols


def import_migrate_zip(
    ssh,
    data: dict,
    target_server_id: int,
    zip_bytes: bytes,
    *,
    restore_protocols: bool = True,
    protocol_container_name_fn=None,
) -> dict:
    if target_server_id < 0 or target_server_id >= len(data.get('servers') or []):
        raise ValueError('Target server not found')

    with zipfile.ZipFile(io.BytesIO(zip_bytes), 'r') as zf:
        names = set(zf.namelist())
        if 'panel.json' not in names:
            raise ValueError('Invalid migrate archive: missing panel.json')
        panel = json.loads(zf.read('panel.json').decode('utf-8'))
        if panel.get('format') != MIGRATE_FORMAT:
            raise ValueError(f"Unsupported migrate format: {panel.get('format')}")
        manifest = {}
        if 'manifest.json' in names:
            try:
                manifest = json.loads(zf.read('manifest.json').decode('utf-8'))
            except Exception:
                manifest = {}

        user_map = _merge_users(data, panel.get('users') or [])
        conn_stats = _merge_connections(
            data,
            panel.get('user_connections') or [],
            target_server_id=target_server_id,
            user_id_map=user_map,
        )
        _apply_server_meta(data['servers'][target_server_id], panel.get('server') or {})

        # Optional invite links (remap server_id)
        invites_added = 0
        for inv in panel.get('invite_links') or []:
            if not isinstance(inv, dict):
                continue
            token = inv.get('token')
            if not token:
                continue
            existing_tokens = {i.get('token') for i in data.get('invite_links') or []}
            if token in existing_tokens:
                continue
            item = dict(inv)
            item['server_id'] = target_server_id
            remapped = []
            seen = set()
            for opt in item.get('server_options') or []:
                if not isinstance(opt, dict):
                    continue
                cloned = dict(opt)
                if cloned.get('kind') != 'xui':
                    cloned['server_id'] = target_server_id
                key = (
                    cloned.get('kind'),
                    cloned.get('server_id'),
                    cloned.get('protocol'),
                    cloned.get('xui_panel_id'),
                    cloned.get('xui_inbound_id'),
                )
                if key in seen:
                    continue
                seen.add(key)
                remapped.append(cloned)
            if remapped:
                item['server_options'] = remapped
            if not item.get('id'):
                item['id'] = str(uuid.uuid4())
            data.setdefault('invite_links', []).append(item)
            invites_added += 1

        restored = []
        restore_errors = []
        if restore_protocols and ssh is not None:
            bm = BackupManager(ssh)
            backups = manifest.get('protocol_backups') or []
            # Fallback: scan protocols/ folder
            if not backups:
                for name in names:
                    if name.startswith('protocols/') and name.endswith('.tar.gz'):
                        backups.append({
                            'protocol': name.rsplit('/', 1)[-1].split('-', 1)[0],
                            'filename': name.rsplit('/', 1)[-1],
                            'archive': name,
                        })
            target = data['servers'][target_server_id]
            protocols = target.get('protocols') or {}
            for item in backups:
                proto = item.get('protocol')
                filename = item.get('filename')
                archive = item.get('archive') or f'protocols/{filename}'
                if not proto or not filename or archive not in names:
                    continue
                try:
                    blob = zf.read(archive)
                    remote = f'{BackupManager.BACKUP_ROOT}/{bm.safe_protocol(proto)}/{bm.safe_filename(filename) or filename}'
                    _upload_bytes_sudo(ssh, blob, remote)
                    container = ''
                    if protocol_container_name_fn:
                        container = protocol_container_name_fn(proto) or ''
                    info = protocols.get(proto) or {}
                    container = info.get('container_name') or item.get('container') or container or ''
                    result = bm.restore_backup(proto, container, filename)
                    if result.get('status') == 'success':
                        restored.append(proto)
                        # Mark installed in panel metadata
                        pinfo = dict(protocols.get(proto) or {})
                        pinfo['installed'] = True
                        if container:
                            pinfo['container_name'] = container
                        protocols[proto] = pinfo
                    else:
                        restore_errors.append({
                            'protocol': proto,
                            'error': result.get('message') or 'restore failed',
                        })
                except Exception as e:
                    logger.exception('Failed restoring protocol %s', proto)
                    restore_errors.append({'protocol': proto, 'error': str(e)})
            target['protocols'] = protocols

    return {
        'users_mapped': len(user_map),
        'connections': conn_stats,
        'invites_added': invites_added,
        'protocols_restored': restored,
        'protocol_errors': restore_errors,
        'connect_domain': (panel.get('server') or {}).get('connect_domain') or '',
        'hint': (
            'Update DNS A-record for connect_domain to this server IP. '
            'Existing client configs keep working if protocol state was restored.'
        ),
    }
