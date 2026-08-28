"""3x-ui HTTP API client - create VLESS clients and fetch share links.

Works with modern panels (/panel/api/clients/*) and falls back to legacy
/panel/api/inbounds/addClient when needed.
"""

from __future__ import annotations

import json
import logging
import secrets
import string
import uuid
from typing import Any, Optional
from urllib.parse import quote

import httpx

logger = logging.getLogger(__name__)


def _new_sub_id(length: int = 16) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def _settings_creds(settings: dict) -> dict:
    sync = (settings or {}).get('sync') or {}
    return {
        'url': (sync.get('xui_url') or '').strip().rstrip('/'),
        'api_token': (sync.get('xui_api_token') or '').strip(),
        'username': (sync.get('xui_username') or '').strip(),
        'password': sync.get('xui_password') or '',
        'inbound_id': sync.get('xui_inbound_id'),
        'sub_url': (sync.get('xui_sub_url') or '').strip().rstrip('/'),
    }


def build_subscription_url(settings: dict, sub_id: str) -> str:
    """Build public subscription URL from panel settings + client subId."""
    sub_id = (sub_id or '').strip()
    if not sub_id:
        return ''
    base = _settings_creds(settings).get('sub_url') or ''
    if not base:
        return ''
    return f"{base}/{sub_id}"


def _resolve_settings(settings: dict, panel_id: Optional[str] = None) -> dict:
    """Scope settings to a specific xui panel when panel_id / multi-server registry is used."""
    try:
        from managers.xui_servers import resolve_panel_settings, ensure_xui_servers
        ensure_xui_servers(settings)
        return resolve_panel_settings(settings, panel_id)
    except Exception:
        return settings


class XuiApiError(RuntimeError):
    pass


class XuiApi:
    def __init__(self, base_url: str, *, api_token: str = '', username: str = '', password: str = ''):
        self.base_url = (base_url or '').rstrip('/')
        if not self.base_url:
            raise XuiApiError('3x-ui URL is not configured')
        self.api_token = (api_token or '').strip()
        self.username = (username or '').strip()
        self.password = password or ''
        self._client: Optional[httpx.AsyncClient] = None

    @classmethod
    def from_panel_settings(cls, settings: dict) -> 'XuiApi':
        c = _settings_creds(settings)
        return cls(c['url'], api_token=c['api_token'], username=c['username'], password=c['password'])

    async def __aenter__(self) -> 'XuiApi':
        headers = {'Accept': 'application/json'}
        if self.api_token:
            headers['Authorization'] = f'Bearer {self.api_token}'
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=30.0,
            follow_redirects=True,
            headers=headers,
        )
        if not self.api_token:
            await self._login()
        return self

    async def __aexit__(self, *args):
        if self._client:
            await self._client.aclose()
            self._client = None

    async def _login(self):
        if not self.username or not self.password:
            raise XuiApiError('Provide 3x-ui API token or username/password')
        resp = await self._client.post('/login', json={
            'username': self.username,
            'password': self.password,
        })
        if resp.status_code != 200:
            raise XuiApiError(f'3x-ui login failed: HTTP {resp.status_code}')
        try:
            body = resp.json()
        except Exception:
            body = {}
        if body.get('success') is False:
            raise XuiApiError(f"3x-ui login failed: {body.get('msg', 'unknown error')}")

    async def _request(self, method: str, path: str, **kwargs) -> Any:
        assert self._client is not None
        resp = await self._client.request(method, path, **kwargs)
        try:
            payload = resp.json()
        except Exception:
            raise XuiApiError(f'3x-ui {method} {path}: HTTP {resp.status_code} non-JSON')
        if resp.status_code >= 400:
            raise XuiApiError(
                f"3x-ui {method} {path}: HTTP {resp.status_code} {payload.get('msg') or payload}"
            )
        if isinstance(payload, dict) and payload.get('success') is False:
            raise XuiApiError(payload.get('msg') or f'3x-ui {method} {path} failed')
        return payload

    async def list_inbounds(self) -> list:
        for path, method in (
            ('/panel/api/inbounds/list', 'GET'),
            ('/panel/api/inbounds/list', 'POST'),
            ('/panel/inbound/list', 'POST'),
        ):
            try:
                payload = await self._request(method, path)
            except XuiApiError:
                continue
            obj = payload.get('obj') if isinstance(payload, dict) else None
            if isinstance(obj, list):
                return obj
        return []

    async def list_vless_inbounds(self) -> list:
        result = []
        for inbound in await self.list_inbounds():
            if not isinstance(inbound, dict):
                continue
            proto = (inbound.get('protocol') or '').lower()
            if proto != 'vless':
                continue
            result.append({
                'id': inbound.get('id'),
                'remark': inbound.get('remark') or f"VLESS:{inbound.get('port')}",
                'port': inbound.get('port'),
                'protocol': proto,
                'enable': bool(inbound.get('enable', True)),
            })
        return result

    async def get_inbound(self, inbound_id: int) -> dict:
        inbound_id = int(inbound_id)
        for inbound in await self.list_inbounds():
            if isinstance(inbound, dict) and int(inbound.get('id') or 0) == inbound_id:
                return inbound
        raise XuiApiError(f'Inbound #{inbound_id} not found on 3x-ui')

    @staticmethod
    def _parse_inbound_settings(inbound: dict) -> dict:
        settings_raw = inbound.get('settings') or '{}'
        if isinstance(settings_raw, str):
            try:
                settings_obj = json.loads(settings_raw)
            except Exception:
                settings_obj = {}
        else:
            settings_obj = settings_raw if isinstance(settings_raw, dict) else {}
        return settings_obj if isinstance(settings_obj, dict) else {}

    def _client_template_from_inbound(self, inbound: dict) -> dict:
        """Copy only fields 3x-ui already uses on this inbound — do not invent extras."""
        settings_obj = self._parse_inbound_settings(inbound)
        clients = settings_obj.get('clients') or []
        template = next((c for c in clients if isinstance(c, dict)), None) or {}
        flow = template.get('flow')
        if not isinstance(flow, str):
            flow = ''
        # If no existing clients, detect Reality → vision (required for those inbounds)
        if not flow:
            stream_raw = inbound.get('streamSettings') or '{}'
            if isinstance(stream_raw, str):
                try:
                    stream = json.loads(stream_raw)
                except Exception:
                    stream = {}
            else:
                stream = stream_raw if isinstance(stream_raw, dict) else {}
            security = (stream.get('security') or '').lower()
            network = (stream.get('network') or '').lower()
            if security == 'reality' and network in ('tcp', 'raw', ''):
                flow = 'xtls-rprx-vision'
        return {
            'flow': flow,
            'limitIp': int(template.get('limitIp') or 0),
            'totalGB': 0,
            'tgId': '' if template.get('tgId') in (None, 0) else str(template.get('tgId') or ''),
        }

    async def add_vless_client(
        self,
        *,
        email: str,
        inbound_id: int,
        enable: bool = True,
        expiry_time: int = 0,
    ) -> dict:
        """Add client via 3x-ui addClient only. Minimal payload; flow taken from inbound."""
        email = (email or '').strip()
        if not email:
            raise XuiApiError('Client email is required')
        if not inbound_id:
            raise XuiApiError('VLESS inbound id is required')

        inbound = await self.get_inbound(int(inbound_id))
        if (inbound.get('protocol') or '').lower() != 'vless':
            raise XuiApiError(f'Inbound #{inbound_id} is not VLESS')

        tmpl = self._client_template_from_inbound(inbound)
        client_uuid = str(uuid.uuid4())
        sub_id = _new_sub_id()

        # Minimal client object — nothing beyond what 3x-ui expects for this inbound
        client = {
            'id': client_uuid,
            'email': email,
            'enable': bool(enable),
            'flow': tmpl['flow'],
            'limitIp': tmpl['limitIp'],
            'totalGB': 0,
            'expiryTime': int(expiry_time or 0),
            'tgId': tmpl['tgId'],
            'subId': sub_id,
        }

        # Official path: addClient with settings as JSON string (object form breaks some builds)
        await self._request(
            'POST',
            '/panel/api/inbounds/addClient',
            json={
                'id': int(inbound_id),
                'settings': json.dumps({'clients': [client]}),
            },
        )

        # Share links ONLY from the panel — never build vless:// here
        links = await self.get_client_links(email)
        if not links:
            links = await self.get_sub_links(sub_id)

        return {
            'client_id': email,
            'uuid': client_uuid,
            'sub_id': sub_id,
            'email': email,
            'config': '',
            'links': links,
            'expiry_time': int(expiry_time or 0),
            'inbound_id': int(inbound_id),
        }

    async def get_client_links(self, email: str) -> list:
        email = (email or '').strip()
        if not email:
            return []
        for path in (
            f'/panel/api/clients/links/{quote(email, safe="")}',
            f'/panel/api/inbounds/clientLinks/0/{quote(email, safe="")}',
        ):
            try:
                payload = await self._request('GET', path)
                obj = payload.get('obj') if isinstance(payload, dict) else None
                if isinstance(obj, list):
                    return [x for x in obj if isinstance(x, str) and x.strip()]
            except XuiApiError as e:
                logger.warning('get_client_links %s failed: %s', path, e)
        return []

    async def get_sub_links(self, sub_id: str) -> list:
        """Ask 3x-ui for protocol URLs produced for this subscription id."""
        sub_id = (sub_id or '').strip()
        if not sub_id:
            return []
        path = f'/panel/api/inbounds/getSubLinks/{quote(sub_id, safe="")}'
        try:
            payload = await self._request('GET', path)
            obj = payload.get('obj') if isinstance(payload, dict) else None
            if isinstance(obj, list):
                return [x for x in obj if isinstance(x, str) and x.strip()]
        except XuiApiError as e:
            logger.warning('getSubLinks failed: %s', e)
        return []

    async def get_panel_sub_base(self) -> str:
        """Try to read public subscription base URL from 3x-ui panel settings."""
        for path, method in (
            ('/panel/api/setting', 'GET'),
            ('/panel/setting/all', 'POST'),
            ('/panel/api/settings', 'GET'),
        ):
            try:
                payload = await self._request(method, path)
            except XuiApiError:
                continue
            obj = payload.get('obj') if isinstance(payload, dict) else payload
            if not isinstance(obj, dict):
                continue
            # Common field names across 3x-ui versions
            sub_uri = (obj.get('subURI') or obj.get('subUri') or obj.get('sub_uri') or '').strip()
            sub_path = (obj.get('subPath') or obj.get('sub_path') or '/sub').strip() or '/sub'
            sub_port = obj.get('subPort') or obj.get('sub_port')
            sub_listen = (obj.get('subListen') or '').strip()
            if sub_uri:
                return sub_uri.rstrip('/')
            # Build from panel host + sub path if only path is configured
            if sub_path and self.base_url:
                from urllib.parse import urlparse, urlunparse
                parsed = urlparse(self.base_url)
                host = sub_listen or parsed.hostname or ''
                if not host:
                    continue
                scheme = 'https' if parsed.scheme == 'https' else 'http'
                netloc = f'{host}:{sub_port}' if sub_port else host
                path_part = sub_path if sub_path.startswith('/') else f'/{sub_path}'
                return urlunparse((scheme, netloc, path_part.rstrip('/'), '', '', ''))
        return ''

    async def resolve_share_link(self, *, email: str, sub_id: str = '', configured_sub_base: str = '') -> dict:
        """Use only links returned by 3x-ui. Do not synthesize protocol configs."""
        email = (email or '').strip()
        sub_id = (sub_id or '').strip()

        links: list = []
        if email:
            links = await self.get_client_links(email)
        if not links and sub_id:
            links = await self.get_sub_links(sub_id)

        # Prefer protocol share from panel; then HTTP(S) subscription URL from panel
        panel_proto = next(
            (u for u in links if isinstance(u, str) and u.startswith(('vless://', 'vmess://', 'trojan://', 'ss://'))),
            '',
        )
        panel_http = next(
            (u for u in links if isinstance(u, str) and u.startswith(('http://', 'https://'))),
            '',
        )

        # Subscription URL: panel HTTP link first; optional configured base only as last resort
        base = (configured_sub_base or '').strip().rstrip('/')
        if not panel_http and not base:
            try:
                base = (await self.get_panel_sub_base() or '').rstrip('/')
            except Exception as e:
                logger.warning('get_panel_sub_base failed: %s', e)
                base = ''
        subscription_url = panel_http or (f'{base}/{sub_id}' if base and sub_id else '')

        # Prefer panel-generated protocol link (real config); else subscription URL
        share = panel_proto or subscription_url or (links[0] if links else '')
        return {
            'subscription_url': subscription_url,
            'links': links,
            'share': share,
            'sub_base': base,
        }


    async def delete_client(self, email: str) -> None:
        email = (email or '').strip()
        if not email:
            return
        path = f'/panel/api/clients/del/{quote(email, safe="")}'
        try:
            await self._request('POST', path)
            return
        except XuiApiError as e:
            logger.warning('clients/del failed (%s), trying legacy', e)
        # Legacy: need inbound id — try remove by scanning
        for inbound in await self.list_inbounds():
            if not isinstance(inbound, dict):
                continue
            settings = inbound.get('settings')
            if isinstance(settings, str):
                try:
                    settings = json.loads(settings)
                except Exception:
                    settings = {}
            clients = (settings or {}).get('clients') if isinstance(settings, dict) else None
            if not isinstance(clients, list):
                continue
            match = next((c for c in clients if isinstance(c, dict) and c.get('email') == email), None)
            if not match:
                continue
            cid = match.get('id') or email
            inbound_id = inbound.get('id')
            for path in (
                f'/panel/api/inbounds/{inbound_id}/delClient/{quote(str(cid), safe="")}',
                f'/panel/api/inbounds/{inbound_id}/delClientByEmail/{quote(email, safe="")}',
            ):
                try:
                    await self._request('POST', path)
                    return
                except XuiApiError:
                    continue
        raise XuiApiError(f'Failed to delete 3x-ui client {email}')

    async def set_client_enabled(self, email: str, enable: bool) -> None:
        email = (email or '').strip()
        if not email:
            return
        # Prefer full client get + update
        try:
            payload = await self._request('GET', f'/panel/api/clients/get/{quote(email, safe="")}')
            obj = payload.get('obj') if isinstance(payload, dict) else None
            client = None
            if isinstance(obj, dict):
                client = obj.get('client') if isinstance(obj.get('client'), dict) else obj
            if isinstance(client, dict):
                client = dict(client)
                client['enable'] = bool(enable)
                client['email'] = email
                await self._request(
                    'POST',
                    f'/panel/api/clients/update/{quote(email, safe="")}',
                    json=client,
                )
                return
        except XuiApiError as e:
            logger.warning('toggle via clients/update failed: %s', e)
        raise XuiApiError(f'Failed to toggle 3x-ui client {email}')


async def xui_create_vless_config(
    settings: dict,
    *,
    name: str,
    inbound_id: Optional[int] = None,
    expiry_time: int = 0,
    panel_id: Optional[str] = None,
) -> dict:
    """Create client on selected 3x-ui inbound; return only links from the panel."""
    scoped = _resolve_settings(settings, panel_id)
    creds = _settings_creds(scoped)
    inbound = inbound_id if inbound_id not in (None, 0, '0') else creds.get('inbound_id')
    try:
        inbound = int(inbound or 0)
    except (TypeError, ValueError):
        inbound = 0
    if not inbound:
        raise XuiApiError('Select a VLESS inbound from 3x-ui')

    async with XuiApi.from_panel_settings(scoped) as api:
        base = ''.join(ch if ch.isalnum() or ch in '._-+@' else '_' for ch in (name or 'user').strip())
        base = base[:48] or f'user_{secrets.token_hex(4)}'
        email = base
        created = None
        for _ in range(5):
            try:
                created = await api.add_vless_client(
                    email=email,
                    inbound_id=inbound,
                    expiry_time=int(expiry_time or 0),
                )
                break
            except XuiApiError as e:
                if 'exist' in str(e).lower() or 'duplicate' in str(e).lower() or 'already' in str(e).lower():
                    email = f'{base}_{secrets.token_hex(3)}'
                    continue
                raise
        if created is None:
            created = await api.add_vless_client(
                email=email,
                inbound_id=inbound,
                expiry_time=int(expiry_time or 0),
            )

        share = await api.resolve_share_link(
            email=created.get('email') or email,
            sub_id=created.get('sub_id') or '',
            configured_sub_base=creds.get('sub_url') or '',
        )
        panel_links = share.get('links') or created.get('links') or []
        created['links'] = panel_links
        created['subscription_url'] = share.get('subscription_url') or ''
        # Prefer real vless:// (etc.) from 3x-ui; subscription URL only as fallback
        created['config'] = share.get('share') or ''
        if not created['config'] and panel_links:
            created['config'] = panel_links[0]
        created['inbound_id'] = int(created.get('inbound_id') or inbound)
        created['panel_id'] = panel_id or ''
        return created


async def xui_get_config(settings: dict, email: str, panel_id: Optional[str] = None) -> str:
    scoped = _resolve_settings(settings, panel_id)
    creds = _settings_creds(scoped)
    async with XuiApi.from_panel_settings(scoped) as api:
        sub_id = ''
        try:
            for inbound in await api.list_inbounds():
                if not isinstance(inbound, dict):
                    continue
                settings_raw = inbound.get('settings') or '{}'
                if isinstance(settings_raw, str):
                    try:
                        settings_obj = json.loads(settings_raw)
                    except Exception:
                        settings_obj = {}
                else:
                    settings_obj = settings_raw if isinstance(settings_raw, dict) else {}
                for c in settings_obj.get('clients') or []:
                    if isinstance(c, dict) and (c.get('email') or '') == email:
                        sub_id = (c.get('subId') or c.get('sub_id') or '').strip()
                        break
                if sub_id:
                    break
        except Exception as e:
            logger.warning('Could not resolve subId for %s: %s', email, e)

        share = await api.resolve_share_link(
            email=email,
            sub_id=sub_id,
            configured_sub_base=creds.get('sub_url') or '',
        )
        if share.get('share'):
            return share['share']
        links = share.get('links') or await api.get_client_links(email)
    vless = next((u for u in links if isinstance(u, str) and u.startswith('vless://')), None)
    if vless:
        return vless
    if links:
        return links[0]
    raise XuiApiError(f'No share links for 3x-ui client {email}')


async def xui_delete_client(settings: dict, email: str, panel_id: Optional[str] = None) -> None:
    scoped = _resolve_settings(settings, panel_id)
    async with XuiApi.from_panel_settings(scoped) as api:
        await api.delete_client(email)


async def xui_toggle_client(settings: dict, email: str, enable: bool, panel_id: Optional[str] = None) -> None:
    scoped = _resolve_settings(settings, panel_id)
    async with XuiApi.from_panel_settings(scoped) as api:
        await api.set_client_enabled(email, enable)


async def xui_list_vless_inbounds(settings: dict, panel_id: Optional[str] = None) -> list:
    scoped = _resolve_settings(settings, panel_id)
    async with XuiApi.from_panel_settings(scoped) as api:
        return await api.list_vless_inbounds()
