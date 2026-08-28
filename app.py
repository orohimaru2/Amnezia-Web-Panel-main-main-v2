import os
import sys
import json
import logging
from collections import Counter

from dotenv import load_dotenv
load_dotenv()
import base64
import hashlib
import secrets
import uuid
import asyncio
import platform
import re
import shutil
import shlex
import tempfile
import subprocess
import tarfile
import threading
import time
import urllib.request
import zipfile
import signal
from datetime import datetime, timezone
import io
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse, StreamingResponse, FileResponse
from starlette.background import BackgroundTask
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi import FastAPI, Request, Query, UploadFile, File, HTTPException
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict
import uvicorn
import httpx

try:
    from multicolorcaptcha import CaptchaGenerator
except ImportError:
    CaptchaGenerator = None

from managers.ssh_manager import SSHManager, run_pooled
from managers import api_cache
from managers.awg_manager import AWGManager
from managers.xray_manager import XrayManager
from managers.wireguard_manager import WireGuardManager
from managers.backup_manager import BackupManager
from managers.update_manager import (
    UpdateManager,
    version_gt,
    api_latest_url,
    repo_url,
    resolve_latest_remote_version,
)
import telegram_bot as tg_bot

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Ordered list of OpenAPI tag groups — the order here drives the section order in /docs and /redoc.
OPENAPI_TAGS = [
    {"name": "System Templates", "description": "HTML pages served to browsers. These return Jinja-rendered templates rather than a JSON contract — they are not part of the public API and are listed here only for completeness."},
    {"name": "Authentication", "description": "Login, captcha, and session lifecycle."},
    {"name": "Servers", "description": "Server inventory, lifecycle and host-level operations (add, edit, delete, ping, reorder, reboot, clear, stats, status check)."},
    {"name": "Protocols", "description": "Install, uninstall, container start/stop and raw config editing for the protocols/services on a server (AWG, Xray, WireGuard, Telemt, AmneziaDNS, AdGuard Home, SOCKS5)."},
    {"name": "Connections", "description": "Per-protocol VPN client connections on a server (CRUD plus enable/disable and config retrieval)."},
    {"name": "Users", "description": "Panel user accounts and the connections assigned to them."},
    {"name": "Self-service", "description": "Endpoints called by a regular user for their own data (the /my surface)."},
    {"name": "Sharing", "description": "Public, token-protected configuration sharing for end users — no panel session required."},
    {"name": "Settings", "description": "Panel-wide settings, Telegram bot, Remnawave sync, JSON backup/restore."},
    {"name": "API Tokens", "description": "Bearer tokens for external integrations. Send the token in `Authorization: Bearer <token>`; tokens have admin-equivalent rights and are tied to the admin user that created them."},
]

app = FastAPI(
    title="Amnezia Web Panel",
    openapi_tags=OPENAPI_TAGS,
    # FastAPI's stock /redoc loads the JS bundle from `redoc@next` on jsdelivr —
    # an unstable rolling tag that breaks unpredictably. Disable the default and
    # serve our own /redoc just below, pinned to the stable v2 bundle.
    redoc_url=None,
)


@app.get("/redoc", include_in_schema=False)
async def custom_redoc():
    """Self-curated ReDoc page. Differs from FastAPI's default in two ways:
    pinned bundle (`redoc@2` instead of `@next`) and Google Fonts disabled
    (the Montserrat/Roboto stylesheet is blocked on a lot of networks and made
    the page hang for some users)."""
    from fastapi.openapi.docs import get_redoc_html
    return get_redoc_html(
        openapi_url=app.openapi_url or "/openapi.json",
        title=f"{app.title} — ReDoc",
        redoc_js_url="https://cdn.jsdelivr.net/npm/redoc@2/bundles/redoc.standalone.js",
        with_google_fonts=False,
    )
app.add_middleware(SessionMiddleware, secret_key=os.environ.get('SECRET_KEY', secrets.token_hex(32)))

# Mount static files & templates
app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

if getattr(sys, 'frozen', False):
    application_path = os.path.dirname(sys.executable)
else:
    application_path = os.path.dirname(__file__)

DATA_FILE = os.path.join(application_path, 'data.json')  # legacy JSON; used only for one-shot import / export
CURRENT_VERSION = "v3.2.2"
RELEASES_REPO_URL = repo_url()
RELEASES_API_LATEST = api_latest_url()
BIN_DIR = os.environ.get('TUNNEL_BIN_DIR', os.path.join(application_path, 'bin'))
TUNNEL_STATE_FILE = os.environ.get('TUNNEL_STATE_FILE', os.path.join(application_path, 'tunnels_state.json'))

# Panel state lives in PostgreSQL 17 (see db/). load_data/save_data keep the old dict API.
from db import (  # noqa: E402
    backup_filename,
    clear_tunnel_state,
    ensure_db_ready,
    export_data_dict,
    export_database_sql,
    delete_api_token,
    insert_api_token,
    invalidate_data_cache,
    load_data,
    load_tunnel_state,
    normalize_import_data,
    restore_database_sql,
    save_data,
    save_tunnel_state,
    update_api_token_last_used,
    update_tunnel_state,
)


class TunnelRuntime:
    def __init__(self):
        self.process = None
        self.pid = None
        self.public_url = ''
        self.last_error = ''
        self.started_at = None
        self.output = []


TUNNEL_RUNTIMES = {
    'cloudflare': TunnelRuntime(),
    'ngrok': TunnelRuntime(),
}
TUNNEL_LOCK = threading.Lock()
TUNNEL_URL_RE = re.compile(r'https://[^\s"\']+')
WARP_CLI_COMMAND = 'warp-cli.exe' if os.name == 'nt' else 'warp-cli'
NORDVPN_CLI_COMMAND = 'nordvpn.exe' if os.name == 'nt' else 'nordvpn'



# ======================== Translations ========================
TRANSLATIONS = {}

def load_translations():
    global TRANSLATIONS
    trans_dir = os.path.join(os.path.dirname(__file__), 'translations')
    if os.path.exists(trans_dir):
        for f in os.listdir(trans_dir):
            if f.endswith('.json'):
                lang = f.split('.')[0]
                try:
                    with open(os.path.join(trans_dir, f), 'r', encoding='utf-8-sig') as tf:
                        TRANSLATIONS[lang] = json.load(tf)
                except Exception as e:
                    logger.error(f"Error loading translation {f}: {e}")
    logger.info(f"Loaded translations: {list(TRANSLATIONS.keys())}")

def _t(text_id, lang='en'):
    lang_batch = TRANSLATIONS.get(lang, TRANSLATIONS.get('en', {}))
    return lang_batch.get(text_id, text_id)

load_translations()


# ======================== Helpers ========================

# Global lock for panel DB writes to prevent race conditions during async operations
DATA_LOCK = asyncio.Lock()


async def load_data_async():
    """Load panel state off the event loop (uses in-process cache)."""
    return await asyncio.to_thread(load_data)


async def save_data_async(data):
    """Saves panel state to PostgreSQL in a thread-safe way."""
    async with DATA_LOCK:
        await asyncio.to_thread(save_data, data)


def get_ssh(server):
    return SSHManager(
        host=server['host'],
        port=server.get('ssh_port', 22),
        username=server['username'],
        password=server.get('password'),
        private_key=server.get('private_key'),
    )


def run_ssh(server, fn):
    """Run fn(ssh) on a pooled live session. Serializes commands per host."""
    return run_pooled(
        server['host'],
        server.get('ssh_port', 22),
        server['username'],
        server.get('password'),
        server.get('private_key'),
        fn,
    )


def invalidate_server_reads(server_id, protocol=None):
    if protocol:
        api_cache.invalidate(f'conn:{server_id}:{protocol}')
        api_cache.invalidate(f'clients:{server_id}:{protocol}')
    else:
        api_cache.invalidate_prefix(f'conn:{server_id}:')
        api_cache.invalidate_prefix(f'clients:{server_id}:')
    api_cache.invalidate(f'stats:{server_id}')


WG_AWG_PROTOCOLS = frozenset({'awg', 'awg2', 'awg3', 'awg_legacy', 'wireguard'})


def get_server_connect_host(server: dict, protocol: Optional[str] = None) -> str:
    """Hostname embedded in client VPN configs (Endpoint, vless://, etc.).

    SSH still uses server['host']; this value can be a DNS name so clients
    keep working after the server IP changes — update the A-record only.
    Per-protocol connect_domain (AWG / WireGuard) overrides the server default.
    """
    protocols = server.get('protocols') or {}
    if protocol:
        base = protocol_base(protocol)
        if base in WG_AWG_PROTOCOLS:
            for key in (protocol, base):
                pinfo = protocols.get(key) if key else None
                if isinstance(pinfo, dict):
                    domain = (pinfo.get('connect_domain') or '').strip()
                    if domain:
                        return domain.lower().rstrip('.')
    info = server.get('server_info') or {}
    for key in ('connect_domain', 'ssl_domain'):
        val = (info.get(key) or '').strip()
        if val:
            return val.lower().rstrip('.')
    return (server.get('host') or '').strip()


def _ascii_filename_component(value: str, *, fallback: str = 'file') -> str:
    """HTTP headers are latin-1; keep only ASCII for Content-Disposition filenames."""
    text = str(value or '').strip()
    # NFKD strip accents, then drop non-ASCII leftovers (e.g. Cyrillic names).
    import unicodedata
    text = unicodedata.normalize('NFKD', text)
    text = text.encode('ascii', 'ignore').decode('ascii')
    text = re.sub(r'[^A-Za-z0-9._-]+', '_', text).strip('._-')
    return text or fallback


def get_current_user(request: Request, data: Optional[dict] = None):
    user_id = request.session.get('user_id')
    if not user_id:
        return None
    snapshot = data if data is not None else load_data()
    for u in snapshot.get('users', []):
        if u['id'] == user_id:
            return u
    return None


def tpl(request, template, **kwargs):
    data = load_data()
    lang = request.cookies.get('lang', 'en')
    donate_cfg = (data.get('settings') or {}).get('donate') or {}
    ctx = {
        'request': request,
        'current_user': get_current_user(request, data),
        'site_settings': data.get('settings', {}).get('appearance', {}),
        'captcha_settings': data.get('settings', {}).get('captcha', {}),
        'telegram_settings': data.get('settings', {}).get('telegram', {}),
        'donate_enabled': bool(donate_cfg.get('enabled', True)),
        'bot_running': tg_bot.is_running(),
        'lang': lang,
        '_': lambda text_id: _t(text_id, lang),
        'translations_json': json.dumps(TRANSLATIONS.get(lang, TRANSLATIONS.get('en', {}))),
        # Keep for legacy JS; prefer translations_json on new pages
        'all_translations_json': json.dumps(TRANSLATIONS),
        'releases_repo_url': RELEASES_REPO_URL,
    }
    ctx.update(kwargs)
    return templates.TemplateResponse(template, ctx)


def get_panel_listen_port(data: Optional[dict] = None) -> int:
    for env_key in ('APP_PORT', 'PORT'):
        try:
            env_port = int(os.environ.get(env_key, '0') or '0')
        except ValueError:
            env_port = 0
        if env_port:
            return env_port
    if data is None:
        data = load_data()
    ssl_conf = data.get('settings', {}).get('ssl', {}) or {}
    try:
        return int(ssl_conf.get('panel_port', 5000) or 5000)
    except (TypeError, ValueError):
        return 5000


def panel_ssl_active(data: Optional[dict] = None) -> bool:
    # Behind Docker / reverse proxy TLS is always terminated outside the app.
    if os.environ.get('PANEL_IN_DOCKER') == '1' or os.environ.get('PANEL_BEHIND_PROXY') == '1':
        return False
    if os.environ.get('APP_PORT') or os.environ.get('PORT'):
        return False
    if data is None:
        data = load_data()
    ssl_conf = data.get('settings', {}).get('ssl', {}) or {}
    if not ssl_conf.get('enabled'):
        return False
    cert_path = ssl_conf.get('cert_path')
    key_path = ssl_conf.get('key_path')
    if ssl_conf.get('cert_text') or ssl_conf.get('key_text'):
        return True
    return bool(
        cert_path and key_path
        and os.path.exists(cert_path) and os.path.exists(key_path)
    )


def get_panel_local_url(request: Optional[Request] = None):
    data = load_data()
    scheme = 'https' if panel_ssl_active(data) else 'http'
    host = '127.0.0.1'
    port = get_panel_listen_port(data)
    if request:
        scheme = request.url.scheme or scheme
        host = request.url.hostname or host
        port = request.url.port or port
    return f"{scheme}://{host}:{port}"


def get_panel_tunnel_target_url():
    data = load_data()
    scheme = 'https' if panel_ssl_active(data) else 'http'
    port = get_panel_listen_port(data)
    return f"{scheme}://127.0.0.1:{port}"


def get_panel_public_url(request: Optional[Request] = None) -> str:
    if request is not None:
        forwarded_proto = (request.headers.get('x-forwarded-proto') or '').split(',')[0].strip()
        scheme = forwarded_proto or request.url.scheme or 'http'
        host = (
            (request.headers.get('x-forwarded-host') or '').split(',')[0].strip()
            or request.headers.get('host')
            or request.url.netloc
        )
        if host:
            return f"{scheme}://{host}/"
    return get_panel_local_url(request).rstrip('/') + '/'


def enrich_update_result(request: Request, result: dict) -> dict:
    result['panel_url'] = get_panel_public_url(request)
    return result


@app.exception_handler(StarletteHTTPException)
async def custom_http_exception_handler(request: Request, exc: StarletteHTTPException):
    if exc.status_code != 404:
        detail = exc.detail if isinstance(exc.detail, str) else 'Error'
        if request.url.path.startswith('/api/'):
            return JSONResponse({'error': detail}, status_code=exc.status_code)
        return HTMLResponse(f'<h1>{exc.status_code}</h1><p>{detail}</p>', status_code=exc.status_code)
    if request.url.path.startswith('/api/') or 'application/json' in (request.headers.get('accept') or '').lower():
        return JSONResponse({'error': 'Not found'}, status_code=404)
    home = get_panel_public_url(request)
    return HTMLResponse(
        f'''<!DOCTYPE html><html><head><meta charset="utf-8"><title>Amnezia Panel</title></head>
        <body style="font-family:sans-serif;max-width:520px;margin:3rem auto;padding:0 1rem;">
        <h1>Страница не найдена</h1>
        <p>Адрес <code>{request.url.path}</code> не существует в панели.</p>
        <p>Если вы только что обновили панель, подождите 10–30 секунд и откройте:</p>
        <p><a href="{home}">{home}</a></p>
        <p><a href="/health">/health</a> — проверка, что панель запущена.</p>
        </body></html>''',
        status_code=404,
    )


@app.get('/health', include_in_schema=False)
@app.get('/api/health', include_in_schema=False)
async def health_check():
    return {'status': 'ok', 'version': CURRENT_VERSION}


def get_warp_cli_binary():
    found = shutil.which(WARP_CLI_COMMAND)
    if found:
        return found
    if os.name == 'nt':
        for base in (os.environ.get('ProgramFiles'), os.environ.get('ProgramFiles(x86)')):
            if not base:
                continue
            candidate = os.path.join(base, 'Cloudflare', 'Cloudflare WARP', 'warp-cli.exe')
            if os.path.exists(candidate):
                return candidate
    return None


def is_warp_cli_installed():
    return bool(get_warp_cli_binary())


def _warp_install_hint():
    system = platform.system().lower()
    if system == 'windows':
        return 'Install Cloudflare WARP from https://1.1.1.1/ or winget install Cloudflare.Warp, then restart this panel.'
    if system == 'darwin':
        return 'Install Cloudflare WARP from https://1.1.1.1/ or brew install --cask cloudflare-warp, then restart this panel.'
    return 'Install the official cloudflare-warp package for your Linux distribution, start warp-svc, then restart this panel.'


def run_warp_cli(*args, timeout: int = 12):
    binary = get_warp_cli_binary()
    if not binary:
        raise RuntimeError(_warp_install_hint())
    creationflags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
    command = [binary]
    if '--accept-tos' not in args:
        command.append('--accept-tos')
    command.extend(args)
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding='utf-8',
        errors='replace',
        timeout=timeout,
        creationflags=creationflags,
    )
    output = '\n'.join(part.strip() for part in (result.stdout, result.stderr) if part and part.strip())
    if result.returncode != 0:
        raise RuntimeError(output or f'warp-cli exited with code {result.returncode}')
    return output


def _parse_warp_status(output: str):
    lowered = (output or '').lower()
    if 'registration missing' in lowered or 'not registered' in lowered or 'not enrolled' in lowered:
        return 'not_registered'
    if 'disconnect' in lowered or 'disabled' in lowered:
        return 'disconnected'
    if 'connecting' in lowered:
        return 'connecting'
    if 'connected' in lowered:
        return 'connected'
    return 'unknown'


def get_warp_status():
    installed = is_warp_cli_installed()
    status = {
        'installed': installed,
        'running': False,
        'connected': False,
        'status': 'not_installed' if not installed else 'unknown',
        'raw': '',
        'last_error': '' if installed else _warp_install_hint(),
        'install_hint': _warp_install_hint(),
    }
    if not installed:
        return status
    try:
        output = run_warp_cli('status')
        parsed = _parse_warp_status(output)
        status.update({
            'running': parsed in ('connected', 'connecting'),
            'connected': parsed == 'connected',
            'status': parsed,
            'raw': output,
            'last_error': '',
        })
    except Exception as e:
        status['last_error'] = str(e)
        lowered = str(e).lower()
        if 'registration missing' in lowered or 'not registered' in lowered or 'not enrolled' in lowered:
            status['status'] = 'not_registered'
        elif 'service' in lowered or 'daemon' in lowered or 'warp-svc' in lowered:
            status['status'] = 'service_unavailable'
        else:
            status['status'] = 'error'
    return status


def enable_warp():
    current = get_warp_status()
    if not current.get('installed'):
        raise RuntimeError(current.get('install_hint') or _warp_install_hint())
    try:
        if current.get('status') == 'not_registered':
            run_warp_cli('registration', 'new', timeout=30)
        run_warp_cli('mode', 'warp', timeout=15)
        run_warp_cli('connect', timeout=30)
    except Exception as e:
        message = str(e)
        if 'registration' in message.lower() or 'not registered' in message.lower() or 'not enrolled' in message.lower():
            run_warp_cli('registration', 'new', timeout=30)
            run_warp_cli('mode', 'warp', timeout=15)
            run_warp_cli('connect', timeout=30)
        else:
            raise
    time.sleep(1)
    return get_warp_status()


def disable_warp():
    current = get_warp_status()
    if not current.get('installed'):
        raise RuntimeError(current.get('install_hint') or _warp_install_hint())
    run_warp_cli('disconnect', timeout=20)
    time.sleep(0.5)
    return get_warp_status()


def get_nordvpn_cli_binary():
    found = shutil.which(NORDVPN_CLI_COMMAND)
    if found:
        return found
    if os.name == 'nt':
        for base in (os.environ.get('ProgramFiles'), os.environ.get('ProgramFiles(x86)')):
            if not base:
                continue
            for sub in ('NordVPN', 'NordVPN NordSec'):
                candidate = os.path.join(base, sub, 'nordvpn.exe')
                if os.path.exists(candidate):
                    return candidate
    return None


def is_nordvpn_cli_installed():
    return bool(get_nordvpn_cli_binary())


def _nordvpn_install_hint():
    system = platform.system().lower()
    if system == 'windows':
        return (
            'Install NordVPN from https://nordvpn.com/download/ or Microsoft Store, '
            'then restart this panel.'
        )
    if system == 'darwin':
        return 'Install NordVPN for macOS from https://nordvpn.com/download/, then restart this panel.'
    return (
        'Install NordVPN CLI: sh <(curl -sSf https://downloads.nordcdn.com/apps/linux/install.sh), '
        'add your user to the nordvpn group, run nordvpn login, then restart this panel.'
    )


def run_nordvpn_cli(*args, timeout: int = 30):
    binary = get_nordvpn_cli_binary()
    if not binary:
        raise RuntimeError(_nordvpn_install_hint())
    creationflags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
    result = subprocess.run(
        [binary, *args],
        capture_output=True,
        text=True,
        encoding='utf-8',
        errors='replace',
        timeout=timeout,
        creationflags=creationflags,
    )
    output = '\n'.join(part.strip() for part in (result.stdout, result.stderr) if part and part.strip())
    if result.returncode != 0:
        raise RuntimeError(output or f'nordvpn exited with code {result.returncode}')
    return output


def _parse_nordvpn_status(output: str):
    lowered = (output or '').lower()
    if 'not logged in' in lowered or 'login required' in lowered or 'please log in' in lowered:
        return 'not_logged_in'
    if 'disconnected' in lowered:
        return 'disconnected'
    if 'connecting' in lowered:
        return 'connecting'
    if 'connected' in lowered:
        return 'connected'
    if 'daemon' in lowered or 'nordvpnd' in lowered:
        return 'service_unavailable'
    return 'unknown'


def _nordvpn_server_line(output: str) -> str:
    for line in (output or '').splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        low = stripped.lower()
        if low.startswith('server:') or low.startswith('country:') or low.startswith('your new ip:'):
            return stripped
    return ''


def get_nordvpn_status():
    installed = is_nordvpn_cli_installed()
    status = {
        'installed': installed,
        'running': False,
        'connected': False,
        'status': 'not_installed' if not installed else 'unknown',
        'server': '',
        'raw': '',
        'last_error': '' if installed else _nordvpn_install_hint(),
        'install_hint': _nordvpn_install_hint(),
    }
    if not installed:
        return status
    try:
        output = run_nordvpn_cli('status', timeout=15)
        parsed = _parse_nordvpn_status(output)
        status.update({
            'running': parsed in ('connected', 'connecting'),
            'connected': parsed == 'connected',
            'status': parsed,
            'server': _nordvpn_server_line(output),
            'raw': output,
            'last_error': '',
        })
    except Exception as e:
        status['last_error'] = str(e)
        lowered = str(e).lower()
        if 'not logged in' in lowered or 'login' in lowered:
            status['status'] = 'not_logged_in'
        elif 'daemon' in lowered or 'nordvpnd' in lowered or 'service' in lowered or 'permission' in lowered:
            status['status'] = 'service_unavailable'
        else:
            status['status'] = 'error'
    return status


def enable_nordvpn(country: str = '', city: str = ''):
    current = get_nordvpn_status()
    if not current.get('installed'):
        raise RuntimeError(current.get('install_hint') or _nordvpn_install_hint())
    if current.get('status') == 'not_logged_in':
        raise RuntimeError(
            'NordVPN is not logged in. Run `nordvpn login` on this host (browser flow), then retry.'
        )
    args = ['connect']
    country = (country or '').strip()
    city = (city or '').strip()
    if country and city:
        args.extend([country, city])
    elif country:
        args.append(country)
    run_nordvpn_cli(*args, timeout=45)
    time.sleep(1)
    return get_nordvpn_status()


def disable_nordvpn():
    current = get_nordvpn_status()
    if not current.get('installed'):
        raise RuntimeError(current.get('install_hint') or _nordvpn_install_hint())
    run_nordvpn_cli('disconnect', timeout=30)
    time.sleep(0.5)
    return get_nordvpn_status()


def get_tunnel_command_name(provider: str):
    if provider == 'cloudflare':
        return 'cloudflared.exe' if os.name == 'nt' else 'cloudflared'
    if provider == 'ngrok':
        return 'ngrok.exe' if os.name == 'nt' else 'ngrok'
    raise ValueError('Unsupported tunnel provider')


def get_tunnel_binary_path(provider: str):
    return os.path.join(BIN_DIR, get_tunnel_command_name(provider))


def find_tunnel_binary(provider: str):
    bundled = get_tunnel_binary_path(provider)
    if os.path.exists(bundled):
        return bundled
    return shutil.which(get_tunnel_command_name(provider))


def is_tunnel_installed(provider: str):
    return bool(find_tunnel_binary(provider))


def pid_is_running(pid):
    if not pid:
        return False
    try:
        os.kill(int(pid), 0)
        return True
    except OSError:
        return False
    except Exception:
        return False


def kill_pid(pid):
    if not pid:
        return
    if os.name == 'nt':
        subprocess.run(['taskkill', '/PID', str(pid), '/T', '/F'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if not pid_is_running(pid):
                return
            time.sleep(0.2)
    else:
        try:
            os.kill(int(pid), signal.SIGTERM)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if not pid_is_running(pid):
                    return
                time.sleep(0.2)
            if pid_is_running(pid):
                os.kill(int(pid), signal.SIGKILL)
        except ProcessLookupError:
            return


def wait_for_path_release(path, seconds: int = 5):
    if os.name != 'nt':
        return
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if not os.path.exists(path):
                return
            with open(path, 'ab'):
                return
        except PermissionError:
            time.sleep(0.25)


def find_running_tunnel_pids_in_proc(provider: str, binary_path: str = ''):
    proc_dir = '/proc'
    if os.name == 'nt' or not os.path.isdir(proc_dir):
        return []
    command_name = get_tunnel_command_name(provider).lower()
    command_base = command_name.replace('.exe', '')
    markers = ['tunnel', '--url'] if provider == 'cloudflare' else ['http']
    expected_binary = os.path.abspath(binary_path).lower() if binary_path else ''
    pids = []
    try:
        for entry in os.listdir(proc_dir):
            if not entry.isdigit():
                continue
            pid = int(entry)
            if pid == os.getpid():
                continue
            cmdline_path = os.path.join(proc_dir, entry, 'cmdline')
            try:
                with open(cmdline_path, 'rb') as f:
                    cmdline = f.read().replace(b'\x00', b' ').decode('utf-8', errors='replace').strip()
            except Exception:
                continue
            lowered = cmdline.lower()
            exe_path = ''
            try:
                exe_path = os.path.abspath(os.readlink(os.path.join(proc_dir, entry, 'exe'))).lower()
            except Exception:
                pass
            path_matches = bool(expected_binary and exe_path == expected_binary)
            command_matches = (command_name in lowered or command_base in lowered) and all(marker in lowered for marker in markers)
            if path_matches or command_matches:
                if pid_is_running(pid):
                    pids.append(pid)
    except Exception as e:
        logger.debug(f"Failed to scan /proc for running {provider} tunnel process: {e}")
    return pids


def find_running_tunnel_pids(provider: str, binary_path: str = ''):
    command_name = get_tunnel_command_name(provider).lower()
    process_name = command_name[:-4] if command_name.endswith('.exe') else command_name
    markers = ['tunnel', '--url'] if provider == 'cloudflare' else ['http']
    expected_binary = os.path.normcase(os.path.abspath(binary_path or get_tunnel_binary_path(provider)))
    pids = []
    try:
        if os.name == 'nt':
            ps_script = f"Get-CimInstance Win32_Process -Filter \"name='{command_name}'\" | Select-Object ProcessId,CommandLine,ExecutablePath | ConvertTo-Json -Compress"
            result = subprocess.run(['powershell', '-NoProfile', '-Command', ps_script], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=5)
            rows = []
            if result.returncode == 0 and result.stdout.strip():
                payload = json.loads(result.stdout)
                if payload:
                    rows = payload if isinstance(payload, list) else [payload]
            if not rows:
                ps_script = f"Get-Process -Name '{process_name}' -ErrorAction SilentlyContinue | Select-Object Id,Path | ConvertTo-Json -Compress"
                result = subprocess.run(['powershell', '-NoProfile', '-Command', ps_script], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=5)
                if result.returncode == 0 and result.stdout.strip():
                    payload = json.loads(result.stdout)
                    proc_rows = payload if isinstance(payload, list) else ([payload] if payload else [])
                    rows = [{'ProcessId': r.get('Id'), 'ExecutablePath': r.get('Path'), 'CommandLine': ''} for r in proc_rows]
            for row in rows:
                if not row:
                    continue
                pid = int(row.get('ProcessId') or 0)
                command_line = str(row.get('CommandLine') or '').lower()
                executable = os.path.normcase(os.path.abspath(str(row.get('ExecutablePath') or ''))) if row.get('ExecutablePath') else ''
                path_matches = bool(expected_binary and executable == expected_binary)
                command_matches = command_name in command_line and all(marker in command_line for marker in markers)
                if pid and pid != os.getpid() and (path_matches or command_matches) and pid_is_running(pid):
                    pids.append(pid)
            if not pids and os.path.exists(expected_binary):
                result = subprocess.run(['tasklist', '/FI', f'IMAGENAME eq {command_name}', '/FO', 'CSV', '/NH'], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=5)
                for line in result.stdout.splitlines():
                    match = re.match(r'"[^"]+","(\d+)"', line.strip())
                    if match:
                        pid = int(match.group(1))
                        if pid != os.getpid() and pid_is_running(pid):
                            pids.append(pid)
            return list(dict.fromkeys(pids))
        else:
            result = subprocess.run(
                ['ps', '-eo', 'pid=,args='],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=5,
            )
            lines = result.stdout.splitlines()

        for line in lines:
            text = line.strip()
            lowered = text.lower()
            if command_name not in lowered or not all(marker in lowered for marker in markers):
                continue
            pid_match = re.match(r'\s*(\d+)\s+', text)
            if pid_match:
                pid = int(pid_match.group(1))
                if pid != os.getpid() and pid_is_running(pid):
                    pids.append(pid)
    except Exception as e:
        logger.debug(f"Failed to scan running {provider} tunnel process: {e}")
    pids.extend(find_running_tunnel_pids_in_proc(provider, expected_binary))
    return list(dict.fromkeys(pids))


def find_running_tunnel_pid(provider: str):
    pids = find_running_tunnel_pids(provider)
    return pids[0] if pids else None


def kill_tunnel_processes(provider: str, binary_path: str = '', include_all_by_name: bool = False):
    pids = find_running_tunnel_pids(provider, binary_path)
    for pid in pids:
        kill_pid(pid)
    if os.name == 'nt' and include_all_by_name:
        subprocess.run(['taskkill', '/IM', get_tunnel_command_name(provider), '/T', '/F'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    return pids


def get_tunnel_download(provider: str):
    system = platform.system().lower()
    machine = platform.machine().lower()

    if provider == 'cloudflare':
        if system == 'windows':
            arch = 'amd64' if machine in ('amd64', 'x86_64') else '386'
            return f'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-{arch}.exe', 'exe'
        if system == 'darwin':
            arch = 'arm64' if 'arm' in machine else 'amd64'
            return f'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-{arch}.tgz', 'tgz'
        arch = 'arm64' if 'aarch64' in machine or 'arm64' in machine else 'amd64'
        return f'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-{arch}', 'bin'

    if provider == 'ngrok':
        if system == 'windows':
            os_part = 'windows'
            ext = 'zip'
        elif system == 'darwin':
            os_part = 'darwin'
            ext = 'zip'
        else:
            os_part = 'linux'
            ext = 'tgz'
        arch = 'arm64' if 'aarch64' in machine or 'arm64' in machine else 'amd64'
        return f'https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-{os_part}-{arch}.{ext}', ext

    raise ValueError('Unsupported tunnel provider')


def install_tunnel_binary(provider: str):
    if is_tunnel_installed(provider):
        return find_tunnel_binary(provider)

    os.makedirs(BIN_DIR, exist_ok=True)
    url, archive_type = get_tunnel_download(provider)
    target = get_tunnel_binary_path(provider)
    tmp_path = os.path.join(BIN_DIR, f'{provider}.download')
    logger.info(f"Downloading {provider} tunnel binary from {url}")
    urllib.request.urlretrieve(url, tmp_path)

    if archive_type in ('bin', 'exe'):
        shutil.move(tmp_path, target)
    elif archive_type == 'zip':
        with zipfile.ZipFile(tmp_path) as zf:
            member = next((m for m in zf.namelist() if os.path.basename(m).lower() == get_tunnel_command_name(provider).lower()), None)
            if not member:
                raise RuntimeError(f'{provider} binary not found in downloaded archive')
            with zf.open(member) as src, open(target, 'wb') as dst:
                shutil.copyfileobj(src, dst)
        os.remove(tmp_path)
    elif archive_type == 'tgz':
        with tarfile.open(tmp_path, 'r:gz') as tf:
            member = next((m for m in tf.getmembers() if os.path.basename(m.name).lower() == get_tunnel_command_name(provider).lower()), None)
            if not member:
                raise RuntimeError(f'{provider} binary not found in downloaded archive')
            extracted = tf.extractfile(member)
            if not extracted:
                raise RuntimeError(f'Cannot extract {provider} binary')
            with extracted as src, open(target, 'wb') as dst:
                shutil.copyfileobj(src, dst)
        os.remove(tmp_path)
    else:
        raise RuntimeError(f'Unsupported download format: {archive_type}')

    if os.name != 'nt':
        os.chmod(target, 0o755)
    return target


def get_tunnel_public_urls(provider: str, runtime: TunnelRuntime):
    urls = []
    if runtime.public_url:
        urls.append(runtime.public_url)
    state_url = load_tunnel_state().get(provider, {}).get('public_url')
    if state_url:
        urls.append(state_url)
    if provider == 'ngrok' and runtime.process and runtime.process.poll() is None:
        try:
            with urllib.request.urlopen('http://127.0.0.1:4040/api/tunnels', timeout=1) as resp:
                payload = json.loads(resp.read().decode('utf-8'))
            for item in payload.get('tunnels', []):
                public_url = item.get('public_url')
                if public_url and public_url.startswith('https://'):
                    urls.append(public_url)
        except Exception:
            pass
    return list(dict.fromkeys(urls))


def watch_tunnel_output(provider: str):
    runtime = TUNNEL_RUNTIMES[provider]
    process = runtime.process
    if not process or not process.stdout:
        return
    try:
        for line in iter(process.stdout.readline, ''):
            if not line:
                break
            text = line.strip()
            with TUNNEL_LOCK:
                runtime.output.append(text)
                runtime.output = runtime.output[-60:]
                match = TUNNEL_URL_RE.search(text)
                if match:
                    runtime.public_url = match.group(0).rstrip('.,')
                    update_tunnel_state(provider, public_url=runtime.public_url)
    except Exception as e:
        with TUNNEL_LOCK:
            runtime.last_error = str(e)


def build_tunnel_command(provider: str, binary: str, local_url: str, authtoken: str = ''):
    if provider == 'cloudflare':
        return [binary, 'tunnel', '--url', local_url, '--no-autoupdate']
    if provider == 'ngrok':
        cmd = [binary, 'http', local_url, '--log=stdout']
        return cmd
    raise ValueError('Unsupported tunnel provider')


def start_tunnel(provider: str, local_url: str, authtoken: str = ''):
    binary = find_tunnel_binary(provider)
    if not binary:
        raise RuntimeError(f'{provider} is not installed')

    runtime = TUNNEL_RUNTIMES[provider]
    with TUNNEL_LOCK:
        if runtime.process and runtime.process.poll() is None:
            return runtime
        runtime.public_url = ''
        runtime.last_error = ''
        runtime.output = []
        runtime.started_at = datetime.now().isoformat()

        creationflags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        env = os.environ.copy()
        if provider == 'ngrok' and authtoken:
            env['NGROK_AUTHTOKEN'] = authtoken

        runtime.process = subprocess.Popen(
            build_tunnel_command(provider, binary, local_url, authtoken),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding='utf-8',
            errors='replace',
            cwd=application_path,
            env=env,
            creationflags=creationflags,
        )
        runtime.pid = runtime.process.pid
        update_tunnel_state(
            provider,
            pid=runtime.pid,
            public_url='',
            started_at=runtime.started_at,
            binary=os.path.abspath(binary),
        )

    threading.Thread(target=watch_tunnel_output, args=(provider,), daemon=True).start()
    return runtime


def stop_tunnel(provider: str):
    runtime = TUNNEL_RUNTIMES[provider]
    process = runtime.process
    state = load_tunnel_state().get(provider, {})
    pids_to_stop = []
    if process and process.poll() is None:
        pids_to_stop.append(process.pid)
        try:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        except Exception as e:
            with TUNNEL_LOCK:
                runtime.last_error = str(e)
            raise
    if state.get('pid') and pid_is_running(state.get('pid')):
        pids_to_stop.append(state.get('pid'))
    pids_to_stop.extend(find_running_tunnel_pids(provider, state.get('binary') or get_tunnel_binary_path(provider)))
    for pid in dict.fromkeys(pids_to_stop):
        if pid_is_running(pid):
            kill_pid(pid)

    with TUNNEL_LOCK:
        runtime.process = None
        runtime.pid = None
        runtime.public_url = ''
        runtime.started_at = None
        runtime.last_error = ''
    clear_tunnel_state(provider)
    return runtime


def delete_tunnel_binary(provider: str):
    stop_tunnel(provider)
    bundled = get_tunnel_binary_path(provider)
    if os.path.exists(bundled):
        wait_for_path_release(bundled, seconds=8)
        try:
            os.remove(bundled)
        except PermissionError:
            killed = kill_tunnel_processes(provider, bundled, include_all_by_name=True)
            if killed:
                wait_for_path_release(bundled, seconds=8)
            try:
                os.remove(bundled)
            except PermissionError:
                raise RuntimeError('Cannot delete tunnel binary because Windows still keeps it locked. All detected cloudflared/ngrok processes were stopped; close any antivirus scan, terminal, or external process using the file and try again.')
    elif shutil.which(get_tunnel_command_name(provider)):
        raise RuntimeError('This tunnel binary is installed system-wide. Remove it from PATH manually or use the panel-managed installation.')

    tmp_path = os.path.join(BIN_DIR, f'{provider}.download')
    if os.path.exists(tmp_path):
        os.remove(tmp_path)

    runtime = TUNNEL_RUNTIMES[provider]
    with TUNNEL_LOCK:
        runtime.output = []
    clear_tunnel_state(provider)
    return runtime


def get_tunnel_status(provider: str):
    runtime = TUNNEL_RUNTIMES[provider]
    state = load_tunnel_state().get(provider, {})
    running = bool(runtime.process and runtime.process.poll() is None)
    if not running and state.get('pid'):
        running = pid_is_running(state.get('pid'))
        if running:
            runtime.pid = state.get('pid')
            runtime.started_at = runtime.started_at or state.get('started_at')
            runtime.public_url = runtime.public_url or state.get('public_url', '')
        else:
            clear_tunnel_state(provider)
            state = {}
    if not running and is_tunnel_installed(provider):
        found_pid = find_running_tunnel_pid(provider)
        if found_pid:
            running = True
            runtime.pid = found_pid
            runtime.started_at = runtime.started_at or datetime.now().isoformat()
            update_tunnel_state(
                provider,
                pid=found_pid,
                public_url=runtime.public_url,
                started_at=runtime.started_at,
                binary=os.path.abspath(find_tunnel_binary(provider) or ''),
            )
            state = load_tunnel_state().get(provider, {})
    if runtime.process and not running and not runtime.last_error and runtime.output:
        runtime.last_error = runtime.output[-1]
    urls = get_tunnel_public_urls(provider, runtime)
    return {
        'installed': is_tunnel_installed(provider),
        'running': running,
        'public_url': urls[0] if urls else '',
        'public_urls': urls,
        'last_error': runtime.last_error,
        'started_at': runtime.started_at or state.get('started_at'),
    }


async def wait_for_tunnel_url(provider: str, seconds: int = 20):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        status = get_tunnel_status(provider)
        if status.get('public_url') or not status.get('running'):
            return status
        await asyncio.sleep(0.5)
    return get_tunnel_status(provider)


BASE_PROTOCOLS = ['awg', 'awg2', 'awg3', 'awg_legacy', 'xray', 'telemt', 'mtproxy', 'hysteria', 'naiveproxy', 'mieru', 'dns', 'wireguard', 'socks5', 'adguard', 'nginx']
MULTI_INSTANCE_PROTOCOLS = {'awg', 'awg2', 'awg3', 'awg_legacy', 'xray', 'telemt', 'mtproxy', 'hysteria', 'socks5'}
NON_DOCKER_PROTOCOLS = frozenset({'mieru'})


def protocol_base(protocol: str) -> str:
    return str(protocol or 'awg').split('__', 1)[0]


def protocol_instance(protocol: str) -> int:
    parts = str(protocol or '').split('__', 1)
    if len(parts) == 2:
        try:
            return max(1, int(parts[1]))
        except ValueError:
            return 1
    return 1


def protocol_key(base: str, instance: int = 1) -> str:
    base = protocol_base(base)
    return base if int(instance or 1) <= 1 else f'{base}__{int(instance)}'


def next_protocol_key(protocols: dict, base: str) -> str:
    base = protocol_base(base)
    used = {protocol_instance(k) for k in (protocols or {}).keys() if protocol_base(k) == base}
    idx = 1
    while idx in used:
        idx += 1
    return protocol_key(base, idx)


def protocol_display_name(protocol: str) -> str:
    base = protocol_base(protocol)
    idx = protocol_instance(protocol)
    names = {
        'awg': 'AmneziaWG',
        'awg2': 'AmneziaWG 2.0',
        'awg3': 'AmneziaWG 3.1',
        'awg_legacy': 'AmneziaWG Legacy',
        'xray': 'Xray',
        'telemt': 'Telemt',
        'mtproxy': 'MTProxy',
        'hysteria': 'Hysteria 2',
        'naiveproxy': 'NaiveProxy',
        'mieru': 'Mieru',
        'dns': 'AmneziaDNS',
        'wireguard': 'WireGuard',
        'socks5': 'SOCKS5',
        'adguard': 'AdGuard Home',
        'nginx': 'NGINX',
    }
    name = names.get(base, base)
    return name if idx <= 1 else f'{name} #{idx}'


def protocol_container_name(protocol: str) -> Optional[str]:
    base = protocol_base(protocol)
    idx = protocol_instance(protocol)
    base_names = {
        'awg': 'amnezia-awg',
        'awg2': 'amnezia-awg2',
        'awg3': 'amnezia-awg3',
        'awg_legacy': 'amnezia-awg-legacy',
        'xray': 'amnezia-xray',
        'telemt': 'telemt',
        'mtproxy': 'mtproxy',
        'hysteria': 'amnezia-hysteria',
        'naiveproxy': 'amnezia-naiveproxy',
        'mieru': 'mita',
        'dns': 'amnezia-dns',
        'wireguard': 'amnezia-wireguard',
        'socks5': 'amnezia-socks5proxy',
        'adguard': 'amnezia-adguard',
        'nginx': 'amnezia-nginx',
    }
    name = base_names.get(base)
    if not name:
        return None
    return name if idx <= 1 else f'{name}-{idx}'


def is_valid_protocol(protocol: str) -> bool:
    return protocol_base(protocol) in BASE_PROTOCOLS


def get_protocol_manager(ssh, protocol: str):
    base = protocol_base(protocol)
    if base == 'xray':
        from managers.xray_manager import XrayManager
        return XrayManager(ssh, protocol)
    elif base == 'telemt':
        from managers.telemt_manager import TelemtManager
        return TelemtManager(ssh, protocol)
    elif base == 'mtproxy':
        from managers.mtproxy_manager import MtproxyManager
        return MtproxyManager(ssh, protocol)
    elif base == 'dns':
        from managers.dns_manager import DNSManager
        return DNSManager(ssh)
    elif base == 'wireguard':
        from managers.wireguard_manager import WireGuardManager
        return WireGuardManager(ssh)
    elif base == 'socks5':
        from managers.socks5_manager import Socks5Manager
        return Socks5Manager(ssh, protocol)
    elif base == 'adguard':
        from managers.adguard_manager import AdguardManager
        return AdguardManager(ssh)
    elif base == 'nginx':
        from managers.nginx_manager import NginxManager
        return NginxManager(ssh, protocol)
    elif base == 'hysteria':
        from managers.hysteria_manager import HysteriaManager
        return HysteriaManager(ssh, protocol)
    elif base == 'naiveproxy':
        from managers.naiveproxy_manager import NaiveProxyManager
        return NaiveProxyManager(ssh, protocol)
    elif base == 'mieru':
        from managers.mieru_manager import MieruManager
        return MieruManager(ssh, protocol)
    from managers.awg_manager import AWGManager
    return AWGManager(ssh)



def ensure_docker_installed(ssh):
    """Ensure Docker is installed and running before installing any protocol/service."""
    out, _, code = ssh.run_command("docker --version 2>/dev/null")
    if code == 0 and out.strip():
        status, _, _ = ssh.run_command("systemctl is-active docker 2>/dev/null || service docker status 2>/dev/null")
        if 'active' in status or 'running' in status.lower():
            return 'Docker already installed'
        ssh.run_sudo_command("systemctl enable --now docker 2>/dev/null || service docker start 2>/dev/null || true", timeout=60)
        status, _, _ = ssh.run_command("systemctl is-active docker 2>/dev/null || service docker status 2>/dev/null")
        if 'active' in status or 'running' in status.lower():
            return 'Docker service started'

    script = r"""
set -e
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y docker.io
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y docker
elif command -v yum >/dev/null 2>&1; then
  yum install -y docker
elif command -v zypper >/dev/null 2>&1; then
  zypper --non-interactive refresh
  zypper --non-interactive install docker
elif command -v pacman >/dev/null 2>&1; then
  pacman -Sy --noconfirm --noprogressbar docker
else
  echo "Packet manager not found" >&2
  exit 1
fi
(systemctl enable --now docker || service docker start || true)
sleep 3
docker --version
"""
    out, err, code = ssh.run_sudo_script(script, timeout=300)
    if code != 0:
        raise RuntimeError(f"Failed to install Docker: {err or out}")
    status, _, _ = ssh.run_command("systemctl is-active docker 2>/dev/null || service docker status 2>/dev/null")
    if 'active' not in status and 'running' not in status.lower():
        raise RuntimeError("Docker installed but service is not running")
    return 'Docker installed successfully'


def _manager_call(manager, method, protocol, *args, **kwargs):
    """Unified call: WireGuard manager methods don't take protocol_type argument."""
    fn = getattr(manager, method)
    if isinstance(manager, WireGuardManager):
        # WireGuard signatures omit protocol and often omit port.
        if method in ('get_client_config', 'add_client') and len(args) >= 2:
            return fn(args[0], args[1])
        return fn(*args, **kwargs)
    return fn(protocol, *args, **kwargs)


# Protocols that own VPN clients (can list/link connections)
CLIENT_VPN_BASES = {'awg', 'awg2', 'awg3', 'awg_legacy', 'xray', 'telemt', 'wireguard', 'hysteria', 'naiveproxy', 'mieru', 'xui'}


def generate_vpn_link(config_text):
    b64 = base64.b64encode(config_text.strip().encode('utf-8')).decode('utf-8')
    return f"vpn://{b64}"


# ===================== API tokens =====================

API_TOKEN_PREFIX = 'awp_'  # "Amnezia Web Panel" — makes tokens visually distinct in logs / configs
API_TOKEN_TOUCH_INTERVAL = 300  # don't re-write data.json more than once per 5 min per token


def _hash_api_token(raw: str) -> str:
    """One-way hash of a raw token. We never store the original token — only the
    SHA-256 digest, plus a short prefix for the UI to identify rotations."""
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


def _generate_api_token() -> str:
    """Generate a fresh bearer token. ~256 bits of entropy with a recognizable
    'awp_' prefix so leaked tokens are obvious in source control / pastes."""
    return f"{API_TOKEN_PREFIX}{secrets.token_urlsafe(32)}"


def _resolve_api_token(data: dict, raw_token: str):
    """Match a raw bearer token against stored hashes. Returns the user record
    that owns the token, or None if the token is unknown / its owner is gone /
    its owner is no longer admin-or-support."""
    if not raw_token:
        return None
    token_hash = _hash_api_token(raw_token)
    entry = next(
        (t for t in data.get('api_tokens', []) if t.get('token_hash') == token_hash),
        None,
    )
    if not entry:
        return None
    user = next((u for u in data.get('users', []) if u['id'] == entry.get('user_id')), None)
    if not user:
        return None
    # Disabled or downgraded admins should not have a working token any more.
    if not user.get('enabled', True):
        return None
    if user.get('role') not in ('admin', 'support'):
        return None
    return (entry, user)


def _touch_api_token(token_entry: dict) -> bool:
    """Update last_used_at on a token entry, but only if enough time has passed
    since the previous touch — avoids hot-write loops under load. Returns True
    if the entry was updated and the caller should persist data."""
    now = datetime.now()
    last = token_entry.get('last_used_at')
    if last:
        try:
            prev = datetime.fromisoformat(last)
            if (now - prev).total_seconds() < API_TOKEN_TOUCH_INTERVAL:
                return False
        except Exception:
            pass
    token_entry['last_used_at'] = now.isoformat()
    return True


def _schedule_api_token_touch(token_id: str) -> None:
    """Persist API token last_used_at without blocking the request handler."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    loop.create_task(_persist_api_token_touch(token_id))


async def _persist_api_token_touch(token_id: str) -> None:
    try:
        async with DATA_LOCK:
            data = await load_data_async()
            entry = next(
                (t for t in data.get('api_tokens', []) if t.get('id') == token_id),
                None,
            )
            if not entry or not _touch_api_token(entry):
                return
            await asyncio.to_thread(
                update_api_token_last_used, token_id, entry['last_used_at']
            )
    except Exception as e:
        logger.warning(f"Failed to touch API token last_used_at: {e}")


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return f"{salt}${h.hex()}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        salt, h = password_hash.split('$', 1)
        new_h = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return new_h.hex() == h
    except Exception:
        return False


async def perform_delete_user(data: dict, user_id: str):
    user = next((u for u in data['users'] if u['id'] == user_id), None)
    if not user:
        return False
    # Remove user's connections from servers / 3x-ui
    user_conns = [c for c in data.get('user_connections', []) if c['user_id'] == user_id]
    for uc in user_conns:
        try:
            if protocol_base(uc.get('protocol', '')) == 'xui':
                from managers.xui_api import xui_delete_client
                await xui_delete_client(
                    data.get('settings', {}),
                    uc['client_id'],
                    panel_id=uc.get('xui_panel_id') or None,
                )
                continue
            sid = uc['server_id']
            if sid < len(data['servers']):
                server = data['servers'][sid]
                ssh = get_ssh(server)
                ssh.connect()
                manager = get_protocol_manager(ssh, uc['protocol'])
                _manager_call(manager, 'remove_client', uc['protocol'], uc['client_id'])
                ssh.disconnect()
        except Exception as e:
            logger.warning(f"Failed to remove connection {uc['client_id']} during user delete: {e}")
    data['user_connections'] = [c for c in data.get('user_connections', []) if c['user_id'] != user_id]
    data['users'] = [u for u in data['users'] if u['id'] != user_id]
    return True


async def perform_toggle_user(data: dict, user_id: str, enable: bool) -> bool:
    """Enable or disable a user and propagate the change to all their VPN connections."""
    user = next((u for u in data['users'] if u['id'] == user_id), None)
    if not user:
        return False

    user['enabled'] = enable

    user_conns = [c for c in data.get('user_connections', []) if c['user_id'] == user_id]
    for uc in user_conns:
        try:
            if protocol_base(uc.get('protocol', '')) == 'xui':
                from managers.xui_api import xui_toggle_client
                await xui_toggle_client(
                    data.get('settings', {}),
                    uc['client_id'],
                    enable,
                    panel_id=uc.get('xui_panel_id') or None,
                )
                continue
            sid = uc['server_id']
            if sid >= len(data['servers']):
                continue
            server = data['servers'][sid]
            ssh = get_ssh(server)
            await asyncio.to_thread(ssh.connect)
            manager = get_protocol_manager(ssh, uc['protocol'])
            await asyncio.to_thread(
                _manager_call, manager, 'toggle_client', uc['protocol'], uc['client_id'], enable
            )
            await asyncio.to_thread(ssh.disconnect)
        except Exception as e:
            logger.warning(f"Failed to toggle connection {uc['client_id']} during user toggle: {e}")

    return True


def resolve_protocol_on_server(server: dict, protocol: str) -> Optional[str]:
    """Pick an installed protocol key on server matching the requested protocol/base."""
    protocols = server.get('protocols') or {}
    if protocol in protocols and protocols[protocol].get('installed'):
        return protocol
    base = protocol_base(protocol)
    candidates = [
        key for key, info in protocols.items()
        if protocol_base(key) == base and info.get('installed')
    ]
    if not candidates:
        return None
    return sorted(candidates, key=protocol_instance)[0]


def _client_display_name(client: dict) -> str:
    user_data = client.get('userData') or {}
    return (
        user_data.get('clientName')
        or client.get('clientName')
        or client.get('clientId')
        or 'Connection'
    )


def _create_remote_client(manager, protocol: str, server: dict, name: str, source_client: Optional[dict] = None):
    proto_info = server.get('protocols', {}).get(protocol, {})
    port = proto_info.get('port', '55424')
    base = protocol_base(protocol)
    if base == 'telemt':
        user_data = (source_client or {}).get('userData') or {}
        connect_host = get_server_connect_host(server, protocol)
        return manager.add_client(
            protocol, name, connect_host, port,
            telemt_quota=user_data.get('quota'),
            telemt_expiry=user_data.get('expiry'),
            secret=user_data.get('token'),
            user_ad_tag=user_data.get('user_ad_tag'),
            max_tcp_conns=user_data.get('max_tcp_conns'),
        )
    connect_host = get_server_connect_host(server, protocol)
    if base == 'wireguard':
        return manager.add_client(name, connect_host)
    return manager.add_client(protocol, name, connect_host, port)


def _move_connections_sync(
    source_server_id: int,
    target_server_id: int,
    protocol: str,
    client_ids: List[str],
    target_protocol: Optional[str] = None,
    delete_source: bool = True,
) -> dict:
    data = load_data()
    if source_server_id >= len(data['servers']) or target_server_id >= len(data['servers']):
        raise ValueError('Server not found')
    if source_server_id == target_server_id:
        raise ValueError('Source and target server must be different')
    if protocol_base(protocol) == 'xui':
        raise ValueError('Moving 3x-ui connections between servers is not supported')

    source_server = data['servers'][source_server_id]
    target_server = data['servers'][target_server_id]
    resolved_target_protocol = target_protocol or resolve_protocol_on_server(target_server, protocol)
    if not resolved_target_protocol:
        raise ValueError(
            f'Target server does not have {protocol_display_name(protocol)} installed'
        )

    source_ssh = get_ssh(source_server)
    target_ssh = get_ssh(target_server)
    source_ssh.connect()
    target_ssh.connect()

    source_manager = get_protocol_manager(source_ssh, protocol)
    source_clients = _manager_call(source_manager, 'get_clients', protocol) or []
    clients_map = {c.get('clientId'): c for c in source_clients if c.get('clientId')}

    target_manager = get_protocol_manager(target_ssh, resolved_target_protocol)
    moved = []
    failed = []

    try:
        for client_id in client_ids:
            client = clients_map.get(client_id)
            if not client:
                failed.append({'client_id': client_id, 'error': 'Client not found on source server'})
                continue

            user_data = client.get('userData') or {}
            base = protocol_base(protocol)
            if user_data.get('externalClient') and not user_data.get('clientPrivateKey') and base in (
                'awg', 'awg2', 'awg3', 'awg_legacy', 'wireguard',
            ):
                failed.append({
                    'client_id': client_id,
                    'error': 'External/native client cannot be moved (no private key)',
                })
                continue

            name = _client_display_name(client)
            enabled = client.get('enabled', True)
            if user_data.get('enabled') is False:
                enabled = False

            try:
                created = _create_remote_client(
                    target_manager, resolved_target_protocol, target_server, name, client,
                )
                new_client_id = created.get('client_id')
                if not new_client_id:
                    failed.append({'client_id': client_id, 'error': 'Failed to create client on target server'})
                    continue

                if not enabled:
                    _manager_call(
                        target_manager, 'toggle_client',
                        resolved_target_protocol, new_client_id, False,
                    )

                user_conn = next(
                    (
                        uc for uc in data.get('user_connections', [])
                        if uc.get('client_id') == client_id
                        and uc.get('server_id') == source_server_id
                        and uc.get('protocol') == protocol
                    ),
                    None,
                )
                if user_conn:
                    user_conn['server_id'] = target_server_id
                    user_conn['client_id'] = new_client_id
                    user_conn['protocol'] = resolved_target_protocol
                    user_conn['name'] = name
                elif client.get('assigned_user_id'):
                    data.setdefault('user_connections', []).append({
                        'id': str(uuid.uuid4()),
                        'user_id': client['assigned_user_id'],
                        'server_id': target_server_id,
                        'protocol': resolved_target_protocol,
                        'client_id': new_client_id,
                        'name': name,
                        'created_at': datetime.now().isoformat(),
                    })

                if delete_source:
                    _manager_call(source_manager, 'remove_client', protocol, client_id)
                    data['user_connections'] = [
                        uc for uc in data.get('user_connections', [])
                        if not (
                            uc.get('client_id') == client_id
                            and uc.get('server_id') == source_server_id
                            and uc.get('protocol') == protocol
                        )
                    ]

                moved.append({
                    'client_id': client_id,
                    'new_client_id': new_client_id,
                    'name': name,
                })
            except Exception as exc:
                logger.exception('Failed to move client %s', client_id)
                failed.append({'client_id': client_id, 'error': str(exc)})
    finally:
        source_ssh.disconnect()
        target_ssh.disconnect()

    if moved:
        save_data(data)

    return {
        'status': 'success' if moved else 'error',
        'moved': moved,
        'failed': failed,
        'target_server_id': target_server_id,
        'target_protocol': resolved_target_protocol,
        'message': f'Moved {len(moved)} connection(s)' + (f', {len(failed)} failed' if failed else ''),
    }


async def perform_mass_operations(delete_uids: List[str] = None, toggle_uids: List[tuple] = None, create_conns: List[dict] = None):
    """
    Executes multiple SSH operations efficiently.
    Reloads data inside to ensure we don't overwrite other changes.
    """
    data = load_data()
    server_ops = {}

    def get_ops(sid):
        if sid not in server_ops:
            server_ops[sid] = {'delete': [], 'toggle': [], 'create': []}
        return server_ops[sid]

    if delete_uids:
        for uid in delete_uids:
            conns = [c for c in data.get('user_connections', []) if c['user_id'] == uid]
            for c in conns: get_ops(c['server_id'])['delete'].append(c)
    
    if toggle_uids:
        for uid, enabled in toggle_uids:
            conns = [c for c in data.get('user_connections', []) if c['user_id'] == uid]
            for c in conns: get_ops(c['server_id'])['toggle'].append((c, enabled))

    if create_conns:
        for req in create_conns: get_ops(req['server_id'])['create'].append(req)

    async def run_server_ops(srv_id, ops):
        # We re-load data inside to be absolutely sure about current state
        # but for performance we'll use the passed srv_id
        current_data = load_data()
        if srv_id >= len(current_data['servers']): return
        srv = current_data['servers'][srv_id]
        
        try:
            ssh = get_ssh(srv)
            await asyncio.to_thread(ssh.connect)
            
            # 1. Deletes
            for c in ops['delete']:
                manager = get_protocol_manager(ssh, c['protocol'])
                await asyncio.to_thread(_manager_call, manager, 'remove_client', c['protocol'], c['client_id'])
                # Incremental delete from data
                async with DATA_LOCK:
                    current_data = load_data()
                    current_data['user_connections'] = [conn for conn in current_data['user_connections'] if conn['id'] != c['id']]
                    save_data(current_data)
            
            # 2. Toggles
            for c, enabled in ops['toggle']:
                manager = get_protocol_manager(ssh, c['protocol'])
                await asyncio.to_thread(_manager_call, manager, 'toggle_client', c['protocol'], c['client_id'], enabled)
                # Incremental toggle in data
                async with DATA_LOCK:
                    current_data = load_data()
                    # We also need to update user status if it was a user toggle
                    # Wait, mass ops caller usually handles user enabled status. 
                    # Here we just toggle the actual wireguard peer.
                    save_data(current_data)
            
            # 3. Creates
            for c_req in ops['create']:
                proto_info = srv.get('protocols', {}).get(c_req['protocol'], {})
                port = proto_info.get('port', '55424')
                manager = get_protocol_manager(ssh, c_req['protocol'])
                
                if c_req['protocol'] == 'wireguard':
                    res = await asyncio.to_thread(manager.add_client, c_req['name'], get_server_connect_host(srv, 'wireguard'))
                else:
                    res = await asyncio.to_thread(_manager_call, manager, 'add_client', c_req['protocol'], c_req['name'], get_server_connect_host(srv, c_req['protocol']), port)
                
                if res.get('client_id'):
                    new_conn = {
                        'id': str(uuid.uuid4()),
                        'user_id': c_req['user_id'],
                        'server_id': srv_id,
                        'protocol': c_req['protocol'],
                        'client_id': res['client_id'],
                        'name': c_req['name'],
                        'created_at': datetime.now().isoformat(),
                    }
                    async with DATA_LOCK:
                        current_data = load_data()
                        current_data['user_connections'].append(new_conn)
                        save_data(current_data)
            
            await asyncio.to_thread(ssh.disconnect)
        except Exception as e:
            logger.error(f"Mass ops failed for server {srv_id}: {e}")

    # Run all servers in parallel
    tasks = [run_server_ops(sid, ops) for sid, ops in server_ops.items()]
    if tasks:
        await asyncio.gather(*tasks)

    # 4. Final user-level cleanup (delete/toggle users metadata)
    async with DATA_LOCK:
        current_data = load_data()
        if delete_uids:
            current_data['users'] = [u for u in current_data['users'] if u['id'] not in delete_uids]
            current_data['user_connections'] = [c for c in current_data.get('user_connections', []) if c['user_id'] not in delete_uids]
        if toggle_uids:
            for uid, enabled in toggle_uids:
                user = next((u for u in current_data['users'] if u['id'] == uid), None)
                if user: user['enabled'] = enabled
        save_data(current_data)

    return True


async def sync_users_with_remnawave(data: dict):
    settings = data.get('settings', {}).get('sync', {})
    if not settings.get('remnawave_sync_users'):
        return 0, "Synchronization is disabled in settings"
    
    url = settings.get('remnawave_url')
    api_key = settings.get('remnawave_api_key')
    if not url or not api_key:
        return 0, "Remnawave URL or API Key not configured"
    
    api_url = url.rstrip('/') + '/api/users'
    headers = {"Authorization": f"Bearer {api_key}"}
    
    try:
        rw_users = []
        async with httpx.AsyncClient(timeout=30.0) as client:
            page_size = 50  # Use a smaller page size that is more likely to be accepted
            current_start = 0
            while True:
                resp = await client.get(f"{api_url}?size={page_size}&start={current_start}", headers=headers)
                if resp.status_code != 200:
                    return 0, f"Remnawave API error: {resp.status_code} {resp.text}"
                
                page_data = resp.json()
                response_obj = page_data.get('response', {})
                page_users = response_obj.get('users', [])
                total_count = response_obj.get('total', 0)
                
                if not page_users:
                    break
                
                rw_users.extend(page_users)
                logger.info(f"Fetched {len(rw_users)} / {total_count} users from Remnawave...")
                
                if len(rw_users) >= total_count or len(page_users) == 0:
                    break
                    
                current_start += len(page_users)

            rw_uuids = {u['uuid'] for u in rw_users}
            
            # 1. Handle deletion (users that have remnawave_uuid but are no longer in Remnawave)
            to_delete_ids = []
            for u in data['users']:
                if u.get('remnawave_uuid') and u['remnawave_uuid'] not in rw_uuids:
                    to_delete_ids.append(u['id'])
            
            if to_delete_ids:
                logger.info(f"Removing {len(to_delete_ids)} users deleted in Remnawave")
                await perform_mass_operations(delete_uids=to_delete_ids)

            # 2. Sync / Create users
            synced_count = 0
            to_toggle = [] # list of (user_id, enabled)
            to_create_conns = [] # list of dicts
            
            for rw_u in rw_users:
                # We reload data in each loop step to handle concurrency
                data = load_data()
                local_u = next((u for u in data['users'] if u.get('remnawave_uuid') == rw_u['uuid']), None)
                if not local_u:
                    local_u = next((u for u in data['users'] if u['username'] == rw_u['username']), None)

                is_active = (rw_u.get('status') == 'ACTIVE')
                
                if local_u:
                    local_u['username'] = rw_u['username']
                    local_u['telegramId'] = rw_u.get('telegramId')
                    local_u['email'] = rw_u.get('email')
                    local_u['description'] = rw_u.get('description')
                    local_u['remnawave_uuid'] = rw_u['uuid']
                    
                    if local_u.get('enabled', True) != is_active:
                        to_toggle.append((local_u['id'], is_active))
                    
                    # Save metadata immediately
                    async with DATA_LOCK:
                        current = load_data()
                        # Update index
                        idx = next((i for i, u in enumerate(current['users']) if u['id'] == local_u['id']), -1)
                        if idx != -1:
                            current['users'][idx] = local_u
                            save_data(current)
                    
                    synced_count += 1
                else:
                    new_id = str(uuid.uuid4())
                    new_user = {
                        'id': new_id,
                        'username': rw_u['username'],
                        'password_hash': '', 
                        'role': 'user',
                        'telegramId': rw_u.get('telegramId'),
                        'email': rw_u.get('email'),
                        'description': rw_u.get('description'),
                        'enabled': is_active,
                        'created_at': datetime.now().isoformat(),
                        'remnawave_uuid': rw_u['uuid'],
                        'xui_email': None,
                        'share_enabled': False,
                        'share_token': secrets.token_urlsafe(16),
                        'share_password_hash': None,
                    }
                    async with DATA_LOCK:
                        current = load_data()
                        current['users'].append(new_user)
                        save_data(current)
                    
                    if settings.get('remnawave_create_conns'):
                        sid = settings.get('remnawave_server_id')
                        if sid is not None:
                            to_create_conns.append({
                                'user_id': new_id,
                                'server_id': sid,
                                'protocol': settings.get('remnawave_protocol', 'awg'),
                                'name': f"{rw_u['username']}_vpn"
                            })
                    synced_count += 1
            
            # Execute all collected mass operations
            if to_toggle or to_create_conns:
                logger.info(f"Executing mass ops for Remnawave sync: toggle={len(to_toggle)}, create={len(to_create_conns)}")
                await perform_mass_operations(toggle_uids=to_toggle, create_conns=to_create_conns)
            
            return synced_count, "Successfully synchronized with Remnawave"
            
    except Exception as e:
        logger.exception("Synchronization error")
        return 0, f"Error: {str(e)}"


def _xui_sanitize_username(email: str) -> str:
    raw = (email or '').strip()
    if not raw:
        return ''
    cleaned = re.sub(r'[^\w.\-@]+', '_', raw, flags=re.UNICODE)
    return cleaned[:64] or raw[:64]


def _xui_parse_clients_from_inbounds(inbounds) -> list:
    """Extract unique clients from classic 3x-ui inbounds list payload."""
    clients_by_email = {}
    if not isinstance(inbounds, list):
        return []
    for inbound in inbounds:
        settings = inbound.get('settings') if isinstance(inbound, dict) else None
        if isinstance(settings, str):
            try:
                settings = json.loads(settings)
            except Exception:
                settings = {}
        if not isinstance(settings, dict):
            continue
        for client in settings.get('clients') or []:
            if not isinstance(client, dict):
                continue
            email = (client.get('email') or '').strip()
            if not email:
                continue
            prev = clients_by_email.get(email)
            if prev and prev.get('enable') and not client.get('enable', True):
                continue
            clients_by_email[email] = client
    return list(clients_by_email.values())


async def _xui_fetch_clients(client: httpx.AsyncClient, base_url: str, headers: dict) -> list:
    """Fetch clients from 3x-ui, supporting new and legacy API shapes."""
    base = base_url.rstrip('/')
    for path in ('/panel/api/clients/list', '/panel/api/inbounds/list'):
        try:
            resp = await client.get(base + path, headers=headers)
        except Exception:
            continue
        if resp.status_code != 200:
            continue
        try:
            payload = resp.json()
        except Exception:
            continue
        if not payload.get('success', True) and payload.get('success') is False:
            continue
        obj = payload.get('obj', payload.get('data'))
        if path.endswith('/clients/list') and isinstance(obj, list):
            by_email = {}
            for c in obj:
                if not isinstance(c, dict):
                    continue
                email = (c.get('email') or '').strip()
                if email:
                    by_email[email] = c
            if by_email:
                return list(by_email.values())
        if path.endswith('/inbounds/list'):
            clients = _xui_parse_clients_from_inbounds(obj if isinstance(obj, list) else [])
            if clients:
                return clients
    for path in ('/panel/api/inbounds/list', '/panel/inbound/list'):
        try:
            resp = await client.post(base + path, headers=headers)
        except Exception:
            continue
        if resp.status_code != 200:
            continue
        try:
            payload = resp.json()
        except Exception:
            continue
        obj = payload.get('obj', payload.get('data'))
        clients = _xui_parse_clients_from_inbounds(obj if isinstance(obj, list) else [])
        if clients:
            return clients
    return []


async def sync_users_with_xui(data: dict, *, force: bool = False):
    """Import / update panel users from an existing 3x-ui instance."""
    from managers.xui_servers import ensure_xui_servers, list_xui_servers
    panel_settings = data.setdefault('settings', {})
    ensure_xui_servers(panel_settings)
    sync_settings = panel_settings.get('sync') or {}

    if not force and not sync_settings.get('xui_sync_users'):
        servers_with_sync = [s for s in list_xui_servers(panel_settings) if s.get('sync_users')]
        if not servers_with_sync:
            return 0, "3x-ui synchronization is disabled in settings"

    url = (sync_settings.get('xui_url') or '').strip()
    if not url:
        primary = next((s for s in list_xui_servers(panel_settings) if s.get('enabled')), None)
        if not primary:
            primary = next(iter(list_xui_servers(panel_settings)), None)
        url = (primary or {}).get('url') or ''
    if not url:
        return 0, "3x-ui URL not configured"

    api_token = (sync_settings.get('xui_api_token') or '').strip()
    username = (sync_settings.get('xui_username') or '').strip()
    password = sync_settings.get('xui_password') or ''
    if not api_token and (not username or not password):
        primary = next((s for s in list_xui_servers(panel_settings) if (s.get('url') or '').strip() == url), None)
        if primary:
            api_token = (primary.get('api_token') or '').strip()
            username = (primary.get('username') or '').strip()
            password = primary.get('password') or ''

    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            headers = {'Accept': 'application/json'}
            if api_token:
                headers['Authorization'] = f'Bearer {api_token}'
            else:
                if not username or not password:
                    return 0, "Provide 3x-ui API token or username/password"
                login_resp = await client.post(
                    url.rstrip('/') + '/login',
                    json={'username': username, 'password': password},
                    headers=headers,
                )
                if login_resp.status_code != 200:
                    return 0, f"3x-ui login failed: {login_resp.status_code} {login_resp.text[:200]}"
                try:
                    login_body = login_resp.json()
                except Exception:
                    login_body = {}
                if login_body.get('success') is False:
                    return 0, f"3x-ui login failed: {login_body.get('msg', 'unknown error')}"

            xui_clients = await _xui_fetch_clients(client, url, headers)
            if not xui_clients:
                return 0, "No clients found in 3x-ui (check URL/credentials/API path)"

            xui_emails = {(c.get('email') or '').strip() for c in xui_clients if (c.get('email') or '').strip()}

            to_delete_ids = []
            for u in data['users']:
                email = (u.get('xui_email') or '').strip()
                if email and email not in xui_emails:
                    to_delete_ids.append(u['id'])
            if to_delete_ids:
                logger.info(f"Removing {len(to_delete_ids)} users deleted in 3x-ui")
                await perform_mass_operations(delete_uids=to_delete_ids)

            synced_count = 0
            to_toggle = []
            to_create_conns = []

            for xc in xui_clients:
                email = (xc.get('email') or '').strip()
                if not email:
                    continue

                data = load_data()
                local_u = next((u for u in data['users'] if (u.get('xui_email') or '') == email), None)
                uname = _xui_sanitize_username(email)
                if not local_u and uname:
                    local_u = next((u for u in data['users'] if u['username'] == uname), None)

                is_active = bool(xc.get('enable', True))
                tg_id = xc.get('tgId') or xc.get('telegramId') or None
                if tg_id is not None:
                    tg_id = str(tg_id) if str(tg_id).strip() else None

                traffic_limit = int(xc.get('totalGB') or 0)
                expiry_ms = int(xc.get('expiryTime') or 0)
                expiration_date = None
                if expiry_ms > 0:
                    try:
                        expiration_date = datetime.fromtimestamp(expiry_ms / 1000.0).isoformat()
                    except Exception:
                        expiration_date = None

                if local_u:
                    local_u['username'] = uname or local_u['username']
                    local_u['telegramId'] = tg_id
                    local_u['email'] = email if '@' in email else local_u.get('email')
                    local_u['description'] = xc.get('comment') or local_u.get('description')
                    local_u['xui_email'] = email
                    local_u['traffic_limit'] = traffic_limit
                    local_u['expiration_date'] = expiration_date
                    if local_u.get('enabled', True) != is_active:
                        to_toggle.append((local_u['id'], is_active))
                    async with DATA_LOCK:
                        current = load_data()
                        idx = next((i for i, u in enumerate(current['users']) if u['id'] == local_u['id']), -1)
                        if idx != -1:
                            current['users'][idx] = local_u
                            save_data(current)
                    synced_count += 1
                else:
                    new_id = str(uuid.uuid4())
                    final_name = uname or f"xui_{new_id[:8]}"
                    existing_names = {u['username'] for u in data['users']}
                    if final_name in existing_names:
                        final_name = f"{final_name}_{new_id[:6]}"
                    new_user = {
                        'id': new_id,
                        'username': final_name,
                        'password_hash': '',
                        'role': 'user',
                        'telegramId': tg_id,
                        'email': email if '@' in email else None,
                        'description': xc.get('comment'),
                        'enabled': is_active,
                        'created_at': datetime.now().isoformat(),
                        'remnawave_uuid': None,
                        'xui_email': email,
                        'traffic_limit': traffic_limit,
                        'traffic_used': 0,
                        'traffic_total': 0,
                        'traffic_reset_strategy': 'never',
                        'last_reset_at': datetime.now().isoformat(),
                        'expiration_date': expiration_date,
                        'expire_after_first_use': False,
                        'expiration_days': 0,
                        'share_enabled': False,
                        'share_token': secrets.token_urlsafe(16),
                        'share_password_hash': None,
                    }
                    async with DATA_LOCK:
                        current = load_data()
                        current['users'].append(new_user)
                        save_data(current)

                    if sync_settings.get('xui_create_conns'):
                        sid = sync_settings.get('xui_server_id')
                        if sid is not None:
                            to_create_conns.append({
                                'user_id': new_id,
                                'server_id': sid,
                                'protocol': sync_settings.get('xui_protocol', 'xray'),
                                'name': f"{final_name}_vpn",
                            })
                    synced_count += 1

            if to_toggle or to_create_conns:
                logger.info(
                    f"Executing mass ops for 3x-ui sync: toggle={len(to_toggle)}, create={len(to_create_conns)}"
                )
                await perform_mass_operations(toggle_uids=to_toggle, create_conns=to_create_conns)

            return synced_count, "Successfully synchronized with 3x-ui"

    except Exception as e:
        logger.exception("3x-ui synchronization error")
        return 0, f"Error: {str(e)}"


# ======================== Pydantic Models ========================

class LoginRequest(BaseModel):
    username: str
    password: str
    captcha: Optional[str] = None


class AddServerRequest(BaseModel):
    host: str = ''
    ssh_port: int = 22
    username: str = ''
    password: str = ''
    private_key: str = ''
    name: str = ''
    ssl_domain: str = ''
    ssl_email: str = ''
    connect_domain: str = ''


class EditServerRequest(BaseModel):
    name: str = ''
    host: str = ''
    ssh_port: int = 22
    username: str = ''
    # Optional[str] = None lets the client distinguish "leave field as is"
    # (omit / null) from "explicitly clear" (empty string). Both credential
    # fields can be omitted to keep current auth unchanged.
    password: Optional[str] = None
    private_key: Optional[str] = None
    ssl_domain: Optional[str] = None
    ssl_email: Optional[str] = None
    connect_domain: Optional[str] = None


class ConnectDomainRequest(BaseModel):
    connect_domain: str = ''
    protocol: Optional[str] = None


class ReorderServersRequest(BaseModel):
    # `order[i]` is the *old* server index now at position `i` in the new layout.
    order: List[int]


class InstallProtocolRequest(BaseModel):
    protocol: str = 'awg'
    port: str = '55424'
    install_another: Optional[bool] = False
    tls_emulation: Optional[bool] = None
    tls_domain: Optional[str] = None
    max_connections: Optional[int] = None
    # MTProxy
    mtproxy_secret: Optional[str] = None
    mtproxy_ad_tag: Optional[str] = None
    # SOCKS5
    socks5_username: Optional[str] = None
    socks5_password: Optional[str] = None
    # AdGuard Home
    adguard_mode: Optional[str] = None  # 'replace' or 'sidebyside'
    adguard_web_port: Optional[int] = None
    adguard_expose_web: Optional[bool] = None
    adguard_dot_port: Optional[int] = None
    adguard_doh_port: Optional[int] = None
    adguard_expose_dns: Optional[bool] = None
    adguard_expose_dot: Optional[bool] = None
    adguard_expose_doh: Optional[bool] = None
    # NGINX
    nginx_domain: Optional[str] = None
    nginx_email: Optional[str] = None
    # Hysteria
    hysteria_domain: Optional[str] = None
    hysteria_email: Optional[str] = None
    # NaiveProxy
    naiveproxy_domain: Optional[str] = None
    naiveproxy_email: Optional[str] = None
    # Xray (VLESS + XHTTP + TLS)
    xray_domain: Optional[str] = None
    xray_email: Optional[str] = None
    xray_acme_method: Optional[str] = 'cloudflare'  # cloudflare | http
    xray_cf_token: Optional[str] = None


class Socks5SettingsRequest(BaseModel):
    protocol: str = 'socks5'
    port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None


class HysteriaSettingsRequest(BaseModel):
    protocol: str = 'hysteria'
    port: Optional[int] = None
    domain: Optional[str] = None
    email: Optional[str] = None
    renew_ssl: bool = False

class ProtocolRequest(BaseModel):
    protocol: str = 'awg'


class ContainerLogsRequest(BaseModel):
    protocol: str = 'awg'
    tail: Optional[int] = 200


class AddConnectionRequest(BaseModel):
    protocol: str = 'awg'
    name: str = 'Connection'
    user_id: Optional[str] = None
    telemt_quota: Optional[str] = None
    telemt_max_ips: Optional[int] = None
    telemt_expiry: Optional[str] = None
    telemt_secret: Optional[str] = None
    telemt_ad_tag: Optional[str] = None
    telemt_max_conns: Optional[int] = None
    xui_inbound_id: Optional[int] = None
    xui_panel_id: Optional[str] = None


class EditConnectionRequest(BaseModel):
    protocol: str = 'telemt'
    client_id: str = ''
    telemt_quota: Optional[str] = None
    telemt_max_ips: Optional[int] = None
    telemt_expiry: Optional[str] = None
    telemt_secret: Optional[str] = None
    telemt_ad_tag: Optional[str] = None
    telemt_max_conns: Optional[int] = None


class ConnectionActionRequest(BaseModel):
    protocol: str = 'awg'
    client_id: str = ''


class ToggleConnectionRequest(BaseModel):
    protocol: str = 'awg'
    client_id: str = ''
    enable: bool = True


class MoveConnectionsRequest(BaseModel):
    protocol: str = 'awg'
    target_server_id: int
    client_ids: List[str]
    target_protocol: Optional[str] = None
    delete_source: bool = True


class AddUserRequest(BaseModel):
    username: str
    password: str
    role: str = 'user'
    telegramId: Optional[str] = None
    email: Optional[str] = None
    description: Optional[str] = None
    traffic_limit: Optional[float] = 0
    traffic_reset_strategy: Optional[str] = 'never'
    server_id: Optional[int] = None
    protocol: Optional[str] = None
    connection_name: Optional[str] = None
    expiration_date: Optional[str] = None
    expire_after_first_use: bool = False
    expiration_days: int = 0
    telemt_quota: Optional[str] = None
    telemt_max_ips: Optional[int] = None
    telemt_expiry: Optional[str] = None
    telemt_secret: Optional[str] = None
    telemt_ad_tag: Optional[str] = None
    telemt_max_conns: Optional[int] = None



class ServerConfigSaveRequest(BaseModel):
    protocol: str
    config: str


class NginxSiteSaveRequest(BaseModel):
    protocol: str = 'nginx'
    html: str = ''


class BackupDownloadRequest(BaseModel):
    protocol: str
    filename: str


class AppearanceSettings(BaseModel):
    title: str = 'Amnezia'
    logo: str = '🛡'
    subtitle: str = 'Web Panel'


class SyncSettings(BaseModel):
    remnawave_url: str = ''
    remnawave_api_key: str = ''
    remnawave_sync: bool = False
    remnawave_sync_users: bool = False
    remnawave_create_conns: bool = False
    remnawave_server_id: int = 0
    remnawave_protocol: str = 'awg'
    xui_sync: bool = False
    xui_url: str = ''
    xui_username: str = ''
    xui_password: str = ''
    xui_api_token: str = ''
    xui_sync_users: bool = False
    xui_create_conns: bool = False
    xui_server_id: int = 0
    xui_protocol: str = 'xray'
    xui_inbound_id: int = 0
    xui_sub_url: str = ''


class XuiServerRequest(BaseModel):
    name: str = ''
    url: str = ''
    sub_url: str = ''
    api_token: str = ''
    username: str = ''
    password: str = ''
    default_inbound_id: int = 0
    enabled: bool = True
    sync_users: bool = False


class CaptchaSettings(BaseModel):
    enabled: bool = False


class SSLSettings(BaseModel):
    enabled: bool = False
    domain: str = ''
    cert_path: str = ''
    key_path: str = ''
    cert_text: str = ''
    key_text: str = ''
    panel_port: int = 5000

class TelegramSettings(BaseModel):
    token: str = ''
    enabled: bool = False


class GuestSettings(BaseModel):
    enabled: bool = False
    token: str = ''
    password: str = ''  # plaintext from form; empty = keep existing hash
    clear_password: bool = False
    user_id: str = ''
    allow_create: bool = False
    create_protocol: str = 'xui'
    create_server_id: int = 0
    create_inbound_id: int = 0
    create_xui_panel_id: str = ''
    create_allow_server_choice: bool = True


class DonateMethodSettings(BaseModel):
    enabled: bool = True
    title: str = ''
    details: str = ''


class DonateSettings(BaseModel):
    enabled: bool = True
    intro: str = ''
    sbp: DonateMethodSettings = DonateMethodSettings()
    card: DonateMethodSettings = DonateMethodSettings()
    crypto: DonateMethodSettings = DonateMethodSettings()


class UpdateUserRequest(BaseModel):
    telegramId: Optional[str] = None
    email: Optional[str] = None
    description: Optional[str] = None
    traffic_limit: Optional[float] = 0
    traffic_reset_strategy: Optional[str] = None
    expiration_date: Optional[str] = None
    expire_after_first_use: Optional[bool] = None
    expiration_days: Optional[int] = None
    password: Optional[str] = None



class SaveSettingsRequest(BaseModel):
    appearance: AppearanceSettings
    sync: SyncSettings
    captcha: CaptchaSettings
    telegram: TelegramSettings
    ssl: SSLSettings
    guest: GuestSettings = GuestSettings()
    donate: DonateSettings = DonateSettings()


class ToggleUserRequest(BaseModel):
    enabled: bool


class AddUserConnectionRequest(BaseModel):
    server_id: int = 0
    protocol: str = 'awg'
    name: str = 'VPN Connection'
    client_id: Optional[str] = None
    telemt_quota: Optional[str] = None
    telemt_max_ips: Optional[int] = None
    telemt_expiry: Optional[str] = None
    telemt_secret: Optional[str] = None
    telemt_ad_tag: Optional[str] = None
    telemt_max_conns: Optional[int] = None
    xui_inbound_id: Optional[int] = None
    xui_panel_id: Optional[str] = None


class CreateApiTokenRequest(BaseModel):
    name: str


class ShareSetupRequest(BaseModel):
    enabled: bool
    password: Optional[str] = None


class ShareAuthRequest(BaseModel):
    password: str


class GuestCreateRequest(BaseModel):
    name: str = 'Guest VPN'
    server_id: Optional[int] = None


class InviteCreateRequest(BaseModel):
    name: str = 'Invite'
    max_uses: int = 1  # 0 = unlimited
    user_id: str = ''
    protocol: str = 'xui'
    server_id: int = 0
    xui_inbound_id: int = 0
    xui_panel_id: str = ''
    password: Optional[str] = None
    duration_days: int = 0  # client lifetime after redeem; 0 = no expiry
    note: str = ''
    enabled: bool = True
    allow_server_choice: bool = True


class InviteUpdateRequest(BaseModel):
    name: Optional[str] = None
    max_uses: Optional[int] = None
    user_id: Optional[str] = None
    protocol: Optional[str] = None
    server_id: Optional[int] = None
    xui_inbound_id: Optional[int] = None
    xui_panel_id: Optional[str] = None
    password: Optional[str] = None
    clear_password: bool = False
    duration_days: Optional[int] = None
    note: Optional[str] = None
    enabled: Optional[bool] = None
    reset_used: bool = False
    allow_server_choice: Optional[bool] = None


class InviteRedeemRequest(BaseModel):
    name: str = 'Invite VPN'
    server_id: Optional[int] = None


class TunnelStartRequest(BaseModel):
    authtoken: Optional[str] = None


class ApplyUpdateRequest(BaseModel):
    target_version: Optional[str] = None
    allow_dirty: bool = False


class NordvpnConnectRequest(BaseModel):
    country: Optional[str] = ''
    city: Optional[str] = ''


# ======================== Startup ========================

@app.on_event("startup")
async def startup():
    # Init Postgres schema; import legacy data.json once if DB is empty
    await asyncio.to_thread(ensure_db_ready, DATA_FILE)
    # Optional: import tunnels_state.json into DB if present and empty
    if os.path.exists(TUNNEL_STATE_FILE):
        try:
            existing = await asyncio.to_thread(load_tunnel_state)
            if not existing:
                with open(TUNNEL_STATE_FILE, 'r', encoding='utf-8') as f:
                    legacy_tunnels = json.load(f)
                if isinstance(legacy_tunnels, dict) and legacy_tunnels:
                    await asyncio.to_thread(save_tunnel_state, legacy_tunnels)
                    logger.info("Imported legacy tunnels_state.json into PostgreSQL")
        except Exception as e:
            logger.warning(f"Could not import tunnels_state.json: {e}")

    data = load_data()
    changed = False
    if not data.get('users'):
        data['users'] = [{
            'id': str(uuid.uuid4()),
            'username': 'admin',
            'password_hash': hash_password('admin'),
            'role': 'admin',
            'enabled': True,
            'created_at': datetime.now().isoformat(),
        }]
        changed = True
        logger.info("Default admin created (admin / admin)")
    
    # Migration for sharing fields and traffic reset strategy
    for u in data['users']:
        migrated = False
        if 'share_enabled' not in u:
            u['share_enabled'] = False
            migrated = True
        if not u.get('share_token'):
            u['share_token'] = secrets.token_urlsafe(16)
            migrated = True
        if 'share_password_hash' not in u:
            u['share_password_hash'] = None
            migrated = True
        
        # Traffic reset strategy and total traffic
        if 'traffic_reset_strategy' not in u:
            u['traffic_reset_strategy'] = 'never'
            migrated = True
        if 'traffic_total' not in u:
            u['traffic_total'] = u.get('traffic_used', 0)
            migrated = True
        if 'last_reset_at' not in u:
            u['last_reset_at'] = datetime.now().isoformat()
            migrated = True
        if 'expiration_date' not in u:
            u['expiration_date'] = None
        if 'expire_after_first_use' not in u:
            u['expire_after_first_use'] = False
        if 'expiration_days' not in u:
            u['expiration_days'] = 0
            migrated = True
        if 'xui_email' not in u:
            u['xui_email'] = None
            migrated = True
            
        if migrated:
            changed = True
            logger.info(f"Migrated user {u['username']} to new traffic/sharing fields")
    
    # API tokens collection — initialise lazily on first run.
    if 'api_tokens' not in data:
        data['api_tokens'] = []
        changed = True
        logger.info("Initialised empty api_tokens collection")

    # SSL settings migration
    if 'ssl' not in data.get('settings', {}):
        if 'settings' not in data: data['settings'] = {}
        data['settings']['ssl'] = {
            'enabled': False,
            'domain': '',
            'cert_path': '',
            'key_path': '',
            'cert_text': '',
            'key_text': '',
            'panel_port': 5000
        }
        changed = True
        logger.info("Migrated SSL settings")

    if changed:
        save_data(data)

    # Start periodic background tasks
    asyncio.create_task(periodic_background_tasks())

    # Start Telegram bot if enabled
    tg_cfg = data.get('settings', {}).get('telegram', {})
    if tg_cfg.get('enabled') and tg_cfg.get('token'):
        logger.info("Starting Telegram bot from saved settings...")
        tg_bot.launch_bot(tg_cfg['token'], load_data, generate_vpn_link, save_data)

    # Reattach quick tunnels after panel restart so public URLs keep working.
    try:
        tunnel_state = await asyncio.to_thread(load_tunnel_state)
        local_url = get_panel_tunnel_target_url()
        for provider in ('cloudflare', 'ngrok'):
            state = tunnel_state.get(provider) or {}
            if not (state.get('public_url') or state.get('pid') or state.get('started_at')):
                continue
            if state.get('pid') and pid_is_running(state.get('pid')):
                continue
            try:
                await asyncio.to_thread(start_tunnel, provider, local_url)
                logger.info('Restarted %s tunnel after panel boot -> %s', provider, local_url)
            except Exception as exc:
                logger.warning('Could not restart %s tunnel after panel boot: %s', provider, exc)
    except Exception as exc:
        logger.warning('Tunnel auto-restart skipped: %s', exc)


def _scrape_server_traffic(server, sid, my_conns):
    server_updates = []
    try:
        traffic_bases = {'awg', 'awg2', 'awg3', 'awg_legacy', 'xray', 'telemt', 'wireguard'}
        installed = server.get('protocols') or {}
        my_by_proto = {}
        for uc in my_conns:
            proto = uc.get('protocol') or ''
            if protocol_base(proto) not in traffic_bases:
                continue
            my_by_proto.setdefault(proto, []).append(uc)
        if not my_by_proto:
            return server_updates

        def _resolve_key(proto):
            if proto in installed:
                return proto
            base = protocol_base(proto)
            if base in installed:
                return base
            return None

        def _scrape(ssh):
            updates = []
            # Deduplicate SSH work when several connection protocols map to one install key
            by_install = {}
            for proto, ucs in my_by_proto.items():
                key = _resolve_key(proto)
                if not key:
                    continue
                by_install.setdefault(key, []).extend(ucs)

            for key, ucs in by_install.items():
                try:
                    manager = get_protocol_manager(ssh, key)
                    clients = _manager_call(manager, 'get_clients', key) or []
                except Exception as e:
                    logger.warning("Traffic scrape %s on server %s failed: %s", key, sid, e)
                    continue
                client_bytes = {}
                for c in clients:
                    rx = c.get('userData', {}).get('dataReceivedBytes', 0) or 0
                    tx = c.get('userData', {}).get('dataSentBytes', 0) or 0
                    cid = c.get('clientId')
                    if cid:
                        client_bytes[cid] = rx + tx
                for uc in ucs:
                    cid = uc.get('client_id')
                    if cid not in client_bytes:
                        continue
                    curr_bytes = client_bytes[cid]
                    last_bytes = uc.get('last_bytes', 0) or 0
                    delta = curr_bytes - last_bytes if curr_bytes >= last_bytes else curr_bytes
                    updates.append((uc['id'], delta, curr_bytes))
            return updates

        server_updates = run_ssh(server, _scrape)
    except Exception as e:
        logger.error(f"Traffic sync err server {sid}: {e}")
    return server_updates


async def periodic_background_tasks():
    """Background task to sync traffic limits and Remnawave every 10 minutes"""
    while True:
        try:
            # We wait before the first sync to let the app settle
            await asyncio.sleep(60) 
            
            # --- 1. TRAFFIC SYNC & LIMITS ---
            logger.info("Starting background traffic sync...")
            data = load_data()
            
            conns_by_server = {}
            for uc in data.get('user_connections', []):
                sid = uc['server_id']
                conns_by_server.setdefault(sid, []).append(uc)
                
            updates = []
            
            for sid, server in enumerate(data.get('servers', [])):
                if sid not in conns_by_server:
                    continue
                try:
                    # Hard cap so one wedged VPS cannot block the whole panel loop
                    server_updates = await asyncio.wait_for(
                        asyncio.to_thread(_scrape_server_traffic, server, sid, conns_by_server[sid]),
                        timeout=90,
                    )
                except asyncio.TimeoutError:
                    logger.error("Traffic sync timed out for server %s (%s)", sid, server.get('host'))
                    continue
                except Exception as e:
                    logger.error("Traffic sync err server %s: %s", sid, e)
                    continue
                if server_updates:
                    updates.extend(server_updates)
                # Brief yield so API requests can use SSH between servers
                await asyncio.sleep(0.2)

            to_disable_uids = []
            if updates:
                async with DATA_LOCK:
                    curr_data = load_data()
                    users_map = {u['id']: u for u in curr_data.get('users', [])}
                    uc_list = curr_data.get('user_connections', [])
                    uc_map = {uc['id']: uc for uc in uc_list}
                    
                    # Current date/time for reset checking
                    now = datetime.now()
                    
                    for uc_id, delta, curr_bytes in updates:
                        if uc_id in uc_map:
                            uc_map[uc_id]['last_bytes'] = curr_bytes
                            uid = uc_map[uc_id]['user_id']
                            if uid in users_map:
                                u = users_map[uid]
                                # Check if reset is needed BEFORE adding new consumption
                                strategy = u.get('traffic_reset_strategy', 'never')
                                last_reset_iso = u.get('last_reset_at')
                                
                                reset_needed = False
                                if strategy != 'never' and last_reset_iso:
                                    try:
                                        last = datetime.fromisoformat(last_reset_iso)
                                        if strategy == 'daily':
                                            reset_needed = now.date() > last.date()
                                        elif strategy == 'weekly':
                                            reset_needed = now.isocalendar()[1] != last.isocalendar()[1] or now.year != last.year
                                        elif strategy == 'monthly':
                                            reset_needed = now.month != last.month or now.year != last.year
                                    except:
                                        pass
                                
                                if reset_needed:
                                    logger.info(f"Resetting traffic for user {u['username']} (strategy: {strategy})")
                                    u['traffic_used'] = 0
                                    u['last_reset_at'] = now.isoformat()
                                
                                # Update both resettable and total traffic
                                u['traffic_used'] = u.get('traffic_used', 0) + delta
                                u['traffic_total'] = u.get('traffic_total', 0) + delta
                                
                                limit = u.get('traffic_limit', 0)
                                if limit > 0 and u['traffic_used'] >= limit and u.get('enabled', True):
                                    if uid not in to_disable_uids:
                                        to_disable_uids.append(uid)
                                
                                # Check expiration date (naive/aware-safe)
                                if u.get('enabled', True):
                                    try:
                                        from managers.user_expiration import user_is_expired
                                        if user_is_expired(u, now=now):
                                            logger.info(
                                                f"Subscription expired for user {u['username']} "
                                                f"(expired at {u.get('expiration_date')})"
                                            )
                                            if uid not in to_disable_uids:
                                                to_disable_uids.append(uid)
                                    except Exception:
                                        pass
                    save_data(curr_data)
                    
            if to_disable_uids:
                logger.info(f"Traffic limit reached, disabling users: {to_disable_uids}")
                await perform_mass_operations(toggle_uids=[(uid, False) for uid in to_disable_uids])

            # --- 2. REMNAWAVE SYNC ---
            logger.info("Starting background Remnawave sync...")
            data = load_data()
            if data.get('settings', {}).get('sync', {}).get('remnawave_sync_users'):
                count, msg = await sync_users_with_remnawave(data)
                logger.info(f"Background Remnawave sync finished: {count} users updated. {msg}")
            else:
                logger.info("Background Remnawave sync skipped (disabled in settings)")

            # --- 3. 3X-UI SYNC ---
            logger.info("Starting background 3x-ui sync...")
            data = load_data()
            sync_cfg = data.get('settings', {}).get('sync', {})
            from managers.xui_servers import ensure_xui_servers, list_xui_servers
            ensure_xui_servers(data.setdefault('settings', {}))
            xui_sync_enabled = bool(sync_cfg.get('xui_sync_users')) or any(
                s.get('sync_users') for s in list_xui_servers(data.get('settings') or {})
            )
            if xui_sync_enabled:
                count, msg = await sync_users_with_xui(data)
                logger.info(f"Background 3x-ui sync finished: {count} users updated. {msg}")
            else:
                logger.info("Background 3x-ui sync skipped (disabled in settings)")

        except Exception as e:
            logger.error(f"Error in periodic_background_tasks: {e}")
            
        # Wait 10 minutes before next sync
        await asyncio.sleep(600)


# ======================== PAGE ROUTES ========================

@app.get('/login', response_class=HTMLResponse, tags=["System Templates"])
async def login_page(request: Request):
    if get_current_user(request):
        return RedirectResponse(url='/', status_code=302)
    data = load_data()
    guest = data.get('settings', {}).get('guest') or {}
    guest_link = None
    if guest.get('enabled') and guest.get('token'):
        guest_link = f"/guest/{guest['token']}"
    return tpl(request, 'login.html', guest_link=guest_link)


@app.get("/set_lang/{lang}", tags=["System Templates"])
async def set_lang(lang: str, request: Request):
    ref = request.headers.get("referer", "/")
    response = RedirectResponse(url=ref)
    response.set_cookie(key="lang", value=lang, max_age=31536000)
    return response


@app.get('/logout', tags=["System Templates"])
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url='/login', status_code=302)


@app.get('/', response_class=HTMLResponse, tags=["System Templates"])
async def index(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url='/login', status_code=302)
    if user['role'] == 'user':
        return RedirectResponse(url='/my', status_code=302)
    data = load_data()
    return tpl(request, 'index.html', servers=data['servers'])


@app.get('/server/{server_id}', response_class=HTMLResponse, tags=["System Templates"])
async def server_detail(request: Request, server_id: int):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url='/login', status_code=302)
    if user['role'] not in ('admin', 'support'):
        return RedirectResponse(url='/my', status_code=302)
    data = load_data()
    if server_id >= len(data['servers']):
        return RedirectResponse(url='/')
    server = data['servers'][server_id]
    users_list = data.get('users', [])
    servers_for_move = [
        {
            'id': idx,
            'name': srv.get('name') or srv.get('host') or f'Server {idx + 1}',
            'host': srv.get('host') or '',
        }
        for idx, srv in enumerate(data['servers'])
    ]
    return tpl(
        request,
        'server.html',
        server=server,
        server_id=server_id,
        users=users_list,
        servers_for_move=servers_for_move,
    )


@app.get('/users', response_class=HTMLResponse, tags=["System Templates"])
async def users_page(request: Request):
    data = load_data()
    user = get_current_user(request, data)
    if not user:
        return RedirectResponse(url='/login', status_code=302)
    if user['role'] not in ('admin', 'support'):
        return RedirectResponse(url='/my', status_code=302)
    users_list = data.get('users', [])
    # Count connections per user
    conns = data.get('user_connections', [])
    conn_counts = Counter(c.get('user_id') for c in conns if c.get('user_id'))
    for u in users_list:
        u['connections_count'] = conn_counts.get(u['id'], 0)
    servers = data['servers']
    from managers.xui_servers import list_xui_servers, ensure_xui_servers, get_xui_server
    ensure_xui_servers(data.setdefault('settings', {}))
    xui_servers = list_xui_servers(data.get('settings') or {})
    primary = get_xui_server(data.get('settings') or {}, None)
    xui_configured = bool(xui_servers)
    return tpl(
        request, 'users.html',
        users=users_list,
        servers=servers,
        current_user=user,
        xui_configured=xui_configured,
        xui_servers=xui_servers,
        xui_inbound_id=int((primary or {}).get('default_inbound_id') or 0),
        xui_default_panel_id=(primary or {}).get('id') or '',
    )


@app.get('/my', response_class=HTMLResponse, tags=["System Templates"])
async def my_connections_page(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url='/login', status_code=302)
    data = load_data()
    conns = [c for c in data.get('user_connections', []) if c['user_id'] == user['id']]
    # Enrich with server names
    for c in conns:
        if protocol_base(c.get('protocol', '')) == 'xui':
            c['server_name'] = '3x-ui'
            continue
        sid = c.get('server_id', 0)
        if sid < len(data['servers']):
            c['server_name'] = data['servers'][sid].get('name', data['servers'][sid].get('host', ''))
        else:
            c['server_name'] = 'Unknown'
    return tpl(request, 'my_connections.html', connections=conns)


# ======================== AUTH API ========================

@app.get('/api/auth/captcha', tags=["Authentication"])
async def api_captcha(request: Request):
    if not CaptchaGenerator:
        return JSONResponse({"error": "multicolorcaptcha is not installed"}, status_code=500)
    
    # 2 is a multiplier for the image resolution size
    generator = CaptchaGenerator(2)
    captcha = generator.gen_captcha_image(difficult_level=2)
    request.session['captcha_answer'] = captcha.characters
    
    img_bytes = io.BytesIO()
    captcha.image.save(img_bytes, format='PNG')
    img_bytes.seek(0)
    
    return StreamingResponse(img_bytes, media_type="image/png")


@app.post('/api/auth/login', tags=["Authentication"])
async def api_login(request: Request, req: LoginRequest):
    data = load_data()
    captcha_settings = data.get('settings', {}).get('captcha', {})
    if captcha_settings.get('enabled') is True:
        answer = request.session.get('captcha_answer')
        lang = request.cookies.get('lang', 'ru')
        if not answer or not req.captcha or answer.lower() != req.captcha.lower():
            request.session.pop('captcha_answer', None)
            return JSONResponse({'error': _t('invalid_captcha', lang)}, status_code=400)
        request.session.pop('captcha_answer', None)

    for u in data.get('users', []):
        if u['username'] == req.username and verify_password(req.password, u['password_hash']):
            lang = request.cookies.get('lang', 'ru')
            if not u.get('enabled', True):
                return JSONResponse({'error': _t('account_disabled', lang)}, status_code=403)
            request.session['user_id'] = u['id']
            return {'status': 'success', 'role': u['role']}
    lang = request.cookies.get('lang', 'ru')
    return JSONResponse({'error': _t('invalid_login', lang)}, status_code=401)


# ======================== SERVER API (admin/support) ========================

def _check_admin(request):
    """Authorize an admin/support action via session cookie OR Bearer token.

    Tokens are admin-equivalent and inherit the role of the user who created
    them — if that user is later disabled or demoted, the token stops working.
    """
    user = get_current_user(request)
    if user and user['role'] in ('admin', 'support'):
        return user

    auth_header = request.headers.get('Authorization', '')
    if auth_header.lower().startswith('bearer '):
        raw_token = auth_header[7:].strip()
        data = load_data()
        resolved = _resolve_api_token(data, raw_token)
        if resolved:
            entry, token_user = resolved
            if _touch_api_token(entry):
                token_id = entry.get('id')
                if token_id:
                    _schedule_api_token_touch(token_id)
            return token_user

    return None


async def _check_admin_async(request):
    """Async variant for hot paths (server list/ping) — avoids blocking the loop."""
    user = get_current_user(request)
    if user and user['role'] in ('admin', 'support'):
        return user

    auth_header = request.headers.get('Authorization', '')
    if auth_header.lower().startswith('bearer '):
        raw_token = auth_header[7:].strip()
        data = await load_data_async()
        resolved = _resolve_api_token(data, raw_token)
        if resolved:
            entry, token_user = resolved
            if _touch_api_token(entry):
                token_id = entry.get('id')
                if token_id:
                    _schedule_api_token_touch(token_id)
            return token_user

    return None


def _public_vpn_server_view(server: dict, server_id: int) -> dict:
    """Safe server list view for API consumers (no SSH secrets)."""
    server_info = dict(server.get('server_info') or {})
    for key in list(server_info.keys()):
        if key not in ('uname', 'ssl_domain', 'ssl_email', 'connect_domain'):
            server_info.pop(key, None)

    protocols = {}
    for key, info in (server.get('protocols') or {}).items():
        if not isinstance(info, dict):
            continue
        protocols[key] = {
            'installed': bool(info.get('installed')),
            'port': info.get('port'),
            'running': info.get('running'),
            'container_exists': info.get('container_exists'),
        }

    return {
        'id': server_id,
        'name': server.get('name') or server.get('host') or '',
        'host': server.get('host') or '',
        'ssh_port': int(server.get('ssh_port') or 22),
        'username': server.get('username') or '',
        'auth': 'key' if server.get('private_key') else 'password',
        'has_password': bool(server.get('password')),
        'has_private_key': bool(server.get('private_key')),
        'server_info': server_info,
        'protocols': protocols,
    }


@app.get('/api/servers', tags=["Servers"])
async def api_list_servers(request: Request):
    """List SSH servers in the panel inventory (credentials are never returned)."""
    if not await _check_admin_async(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = await load_data_async()
    servers = [
        _public_vpn_server_view(s, idx)
        for idx, s in enumerate(data.get('servers', []))
        if isinstance(s, dict)
    ]
    return {'servers': servers, 'total': len(servers)}


@app.post('/api/servers/add', tags=["Servers"])
async def api_add_server(request: Request, req: AddServerRequest):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        host = req.host.strip()
        username = req.username.strip()
        name = req.name.strip() or host
        if not host or not username:
            return JSONResponse({'error': 'Host and username are required'}, status_code=400)
        if not req.password and not req.private_key:
            return JSONResponse({'error': 'Password or SSH key is required'}, status_code=400)

        ssh = SSHManager(host, req.ssh_port, username, req.password, req.private_key)
        try:
            ssh.connect()
            raw_info = ssh.test_connection()
            ssh.disconnect()
        except Exception as e:
            return JSONResponse({'error': f'Connection failed: {str(e)}'}, status_code=400)

        # Always store as an object — legacy test_connection() returns a plain string
        if isinstance(raw_info, dict):
            server_info = raw_info
        else:
            server_info = {'uname': str(raw_info or '').strip()}

        server = {
            'name': name, 'host': host, 'ssh_port': req.ssh_port,
            'username': username, 'password': req.password,
            'private_key': req.private_key, 'server_info': server_info,
            'protocols': {},
        }
        ssl_domain = (req.ssl_domain or '').strip().lower()
        ssl_email = (req.ssl_email or '').strip()
        connect_domain = (req.connect_domain or '').strip().lower()
        if ssl_domain:
            server_info['ssl_domain'] = ssl_domain
        if ssl_email:
            server_info['ssl_email'] = ssl_email
        if connect_domain:
            server_info['connect_domain'] = connect_domain
        server['server_info'] = server_info
        data = load_data()
        data['servers'].append(server)
        save_data(data)
        return {'status': 'success', 'server_id': len(data['servers']) - 1, 'server_info': server_info}
    except Exception as e:
        logger.exception("Error adding server")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/edit', tags=["Servers"])
async def api_edit_server(request: Request, server_id: int, req: EditServerRequest):
    """Update connection details for an existing server entry. Verifies the new
    credentials by SSH-connecting before persisting, so a typo can't lock us out.
    """
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]

        new_host = (req.host or '').strip() or server['host']
        new_user = (req.username or '').strip() or server['username']
        new_port = int(req.ssh_port or server.get('ssh_port', 22))
        new_name = (req.name or '').strip() or server.get('name') or new_host

        # Credential resolution: a non-empty value in either field switches to
        # that auth method (and clears the other). Both omitted => keep current.
        if req.private_key:
            new_pass, new_key = '', req.private_key
        elif req.password:
            new_pass, new_key = req.password, ''
        else:
            new_pass = server.get('password', '')
            new_key = server.get('private_key', '')

        if not new_pass and not new_key:
            return JSONResponse({'error': 'Password or SSH key is required'}, status_code=400)

        # Verify the new connection details before committing the change.
        ssh = SSHManager(new_host, new_port, new_user, new_pass, new_key)
        try:
            ssh.connect()
            raw_info = ssh.test_connection()
            ssh.disconnect()
        except Exception as e:
            return JSONResponse({'error': f'Connection failed: {e}'}, status_code=400)

        if isinstance(raw_info, dict):
            server_info = raw_info
        else:
            server_info = {'uname': str(raw_info or '').strip()}

        server['name'] = new_name
        server['host'] = new_host
        server['ssh_port'] = new_port
        server['username'] = new_user
        server['password'] = new_pass
        server['private_key'] = new_key
        # Merge SSH probe info with preserved SSL domain defaults
        info = dict(server.get('server_info') or {})
        if isinstance(server_info, dict):
            for k, v in server_info.items():
                if k not in ('ssl_domain', 'ssl_email', 'connect_domain'):
                    info[k] = v
        if req.ssl_domain is not None:
            domain = (req.ssl_domain or '').strip().lower()
            if domain:
                info['ssl_domain'] = domain
            else:
                info.pop('ssl_domain', None)
        if req.ssl_email is not None:
            email = (req.ssl_email or '').strip()
            if email:
                info['ssl_email'] = email
            else:
                info.pop('ssl_email', None)
        if req.connect_domain is not None:
            domain = (req.connect_domain or '').strip().lower()
            if domain:
                info['connect_domain'] = domain
            else:
                info.pop('connect_domain', None)
        server['server_info'] = info
        save_data(data)
        return {'status': 'success', 'server_info': info}
    except Exception as e:
        logger.exception("Error editing server")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.get('/api/servers/{server_id}/connect-domain', tags=["Servers"])
async def api_get_connect_domain(request: Request, server_id: int, protocol: Optional[str] = None):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    if server_id >= len(data['servers']):
        return JSONResponse({'error': 'Server not found'}, status_code=404)
    server = data['servers'][server_id]
    proto = (protocol or '').strip()
    info = server.get('server_info') or {}
    proto_domain = ''
    if proto:
        pinfo = (server.get('protocols') or {}).get(proto) or {}
        proto_domain = (pinfo.get('connect_domain') or '').strip()
    return {
        'connect_domain': (info.get('connect_domain') or '').strip(),
        'protocol_connect_domain': proto_domain,
        'protocol': proto,
        'effective_host': get_server_connect_host(server, proto or None),
        'ssh_host': server.get('host') or '',
    }


@app.post('/api/servers/{server_id}/connect-domain', tags=["Servers"])
async def api_set_connect_domain(request: Request, server_id: int, req: ConnectDomainRequest):
    """Set client Endpoint hostname for AWG / WireGuard without re-verifying SSH."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        domain = (req.connect_domain or '').strip().lower().rstrip('.')
        proto = (req.protocol or '').strip()

        if proto:
            base = protocol_base(proto)
            if base not in WG_AWG_PROTOCOLS:
                return JSONResponse(
                    {'error': 'Per-protocol domain is only supported for AmneziaWG / WireGuard'},
                    status_code=400,
                )
            protocols = server.setdefault('protocols', {})
            proto_info = protocols.setdefault(proto, {})
            if domain:
                proto_info['connect_domain'] = domain
            else:
                proto_info.pop('connect_domain', None)
        else:
            info = dict(server.get('server_info') or {})
            if domain:
                info['connect_domain'] = domain
            else:
                info.pop('connect_domain', None)
            server['server_info'] = info

        save_data(data)
        return {
            'status': 'success',
            'connect_domain': domain,
            'protocol': proto,
            'effective_host': get_server_connect_host(server, proto or None),
        }
    except Exception as e:
        logger.exception('Error saving connect domain')
        return JSONResponse({'error': str(e)}, status_code=500)


@app.get('/api/servers/{server_id}/ping', tags=["Servers"])
async def api_server_ping(request: Request, server_id: int):
    """Cheap reachability check: opens a TCP connection to the SSH port,
    measures RTT, immediately closes. Runs on the asyncio loop so the page
    can issue many pings in parallel without blocking each other.
    """
    if not await _check_admin_async(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = await load_data_async()
    if server_id >= len(data['servers']):
        return JSONResponse({'error': 'Server not found'}, status_code=404)
    server = data['servers'][server_id]
    host = server['host']
    port = int(server.get('ssh_port', 22))

    import time as _time
    t0 = _time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=2.0
        )
        ms = round((_time.perf_counter() - t0) * 1000)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return {'alive': True, 'ms': ms}
    except asyncio.TimeoutError:
        return {'alive': False, 'error': 'timeout', 'ms': None}
    except Exception as e:
        return {'alive': False, 'error': str(e), 'ms': None}


@app.post('/api/servers/reorder', tags=["Servers"])
async def api_reorder_servers(request: Request, req: ReorderServersRequest):
    """Persist a user-defined ordering of servers. Also remaps `server_id`
    references in user_connections so existing assignments survive the move.
    """
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    async with DATA_LOCK:
        data = load_data()
        n = len(data['servers'])
        order = req.order or []
        if len(order) != n or sorted(order) != list(range(n)):
            return JSONResponse(
                {'error': f'Order must be a permutation of indices 0..{n - 1}'},
                status_code=400,
            )
        new_servers = [data['servers'][i] for i in order]
        # Map old index -> new index for user_connections remap
        remap = {old: new for new, old in enumerate(order)}
        for c in data.get('user_connections', []):
            old_id = c.get('server_id')
            if isinstance(old_id, int) and old_id in remap:
                c['server_id'] = remap[old_id]
        # Sync settings.sync.remnawave_server_id if it points at a moved server
        sync_cfg = data.get('settings', {}).get('sync', {})
        rsid = sync_cfg.get('remnawave_server_id')
        if isinstance(rsid, int) and rsid in remap:
            sync_cfg['remnawave_server_id'] = remap[rsid]
        data['servers'] = new_servers
        save_data(data)
    return {'status': 'success'}


@app.post('/api/servers/{server_id}/delete', tags=["Servers"])
async def api_delete_server(request: Request, server_id: int):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        data['servers'].pop(server_id)
        # Clean up connections for this server
        data['user_connections'] = [c for c in data.get('user_connections', []) if c.get('server_id') != server_id]
        # Adjust server_ids for connections pointing to higher indices
        for c in data.get('user_connections', []):
            if c.get('server_id', 0) > server_id:
                c['server_id'] -= 1
        save_data(data)
        return {'status': 'success'}
    except Exception as e:
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/reboot', tags=["Servers"])
async def api_reboot_server(request: Request, server_id: int):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        ssh = get_ssh(server)
        ssh.connect()
        try:
            ssh.run_sudo_command("nohup reboot > /dev/null 2>&1 &")
        except Exception:
            pass            
        try:
            ssh.disconnect()
        except:
            pass
        return {'status': 'success'}
    except Exception as e:
        logger.exception("Error rebooting server")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/clear', tags=["Servers"])
async def api_clear_server(request: Request, server_id: int):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        ssh = get_ssh(server)
        ssh.connect()
        # Match every Amnezia container by name prefix (catches awg/awg2/awg-legacy,
        # wireguard, xray/ssxray, openvpn, dns, and any future amnezia-* protocol)
        # plus the telemt container which doesn't share that prefix.
        # Using a single script avoids one SSH round-trip per command.
        cleanup_script = r"""
for c in $(docker ps -a --format '{{.Names}}' 2>/dev/null | grep -E '^(amnezia-|telemt$)'); do
    docker stop "$c" >/dev/null 2>&1 || true
    docker rm -fv "$c" >/dev/null 2>&1 || true
done

# Drop locally-built and pulled Amnezia images so reinstall starts from a clean slate
for img in $(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -E '^(amnezia-|amneziavpn/|telemt:)'); do
    docker rmi -f "$img" >/dev/null 2>&1 || true
done

docker network rm amnezia-dns-net >/dev/null 2>&1 || true
rm -rf /opt/amnezia
"""
        ssh.run_sudo_script(cleanup_script, timeout=120)

        server['protocols'] = {}
        save_data(data)
        ssh.disconnect()
        return {'status': 'success'}
    except Exception as e:
        logger.exception("Error clearing server")
        return JSONResponse({'error': str(e)}, status_code=500)


def _docker_container_inventory(ssh) -> dict:
    """One SSH round-trip: map container name -> running bool."""
    out, _, _ = ssh.run_sudo_command(
        "docker ps -a --format '{{.Names}}|{{.Status}}' 2>/dev/null"
    )
    inventory = {}
    for line in (out or '').splitlines():
        if '|' not in line:
            continue
        name, status = line.split('|', 1)
        name = name.strip()
        if not name:
            continue
        inventory[name] = status.strip().lower().startswith('up')
    return inventory


def _docker_is_ready(ssh) -> bool:
    ver, _, vcode = ssh.run_command("docker --version 2>/dev/null")
    return vcode == 0 and bool((ver or '').strip())


@app.post('/api/servers/{server_id}/stats', tags=["Servers"])
async def api_server_stats(request: Request, server_id: int):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = await load_data_async()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]

        cached = api_cache.get(f'stats:{server_id}', ttl=4)
        if cached is not None:
            return cached

        def _fetch_stats():
            script = r"""
cpu=$(top -bn1 2>/dev/null | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1)
if [ -z "$cpu" ]; then cpu=0; fi
ram=$(free -b 2>/dev/null | awk 'NR==2{printf "%d %d", $3, $2}')
disk=$(df -B1 / 2>/dev/null | awk 'NR==2{printf "%d %d", $3, $2}')
dev=$(ip route 2>/dev/null | awk '/default/ {print $5; exit}')
net=$(awk -v d="${dev}:" '$1==d{printf "%d %d", $2, $10}' /proc/net/dev 2>/dev/null)
up=$(uptime -p 2>/dev/null || uptime)
printf 'CPU|%s\nRAM|%s\nDISK|%s\nNET|%s\nUP|%s\n' "${cpu:-0}" "${ram:-0 0}" "${disk:-0 0}" "${net:-0 0}" "$up"
"""
            def _run(ssh):
                out, _, _ = ssh.run_command(script, timeout=20)
                return out
            out = run_ssh(server, _run)

            stats = {
                'cpu': 0,
                'ram_used': 0, 'ram_total': 0, 'ram_percent': 0,
                'disk_used': 0, 'disk_total': 0, 'disk_percent': 0,
                'net_rx': 0, 'net_tx': 0,
                'uptime': '',
            }
            for line in (out or '').splitlines():
                if '|' not in line:
                    continue
                key, val = line.split('|', 1)
                key, val = key.strip(), val.strip()
                try:
                    if key == 'CPU':
                        stats['cpu'] = round(float(val.split()[0] if val else 0), 1)
                    elif key == 'RAM':
                        parts = val.split()
                        used, total = int(parts[0]), int(parts[1])
                        stats.update(
                            ram_used=used,
                            ram_total=total,
                            ram_percent=round(used / total * 100, 1) if total > 0 else 0,
                        )
                    elif key == 'DISK':
                        parts = val.split()
                        used, total = int(parts[0]), int(parts[1])
                        stats.update(
                            disk_used=used,
                            disk_total=total,
                            disk_percent=round(used / total * 100, 1) if total > 0 else 0,
                        )
                    elif key == 'NET':
                        parts = val.split()
                        stats['net_rx'], stats['net_tx'] = int(parts[0]), int(parts[1])
                    elif key == 'UP':
                        stats['uptime'] = val
                except (ValueError, IndexError):
                    continue
            return stats

        stats = await asyncio.to_thread(_fetch_stats)
        api_cache.set(f'stats:{server_id}', stats)
        return stats
    except Exception as e:
        logger.exception("Error getting server stats")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/check', tags=["Servers"])
async def api_check_server(request: Request, server_id: int):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = await load_data_async()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]

        def _run_check():
            def _do(ssh):
                status = {
                    'connection': 'ok',
                    'docker_installed': _docker_is_ready(ssh),
                    'protocols': {},
                }
                inventory = _docker_container_inventory(ssh) if status['docker_installed'] else {}

                changed = False
                if 'protocols' not in server:
                    server['protocols'] = {}

                def merge_saved_protocol_status(proto, result=None, error=None):
                    db_proto = server.get('protocols', {}).get(proto, {}) or {}
                    merged = dict(result or {})
                    merged.setdefault('protocol', proto)
                    if error:
                        merged['error'] = error
                    if not merged.get('port') and db_proto.get('port'):
                        merged['port'] = db_proto['port']
                    if db_proto.get('awg_params') and not merged.get('awg_params'):
                        merged['awg_params'] = db_proto.get('awg_params')
                    merged['base_protocol'] = db_proto.get('base_protocol') or protocol_base(proto)
                    merged['instance'] = db_proto.get('instance') or protocol_instance(proto)
                    merged['display_name'] = db_proto.get('display_name') or protocol_display_name(proto)
                    merged['container_name'] = db_proto.get('container_name') or protocol_container_name(proto)
                    if protocol_base(proto) == 'adguard':
                        for key in ('web_port', 'mode', 'internal_ip', 'expose_web'):
                            if db_proto.get(key) not in (None, ''):
                                if key == 'web_port' and merged.get('web_exposed'):
                                    continue
                                merged[key] = db_proto[key]
                        if 'expose_web' in db_proto and 'web_exposed' not in merged:
                            merged['web_exposed'] = bool(db_proto.get('expose_web'))
                    if protocol_base(proto) == 'nginx':
                        for key in ('domain', 'email', 'site_url'):
                            if db_proto.get(key) not in (None, ''):
                                merged[key] = db_proto[key]
                    if protocol_base(proto) == 'hysteria':
                        for key in ('domain', 'email'):
                            if db_proto.get(key) not in (None, '') and not merged.get(key):
                                merged[key] = db_proto[key]
                        if db_proto.get('port') and not merged.get('port'):
                            merged['port'] = db_proto['port']
                    if protocol_base(proto) == 'naiveproxy':
                        for key in ('domain', 'email'):
                            if db_proto.get(key) not in (None, '') and not merged.get(key):
                                merged[key] = db_proto[key]
                        if db_proto.get('port') and not merged.get('port'):
                            merged['port'] = db_proto['port']
                    if protocol_base(proto) == 'mieru':
                        for key in ('release',):
                            if db_proto.get(key) not in (None, '') and not merged.get(key):
                                merged[key] = db_proto[key]
                        if db_proto.get('port') and not merged.get('port'):
                            merged['port'] = db_proto['port']
                    return merged

                def should_preserve_saved_protocol(proto, result=None, err=None):
                    db_proto = server.get('protocols', {}).get(proto)
                    if not db_proto:
                        return False
                    if protocol_base(proto) in MULTI_INSTANCE_PROTOCOLS and protocol_instance(proto) > 1:
                        return True
                    if err or (result and result.get('error')):
                        return True
                    return False

                def check_proto(proto):
                    cname = protocol_container_name(proto)
                    base = protocol_base(proto)
                    # Fast path: skip deep manager probes when container is absent
                    if cname and cname not in inventory and base not in NON_DOCKER_PROTOCOLS:
                        return proto, merge_saved_protocol_status(proto, {
                            'container_exists': False,
                            'container_running': False,
                            'protocol': proto,
                        }), None
                    try:
                        p_manager = get_protocol_manager(ssh, proto)
                        result = _manager_call(p_manager, 'get_server_status', proto)
                        return proto, merge_saved_protocol_status(proto, result), None
                    except Exception as e:
                        return proto, merge_saved_protocol_status(proto, {}, str(e)), str(e)

                protocols_to_check = list(dict.fromkeys(
                    BASE_PROTOCOLS + list(server.get('protocols', {}).keys())
                ))
                for proto in protocols_to_check:
                    proto, result, err = check_proto(proto)
                    status['protocols'][proto] = result
                    if err:
                        continue
                    if result.get('container_exists'):
                        if proto not in server['protocols']:
                            server['protocols'][proto] = {
                                'installed': True,
                                'port': result.get('port', '55424'),
                                'awg_params': result.get('awg_params', {}),
                                'base_protocol': protocol_base(proto),
                                'instance': protocol_instance(proto),
                                'display_name': protocol_display_name(proto),
                                'container_name': protocol_container_name(proto),
                            }
                            if protocol_base(proto) == 'adguard':
                                server['protocols'][proto].update({
                                    'mode': result.get('mode'),
                                    'internal_ip': result.get('internal_ip'),
                                    'web_port': result.get('web_port'),
                                    'expose_web': result.get('web_exposed'),
                                })
                            if protocol_base(proto) == 'nginx':
                                server['protocols'][proto].update({
                                    'domain': result.get('domain'),
                                    'email': result.get('email'),
                                    'site_url': result.get('site_url'),
                                })
                            changed = True
                    else:
                        if proto in server['protocols']:
                            if should_preserve_saved_protocol(proto, result, err):
                                status['protocols'][proto]['container_exists'] = True
                                status['protocols'][proto].setdefault('container_running', False)
                                status['protocols'][proto]['status_preserved'] = True
                            else:
                                del server['protocols'][proto]
                                changed = True

                if changed:
                    save_data(data)
                return status

            return run_ssh(server, _do)

        return await asyncio.to_thread(_run_check)
    except Exception as e:
        logger.exception("Error checking server")
        return JSONResponse({'error': str(e), 'connection': 'failed'}, status_code=500)


@app.post('/api/servers/{server_id}/install', tags=["Protocols"])
async def api_install_protocol(request: Request, server_id: int, req: InstallProtocolRequest):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        if not is_valid_protocol(req.protocol):
            return JSONResponse({'error': 'Invalid protocol type'}, status_code=400)

        server = data['servers'][server_id]
        if 'protocols' not in server:
            server['protocols'] = {}
        base_protocol = protocol_base(req.protocol)
        if req.install_another:
            if base_protocol not in MULTI_INSTANCE_PROTOCOLS:
                return JSONResponse({'error': 'Multiple instances are not supported for this protocol yet'}, status_code=400)
            install_protocol = next_protocol_key(server.get('protocols', {}), base_protocol)
        else:
            install_protocol = req.protocol
        install_base = protocol_base(install_protocol)

        ssh = get_ssh(server)
        ssh.connect()
        docker_install_log = ''
        if install_base not in NON_DOCKER_PROTOCOLS:
            docker_install_log = ensure_docker_installed(ssh)
        manager = get_protocol_manager(ssh, install_protocol)

        # Pass parameters to installer
        if install_base == 'telemt':
            result = manager.install_protocol(
                protocol_type=install_protocol,
                port=req.port,
                tls_emulation=req.tls_emulation if req.tls_emulation is not None else True,
                tls_domain=req.tls_domain,
                max_connections=req.max_connections if req.max_connections is not None else 0
            )
        elif install_base == 'mtproxy':
            result = manager.install_protocol(
                protocol_type=install_protocol,
                port=req.port,
                secret=req.mtproxy_secret,
                ad_tag=req.mtproxy_ad_tag
            )
        elif install_base == 'xray':
            result = manager.install_protocol(
                port=req.port,
                domain=req.xray_domain,
                email=req.xray_email,
                acme_method=req.xray_acme_method or 'cloudflare',
                cloudflare_token=req.xray_cf_token,
            )
        elif install_base == 'wireguard':
            result = manager.install_protocol(port=req.port)
        elif install_base == 'socks5':
            result = manager.install_protocol(
                protocol_type=install_protocol,
                port=req.port,
                username=req.socks5_username,
                password=req.socks5_password,
            )
        elif install_base == 'adguard':
            result = manager.install_protocol(
                protocol_type='adguard',
                mode=req.adguard_mode or 'sidebyside',
                web_port=req.adguard_web_port,
                expose_web=bool(req.adguard_expose_web),
                dns_port=req.port,
                dot_port=req.adguard_dot_port,
                doh_port=req.adguard_doh_port,
                expose_dns=bool(req.adguard_expose_dns),
                expose_dot=bool(req.adguard_expose_dot),
                expose_doh=bool(req.adguard_expose_doh),
            )
        elif install_base == 'nginx':
            result = manager.install_protocol(
                protocol_type='nginx',
                port=req.port,
                domain=req.nginx_domain,
                email=req.nginx_email,
            )
        elif install_base == 'hysteria':
            result = manager.install_protocol(
                protocol_type=install_protocol,
                port=req.port,
                domain=req.hysteria_domain,
                email=req.hysteria_email,
            )
        elif install_base == 'naiveproxy':
            result = manager.install_protocol(
                protocol_type=install_protocol,
                port=req.port,
                domain=req.naiveproxy_domain,
                email=req.naiveproxy_email,
            )
        elif install_base == 'mieru':
            result = manager.install_protocol(
                protocol_type=install_protocol,
                port=req.port,
            )
        else:
            result = manager.install_protocol(install_protocol, port=req.port)

        if not isinstance(result, dict):
            result = {'status': 'success', 'message': str(result)}
        if docker_install_log:
            result.setdefault('log', [])
            result['log'].insert(0, docker_install_log)
        if result.get('status') == 'error' or result.get('error'):
            ssh.disconnect()
            return JSONResponse({'error': result.get('message') or result.get('error') or 'Installation failed'}, status_code=400)

        proto_record = {
            'installed': True,
            'port': req.port,
            'awg_params': result.get('awg_params', {}),
        }
        if install_base == 'adguard':
            proto_record['mode'] = result.get('mode')
            proto_record['internal_ip'] = result.get('internal_ip')
            proto_record['web_port'] = result.get('web_port')
            proto_record['expose_web'] = result.get('expose_web')
        if install_base == 'nginx':
            proto_record['domain'] = result.get('domain')
            proto_record['email'] = result.get('email')
            proto_record['site_url'] = result.get('site_url')
        if install_base == 'hysteria':
            # Remember domain/email as server defaults for next installs / renewals
            info = server.setdefault('server_info', {})
            if req.hysteria_domain:
                info['ssl_domain'] = (req.hysteria_domain or '').strip().lower()
            if req.hysteria_email:
                info['ssl_email'] = (req.hysteria_email or '').strip()
            save_data(data)
            proto_record['domain'] = result.get('domain')
            proto_record['email'] = result.get('email')
            if result.get('port'):
                proto_record['port'] = str(result['port'])
        if install_base == 'xray':
            info = server.setdefault('server_info', {})
            if req.xray_domain:
                info['ssl_domain'] = (req.xray_domain or '').strip().lower()
            if req.xray_email:
                info['ssl_email'] = (req.xray_email or '').strip()
            save_data(data)
            proto_record['domain'] = result.get('domain')
            proto_record['path'] = result.get('path')
            proto_record['transport'] = 'xhttp'
            proto_record['security'] = 'tls'
            proto_record['acme_method'] = result.get('acme_method') or req.xray_acme_method or 'cloudflare'
            if result.get('port'):
                proto_record['port'] = str(result['port'])
        if install_base == 'naiveproxy':
            info = server.setdefault('server_info', {})
            if req.naiveproxy_domain:
                info['ssl_domain'] = (req.naiveproxy_domain or '').strip().lower()
            if req.naiveproxy_email:
                info['ssl_email'] = (req.naiveproxy_email or '').strip()
            save_data(data)
            proto_record['domain'] = result.get('domain')
            proto_record['email'] = result.get('email')
            if result.get('port'):
                proto_record['port'] = str(result['port'])
        if install_base == 'mieru':
            if result.get('port'):
                proto_record['port'] = str(result['port'])
            if result.get('release'):
                proto_record['release'] = result.get('release')
        proto_record['base_protocol'] = install_base
        proto_record['instance'] = protocol_instance(install_protocol)
        proto_record['display_name'] = protocol_display_name(install_protocol)
        proto_record['container_name'] = protocol_container_name(install_protocol)
        server['protocols'][install_protocol] = proto_record
        result['protocol'] = install_protocol
        result['base_protocol'] = install_base
        result['display_name'] = proto_record['display_name']
        result['container_name'] = proto_record['container_name']
        save_data(data)
        ssh.disconnect()
        return result
    except Exception as e:
        logger.exception("Error installing protocol")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.get('/api/servers/{server_id}/socks5/credentials', tags=["Protocols"])
async def api_socks5_get_credentials(request: Request, server_id: int, protocol: str = 'socks5'):
    """Return the current SOCKS5 port/username/password for the panel UI."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        protocol = protocol if is_valid_protocol(protocol) and protocol_base(protocol) == 'socks5' else 'socks5'
        ssh = get_ssh(server)
        ssh.connect()
        manager = get_protocol_manager(ssh, protocol)
        creds = manager.get_credentials()
        ssh.disconnect()
        return {'status': 'success', **creds}
    except Exception as e:
        logger.exception("Error reading SOCKS5 credentials")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/socks5/credentials', tags=["Protocols"])
async def api_socks5_update_credentials(request: Request, server_id: int, req: Socks5SettingsRequest):
    """Apply new SOCKS5 connection settings — regenerates the 3proxy config and
    reconciles the container (recreating it if the listening port changed)."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        protocol = req.protocol if is_valid_protocol(req.protocol) and protocol_base(req.protocol) == 'socks5' else 'socks5'
        ssh = get_ssh(server)
        ssh.connect()
        manager = get_protocol_manager(ssh, protocol)
        result = manager.update_credentials(
            port=req.port, username=req.username, password=req.password
        )
        ssh.disconnect()
        # Persist the new port in the saved server record so the dashboard
        # shows the right value on next check without an SSH round-trip.
        if result.get('status') == 'success' and result.get('port'):
            srv_proto = server.setdefault('protocols', {}).setdefault(protocol, {})
            srv_proto['port'] = str(result['port'])
            srv_proto['installed'] = True
            srv_proto['base_protocol'] = protocol_base(protocol)
            srv_proto['instance'] = protocol_instance(protocol)
            srv_proto['display_name'] = protocol_display_name(protocol)
            srv_proto['container_name'] = protocol_container_name(protocol)
            save_data(data)
        return result
    except Exception as e:
        logger.exception("Error updating SOCKS5 credentials")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.get('/api/servers/{server_id}/hysteria/settings', tags=["Protocols"])
async def api_hysteria_get_settings(request: Request, server_id: int, protocol: str = 'hysteria'):
    """Return current Hysteria domain/port for the settings modal."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        if not is_valid_protocol(protocol) or protocol_base(protocol) != 'hysteria':
            return JSONResponse({'error': 'Invalid protocol'}, status_code=400)
        server = data['servers'][server_id]
        ssh = get_ssh(server)
        ssh.connect()
        manager = get_protocol_manager(ssh, protocol)
        settings = manager.get_settings()
        ssh.disconnect()
        saved = (server.get('protocols') or {}).get(protocol) or {}
        if not settings.get('port') and saved.get('port'):
            settings['port'] = int(saved['port'])
        return {'status': 'success', **settings}
    except Exception as e:
        logger.exception("Error reading Hysteria settings")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/hysteria/settings', tags=["Protocols"])
async def api_hysteria_update_settings(request: Request, server_id: int, req: HysteriaSettingsRequest):
    """Change Hysteria UDP listen port and recreate the container."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        protocol = req.protocol if is_valid_protocol(req.protocol) and protocol_base(req.protocol) == 'hysteria' else 'hysteria'
        server = data['servers'][server_id]
        ssh = get_ssh(server)
        ssh.connect()
        manager = get_protocol_manager(ssh, protocol)
        result = manager.update_settings(
            port=req.port,
            domain=req.domain,
            email=req.email,
            renew_ssl=bool(req.renew_ssl),
        )
        ssh.disconnect()
        if result.get('status') == 'error':
            return JSONResponse(
                {'error': result.get('message') or 'Failed to update settings', **{k: v for k, v in result.items() if k != 'status'}},
                status_code=400,
            )
        if result.get('port') or result.get('domain'):
            srv_proto = server.setdefault('protocols', {}).setdefault(protocol, {})
            if result.get('port'):
                srv_proto['port'] = str(result['port'])
            srv_proto['installed'] = True
            srv_proto['base_protocol'] = protocol_base(protocol)
            srv_proto['instance'] = protocol_instance(protocol)
            srv_proto['display_name'] = protocol_display_name(protocol)
            srv_proto['container_name'] = protocol_container_name(protocol)
            if result.get('domain'):
                srv_proto['domain'] = result['domain']
            # Keep server-level SSL defaults in sync
            info = server.setdefault('server_info', {})
            if result.get('domain'):
                info['ssl_domain'] = result['domain']
            if result.get('email'):
                info['ssl_email'] = result['email']
            save_data(data)
        return result
    except Exception as e:
        logger.exception("Error updating Hysteria settings")
        return JSONResponse({'error': str(e)}, status_code=500)



@app.post('/api/servers/{server_id}/uninstall', tags=["Protocols"])
async def api_uninstall_protocol(request: Request, server_id: int, req: ProtocolRequest):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        ssh = get_ssh(server)
        ssh.connect()
        manager = get_protocol_manager(ssh, req.protocol)
        base = protocol_base(req.protocol)
        if base in ('xray', 'wireguard'):
            manager.remove_container()
        else:
            manager.remove_container(req.protocol)
        if req.protocol in server.get('protocols', {}):
            del server['protocols'][req.protocol]
            save_data(data)
        ssh.disconnect()
        return {'status': 'success'}
    except Exception as e:
        logger.exception("Error uninstalling protocol")
        return JSONResponse({'error': str(e)}, status_code=500)


CONTAINER_NAMES = {
    'awg': 'amnezia-awg',
    'awg2': 'amnezia-awg2',
    'awg3': 'amnezia-awg3',
    'awg_legacy': 'amnezia-awg-legacy',
    'xray': 'amnezia-xray',
    'telemt': 'telemt',
    'hysteria': 'amnezia-hysteria',
    'naiveproxy': 'amnezia-naiveproxy',
    'mieru': 'mita',
    'dns': 'amnezia-dns',
    'wireguard': 'amnezia-wireguard',
    'socks5': 'amnezia-socks5proxy',
    'adguard': 'amnezia-adguard',
    'nginx': 'amnezia-nginx',
}



@app.post('/api/servers/{server_id}/backups', tags=["Protocols"])
async def api_protocol_backups_list(request: Request, server_id: int, req: ProtocolRequest):
    """List backups created on the remote server for one protocol."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    if not is_valid_protocol(req.protocol):
        return JSONResponse({'error': 'Unknown protocol'}, status_code=400)
    ssh = None
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        ssh = get_ssh(server)
        ssh.connect()
        result = BackupManager(ssh).list_backups(req.protocol)
        if result.get('status') == 'error':
            return JSONResponse({'error': result.get('message', 'Failed to list backups')}, status_code=500)
        return result
    except Exception as e:
        logger.exception("Error listing protocol backups")
        return JSONResponse({'error': str(e)}, status_code=500)
    finally:
        if ssh:
            ssh.disconnect()


@app.post('/api/servers/{server_id}/backups/create', tags=["Protocols"])
async def api_protocol_backup_create(request: Request, server_id: int, req: ProtocolRequest):
    """Create a protocol backup archive on the remote server."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    if not is_valid_protocol(req.protocol):
        return JSONResponse({'error': 'Unknown protocol'}, status_code=400)
    try:
        data = await load_data_async()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        container = protocol_container_name(req.protocol)
        if not container:
            return JSONResponse({'error': 'Unknown protocol'}, status_code=400)
        server = data['servers'][server_id]

        def _do_create():
            ssh = get_ssh(server)
            ssh.connect()
            try:
                return BackupManager(ssh).create_backup(req.protocol, container)
            finally:
                ssh.disconnect()

        result = await asyncio.to_thread(_do_create)
        if result.get('status') == 'error':
            return JSONResponse({'error': result.get('message', 'Failed to create backup')}, status_code=500)
        return result
    except Exception as e:
        logger.exception("Error creating protocol backup")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/backups/download', tags=["Protocols"])
async def api_protocol_backup_download(request: Request, server_id: int, req: BackupDownloadRequest):
    """Download one remote protocol backup archive through the panel."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    if not is_valid_protocol(req.protocol):
        return JSONResponse({'error': 'Unknown protocol'}, status_code=400)
    manager = BackupManager(None)
    safe_proto = manager.safe_protocol(req.protocol)
    filename = manager.safe_filename(req.filename)
    if not filename:
        return JSONResponse({'error': 'Invalid backup filename'}, status_code=400)
    ssh = None
    tmp_path = None
    tmp_remote = f'/tmp/{filename}'
    remote_path = f'{manager.BACKUP_ROOT}/{safe_proto}/{filename}'
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        ssh = get_ssh(server)
        ssh.connect()
        quoted_remote = shlex.quote(remote_path)
        quoted_tmp = shlex.quote(tmp_remote)
        _, err, code = ssh.run_sudo_command(
            f"test -f {quoted_remote} && cp {quoted_remote} {quoted_tmp} && chmod 0644 {quoted_tmp}"
        )
        if code != 0:
            return JSONResponse({'error': err or 'Backup not found'}, status_code=404)
        fd, tmp_path = tempfile.mkstemp(prefix='amnezia-backup-', suffix='.tar.gz')
        os.close(fd)
        sftp = ssh.client.open_sftp()
        try:
            sftp.get(tmp_remote, tmp_path)
        finally:
            sftp.close()
            ssh.run_sudo_command(f"rm -f {quoted_tmp}")
            ssh.disconnect()
            ssh = None
        return FileResponse(
            tmp_path,
            media_type='application/gzip',
            filename=filename,
            background=BackgroundTask(lambda p=tmp_path: os.path.exists(p) and os.remove(p)),
        )
    except Exception as e:
        logger.exception("Error downloading protocol backup")
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass
        return JSONResponse({'error': str(e)}, status_code=500)
    finally:
        if ssh:
            ssh.disconnect()


WG_BACKUP_BASES = {'awg', 'awg2', 'awg3', 'awg_legacy', 'wireguard'}


def _safe_conf_filename(name: str, used: set) -> str:
    base = re.sub(r'[^\w.\-]+', '_', str(name or '').strip(), flags=re.UNICODE).strip('._') or 'client'
    if len(base) > 80:
        base = base[:80]
    candidate = f'{base}.conf'
    idx = 2
    while candidate.lower() in used:
        candidate = f'{base}_{idx}.conf'
        idx += 1
    used.add(candidate.lower())
    return candidate


@app.post('/api/servers/{server_id}/backups/restore', tags=["Protocols"])
async def api_protocol_backup_restore(request: Request, server_id: int, req: BackupDownloadRequest):
    """Restore a protocol backup archive into the remote container/host paths."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    if not is_valid_protocol(req.protocol):
        return JSONResponse({'error': 'Unknown protocol'}, status_code=400)
    try:
        data = await load_data_async()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        container = protocol_container_name(req.protocol)
        if not container:
            return JSONResponse({'error': 'Unknown protocol'}, status_code=400)
        server = data['servers'][server_id]

        def _do_restore():
            ssh = get_ssh(server)
            ssh.connect()
            try:
                return BackupManager(ssh).restore_backup(req.protocol, container, req.filename)
            finally:
                ssh.disconnect()

        result = await asyncio.to_thread(_do_restore)
        if result.get('status') == 'error':
            return JSONResponse({'error': result.get('message', 'Failed to restore backup')}, status_code=500)
        return result
    except Exception as e:
        logger.exception("Error restoring protocol backup")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.get('/api/servers/{server_id}/migrate/export', tags=["Servers"])
async def api_server_migrate_export(
    request: Request,
    server_id: int,
    include_protocols: bool = True,
):
    """Export users/connections (+ protocol state) for domain-preserving server migration."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = await load_data_async()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        from managers.migrate_manager import export_migrate_zip

        def _do_export():
            ssh = None
            try:
                if include_protocols:
                    ssh = get_ssh(server)
                    ssh.connect()
                return export_migrate_zip(
                    ssh,
                    data,
                    server_id,
                    include_protocol_backups=include_protocols,
                    protocol_container_name_fn=protocol_container_name,
                )
            finally:
                if ssh:
                    ssh.disconnect()

        zip_bytes, summary = await asyncio.to_thread(_do_export)
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        safe_name = _ascii_filename_component(
            server.get('name') or server.get('host') or 'server',
            fallback='server',
        )
        filename = f'amnezia-migrate-{safe_name}-{stamp}.zip'
        headers = {
            'Content-Disposition': f'attachment; filename="{filename}"',
            'X-Migrate-Users': str(summary.get('users', 0)),
            'X-Migrate-Connections': str(summary.get('connections', 0)),
            'X-Migrate-Protocols': ','.join(
                _ascii_filename_component(p, fallback='proto')
                for p in (summary.get('protocols') or [])
            ),
        }
        return StreamingResponse(io.BytesIO(zip_bytes), media_type='application/zip', headers=headers)
    except Exception as e:
        logger.exception('Server migrate export failed')
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/migrate/import', tags=["Servers"])
async def api_server_migrate_import(
    request: Request,
    server_id: int,
    file: UploadFile = File(...),
    restore_protocols: bool = True,
):
    """Import migrate ZIP onto this server (remap users/connections, restore protocol state)."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        content = await file.read()
        if not content:
            return JSONResponse({'error': 'Empty file'}, status_code=400)
        from managers.migrate_manager import import_migrate_zip

        async with DATA_LOCK:
            data = load_data()
            if server_id >= len(data['servers']):
                return JSONResponse({'error': 'Server not found'}, status_code=404)
            server = data['servers'][server_id]

            def _do_import():
                ssh = None
                try:
                    if restore_protocols:
                        ssh = get_ssh(server)
                        ssh.connect()
                    return import_migrate_zip(
                        ssh,
                        data,
                        server_id,
                        content,
                        restore_protocols=restore_protocols,
                        protocol_container_name_fn=protocol_container_name,
                    )
                finally:
                    if ssh:
                        ssh.disconnect()

            result = await asyncio.to_thread(_do_import)
            save_data(data)
        return {'status': 'success', **result}
    except Exception as e:
        logger.exception('Server migrate import failed')
        return JSONResponse({'error': str(e)}, status_code=400)


class AivpnSettingsRequest(BaseModel):
    enabled: Optional[bool] = None
    strategy: Optional[str] = None  # stealth | balanced | speed
    probe: Optional[bool] = None


@app.get('/api/servers/{server_id}/aivpn', tags=["Servers"])
async def api_aivpn_get(request: Request, server_id: int, probe: bool = False):
    """AIVPN settings + ranked protocol recommendation for this server."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    from managers.aivpn_manager import get_aivpn_settings, pick_protocol
    data = await load_data_async()
    if server_id >= len(data['servers']):
        return JSONResponse({'error': 'Server not found'}, status_code=404)
    server = data['servers'][server_id]
    settings = get_aivpn_settings(server)

    live_status = {}
    try:
        # Reuse last known protocol metadata; optional live SSH probe of ports only.
        for key, info in (server.get('protocols') or {}).items():
            if isinstance(info, dict):
                live_status[key] = {
                    'installed': bool(info.get('installed')),
                    'port': info.get('port'),
                    'container_running': bool(info.get('running')),
                    'container_exists': bool(info.get('installed')),
                }
    except Exception:
        pass

    do_probe = bool(probe) if probe else bool(settings.get('probe'))
    picked = await asyncio.to_thread(
        pick_protocol,
        server,
        strategy=settings.get('strategy'),
        probe=do_probe,
        live_status=live_status,
    )
    return {
        'settings': settings,
        'recommendation': picked,
        'connect_domain': get_server_connect_host(server, (picked or {}).get('protocol')),
    }


@app.post('/api/servers/{server_id}/aivpn', tags=["Servers"])
async def api_aivpn_save(request: Request, server_id: int, req: AivpnSettingsRequest):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    from managers.aivpn_manager import set_aivpn_settings, pick_protocol, get_aivpn_settings
    async with DATA_LOCK:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        settings = set_aivpn_settings(
            server,
            enabled=req.enabled,
            strategy=req.strategy,
            probe=req.probe,
        )
        save_data(data)
    picked = pick_protocol(server, probe=False)
    return {'status': 'success', 'settings': settings, 'recommendation': picked}


@app.post('/api/servers/{server_id}/backups/export-clients', tags=["Protocols"])
async def api_protocol_export_clients(request: Request, server_id: int, req: ProtocolRequest):
    """Download a ZIP with all reconstructable WireGuard/AWG client .conf files."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    if not is_valid_protocol(req.protocol):
        return JSONResponse({'error': 'Unknown protocol'}, status_code=400)
    base = protocol_base(req.protocol)
    if base not in WG_BACKUP_BASES:
        return JSONResponse(
            {'error': 'Client config export is only available for WireGuard / AmneziaWG'},
            status_code=400,
        )

    ssh = None
    tmp_path = None
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        proto_info = server.get('protocols', {}).get(req.protocol, {})
        port = proto_info.get('port', '55424')
        ssh = get_ssh(server)
        ssh.connect()
        manager = get_protocol_manager(ssh, req.protocol)
        clients = _manager_call(manager, 'get_clients', req.protocol) or []

        fd, tmp_path = tempfile.mkstemp(prefix='amnezia-clients-', suffix='.zip')
        os.close(fd)
        used_names = set()
        exported = 0
        skipped = []

        with zipfile.ZipFile(tmp_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
            for client in clients:
                ud = client.get('userData') or {}
                client_id = client.get('clientId') or ''
                client_name = ud.get('clientName') or client_id[:12] or 'client'
                if ud.get('externalClient') or not ud.get('clientPrivateKey'):
                    skipped.append(f'{client_name}: no private key (external/native)')
                    continue
                try:
                    config = _manager_call(
                        manager, 'get_client_config', req.protocol, client_id, get_server_connect_host(server, req.protocol), port
                    )
                except Exception as exc:
                    skipped.append(f'{client_name}: {exc}')
                    continue
                if not config:
                    skipped.append(f'{client_name}: empty config')
                    continue
                filename = _safe_conf_filename(client_name, used_names)
                zf.writestr(filename, config if config.endswith('\n') else config + '\n')
                exported += 1

            readme = [
                f'Protocol: {req.protocol}',
                f'Server: {server.get("name") or server.get("host")}',
                f'Host: {server.get("host")}',
                f'Exported: {exported}',
                f'Skipped: {len(skipped)}',
                '',
            ]
            if skipped:
                readme.append('Skipped clients:')
                readme.extend(f'- {line}' for line in skipped)
            zf.writestr('README.txt', '\n'.join(readme) + '\n')

        ssh.disconnect()
        ssh = None

        if exported == 0:
            try:
                os.remove(tmp_path)
            except Exception:
                pass
            tmp_path = None
            return JSONResponse(
                {'error': 'No client configs could be exported (missing private keys?)'},
                status_code=404,
            )

        safe_proto = BackupManager.safe_protocol(req.protocol)
        stamp = datetime.now().strftime('%Y%m%dT%H%M%S')
        download_name = f'{safe_proto}-clients-{stamp}.zip'
        return FileResponse(
            tmp_path,
            media_type='application/zip',
            filename=download_name,
            background=BackgroundTask(lambda p=tmp_path: os.path.exists(p) and os.remove(p)),
        )
    except Exception as e:
        logger.exception("Error exporting client configs")
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass
        return JSONResponse({'error': str(e)}, status_code=500)
    finally:
        if ssh:
            ssh.disconnect()


@app.post('/api/servers/{server_id}/container/toggle', tags=["Protocols"])
async def api_container_toggle(request: Request, server_id: int, req: ProtocolRequest):
    """Start or stop a protocol Docker container."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        container = protocol_container_name(req.protocol)
        if not container:
            return JSONResponse({'error': 'Unknown protocol'}, status_code=400)
        server = data['servers'][server_id]
        ssh = get_ssh(server)
        ssh.connect()
        base = protocol_base(req.protocol)
        if base in NON_DOCKER_PROTOCOLS:
            manager = get_protocol_manager(ssh, req.protocol)
            is_running = manager.check_container_running(req.protocol)
            if is_running:
                manager.stop_service()
                action = 'stopped'
            else:
                manager.start_service()
                action = 'started'
            diag = manager.get_container_diagnostics(req.protocol)
            error = diag.get('error_summary') or ''
            recent_logs = diag.get('recent_logs') or ''
            if action == 'started' and not diag.get('running'):
                ssh.disconnect()
                return JSONResponse({
                    'error': error or 'Mieru failed to start',
                    'action': action,
                    'container': container,
                    'recent_logs': recent_logs,
                }, status_code=400)
            ssh.disconnect()
            return {
                'status': 'success',
                'action': action,
                'container': container,
                'error': error,
                'recent_logs': recent_logs,
            }
        # Check current state
        out, _, _ = ssh.run_sudo_command(
            f"docker inspect -f '{{{{.State.Running}}}}' {container} 2>/dev/null"
        )
        is_running = out.strip().lower() == 'true'
        if is_running:
            ssh.run_sudo_command(f"docker stop {container}")
            action = 'stopped'
        else:
            if protocol_base(req.protocol) == 'hysteria':
                from managers.hysteria_manager import HysteriaManager
                mgr = HysteriaManager(ssh, req.protocol)
                meta = mgr._read_metadata()
                port = int(meta.get('port') or mgr.DEFAULT_PORT)
                mgr._write_config_from_clients(port)
                mgr._start_container(port)
            else:
                ssh.run_sudo_command(f"docker start {container}")
            action = 'started'
        error = ''
        recent_logs = ''
        if protocol_base(req.protocol) == 'hysteria':
            from managers.hysteria_manager import HysteriaManager
            mgr = HysteriaManager(ssh, req.protocol)
            diag = mgr.get_container_diagnostics(req.protocol)
            error = diag.get('error_summary') or ''
            recent_logs = diag.get('recent_logs') or ''
            if action == 'started' and not diag.get('running'):
                ssh.disconnect()
                return JSONResponse({
                    'error': error or 'Hysteria failed to start',
                    'action': action,
                    'container': container,
                    'recent_logs': recent_logs,
                }, status_code=400)
        ssh.disconnect()
        return {
            'status': 'success',
            'action': action,
            'container': container,
            'error': error,
            'recent_logs': recent_logs,
        }
    except Exception as e:
        logger.exception("Error toggling container")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/container/logs', tags=["Protocols"])
async def api_container_logs(request: Request, server_id: int, req: ContainerLogsRequest):
    """Fetch recent Docker logs for a protocol container."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        if not is_valid_protocol(req.protocol):
            return JSONResponse({'error': 'Unknown protocol'}, status_code=400)
        server = data['servers'][server_id]
        container = protocol_container_name(req.protocol)
        ssh = get_ssh(server)
        ssh.connect()
        if protocol_base(req.protocol) in NON_DOCKER_PROTOCOLS:
            mgr = get_protocol_manager(ssh, req.protocol)
            logs = mgr.get_logs(req.protocol, tail=req.tail or 200)
            diag = mgr.get_container_diagnostics(req.protocol)
            ssh.disconnect()
            return {
                'status': 'success',
                'protocol': req.protocol,
                'container': container,
                'logs': logs,
                'running': bool(diag.get('running')),
                'error': diag.get('error_summary') or '',
                'container_status': diag.get('status') or '',
            }
        if protocol_base(req.protocol) == 'hysteria':
            from managers.hysteria_manager import HysteriaManager
            mgr = HysteriaManager(ssh, req.protocol)
            logs = mgr.get_logs(req.protocol, tail=req.tail or 200)
            diag = mgr.get_container_diagnostics(req.protocol)
            ssh.disconnect()
            return {
                'status': 'success',
                'protocol': req.protocol,
                'container': container,
                'logs': logs,
                'running': bool(diag.get('running')),
                'error': diag.get('error_summary') or '',
                'exit_code': diag.get('exit_code'),
                'container_status': diag.get('status') or '',
            }
        tail = max(20, min(int(req.tail or 200), 2000))
        out, err, _ = ssh.run_sudo_command(
            f"docker logs --tail {tail} --timestamps {shlex.quote(container)} 2>&1",
            timeout=30,
        )
        running_out, _, _ = ssh.run_sudo_command(
            f"docker inspect -f '{{{{.State.Running}}}}' {shlex.quote(container)} 2>/dev/null"
        )
        ssh.disconnect()
        return {
            'status': 'success',
            'protocol': req.protocol,
            'container': container,
            'logs': (out or err or '').strip(),
            'running': running_out.strip().lower() == 'true',
            'error': '',
        }
    except Exception as e:
        logger.exception("Error reading container logs")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.get('/api/servers/{server_id}/container/logs/stream', tags=["Protocols"])
async def api_container_logs_stream(request: Request, server_id: int, protocol: str = 'awg', tail: int = 100):
    """SSE stream of docker logs (polls every ~1.5s for new lines)."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    if server_id >= len(data['servers']):
        return JSONResponse({'error': 'Server not found'}, status_code=404)
    if not is_valid_protocol(protocol):
        return JSONResponse({'error': 'Unknown protocol'}, status_code=400)
    server = data['servers'][server_id]
    container = protocol_container_name(protocol)
    if not container:
        return JSONResponse({'error': 'Unknown protocol'}, status_code=400)
    tail = max(20, min(int(tail or 100), 500))

    async def event_gen():
        last_text = ''
        try:
            while True:
                if await request.is_disconnected():
                    break

                def _fetch():
                    ssh = get_ssh(server)
                    ssh.connect()
                    try:
                        if protocol_base(protocol) in NON_DOCKER_PROTOCOLS:
                            mgr = get_protocol_manager(ssh, protocol)
                            logs = mgr.get_logs(protocol, tail=tail)
                            diag = mgr.get_container_diagnostics(protocol)
                            state = '|'.join([
                                diag.get('status') or '',
                                'true' if diag.get('running') else 'false',
                                '',
                                diag.get('error_summary') or '',
                            ])
                            return logs, state
                        out, err, _ = ssh.run_sudo_command(
                            f"docker logs --tail {tail} --timestamps {shlex.quote(container)} 2>&1",
                            timeout=25,
                        )
                        running_out, _, _ = ssh.run_sudo_command(
                            f"docker inspect -f '{{{{.State.Status}}}}|{{{{.State.Running}}}}|{{{{.State.ExitCode}}}}|{{{{.State.Error}}}}' {shlex.quote(container)} 2>/dev/null"
                        )
                        return (out or err or '').strip(), (running_out or '').strip()
                    finally:
                        ssh.disconnect()

                logs, state = await asyncio.to_thread(_fetch)
                if logs != last_text:
                    last_text = logs
                    payload = json.dumps({
                        'logs': logs,
                        'state': state,
                        'container': container,
                        'ts': time.time(),
                    }, ensure_ascii=False)
                    yield f"data: {payload}\n\n"
                else:
                    yield f": ping\n\n"
                await asyncio.sleep(1.5)
        except asyncio.CancelledError:
            return
        except Exception as e:
            payload = json.dumps({'error': str(e)}, ensure_ascii=False)
            yield f"data: {payload}\n\n"

    return StreamingResponse(
        event_gen(),
        media_type='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no',
        },
    )


@app.post('/api/servers/{server_id}/server_config', tags=["Protocols"])
async def api_server_config(request: Request, server_id: int, req: ProtocolRequest):
    """Get the raw server-side WireGuard/Xray configuration."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        ssh = get_ssh(server)
        ssh.connect()
        if protocol_base(req.protocol) == 'xray':
            from managers.xray_manager import XrayManager
            mgr = XrayManager(ssh, req.protocol)
            data_json = mgr._get_server_json()
            import json as _json
            config = _json.dumps(data_json, indent=2, ensure_ascii=False) if data_json else ''
        elif protocol_base(req.protocol) == 'telemt':
            from managers.telemt_manager import TelemtManager
            mgr = TelemtManager(ssh, req.protocol)
            config = mgr._get_server_config()
        elif protocol_base(req.protocol) == 'wireguard':
            from managers.wireguard_manager import WireGuardManager
            mgr = WireGuardManager(ssh)
            config = mgr._get_server_config()
        elif protocol_base(req.protocol) == 'nginx':
            from managers.nginx_manager import NginxManager
            mgr = NginxManager(ssh, req.protocol)
            config = mgr._get_server_config(req.protocol)
        elif protocol_base(req.protocol) == 'hysteria':
            from managers.hysteria_manager import HysteriaManager
            mgr = HysteriaManager(ssh, req.protocol)
            config = mgr.get_server_config(req.protocol)
        elif protocol_base(req.protocol) == 'naiveproxy':
            from managers.naiveproxy_manager import NaiveProxyManager
            mgr = NaiveProxyManager(ssh, req.protocol)
            config = mgr.get_server_config(req.protocol)
        else:
            mgr = AWGManager(ssh)
            config = mgr._get_server_config(req.protocol)
        ssh.disconnect()
        return {'config': config}
    except Exception as e:
        logger.exception("Error getting server config")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/server_config/save', tags=["Protocols"])
async def api_server_config_save(request: Request, server_id: int, req: ServerConfigSaveRequest):
    """Save the raw server-side WireGuard/Xray configuration and apply changes."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        ssh = get_ssh(server)
        ssh.connect()
        if protocol_base(req.protocol) == 'xray':
            from managers.xray_manager import XrayManager
            mgr = XrayManager(ssh, req.protocol)
            import json as _json
            try:
                data_json = _json.loads(req.config)
            except Exception as e:
                ssh.disconnect()
                return JSONResponse({'error': f'Invalid JSON format: {str(e)}'}, status_code=400)
            mgr._save_server_json(data_json)
        elif protocol_base(req.protocol) == 'telemt':
            from managers.telemt_manager import TelemtManager
            mgr = TelemtManager(ssh, req.protocol)
            mgr.save_server_config(req.protocol, req.config)
        elif protocol_base(req.protocol) == 'wireguard':
            from managers.wireguard_manager import WireGuardManager
            mgr = WireGuardManager(ssh)
            mgr.save_server_config(req.config)
        elif protocol_base(req.protocol) == 'nginx':
            from managers.nginx_manager import NginxManager
            mgr = NginxManager(ssh, req.protocol)
            mgr.save_server_config(req.protocol, req.config)
        elif protocol_base(req.protocol) == 'hysteria':
            from managers.hysteria_manager import HysteriaManager
            mgr = HysteriaManager(ssh, req.protocol)
            mgr.save_server_config(req.protocol, req.config)
        elif protocol_base(req.protocol) == 'naiveproxy':
            from managers.naiveproxy_manager import NaiveProxyManager
            mgr = NaiveProxyManager(ssh, req.protocol)
            mgr.save_server_config(req.protocol, req.config)
        else:
            mgr = AWGManager(ssh)
            mgr.save_server_config(req.protocol, req.config)
        ssh.disconnect()
        return {'status': 'success'}
    except Exception as e:
        logger.exception("Error saving server config")
        return JSONResponse({'error': str(e)}, status_code=500)





@app.post('/api/servers/{server_id}/nginx/site', tags=["Protocols"])
async def api_nginx_site_get(request: Request, server_id: int, req: ProtocolRequest):
    """Return editable NGINX site index.html."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        if protocol_base(req.protocol) != 'nginx':
            return JSONResponse({'error': 'Invalid protocol type'}, status_code=400)
        server = data['servers'][server_id]
        ssh = get_ssh(server)
        ssh.connect()
        from managers.nginx_manager import NginxManager
        mgr = NginxManager(ssh, req.protocol)
        html = mgr.get_site_index(req.protocol)
        ssh.disconnect()
        return {'status': 'success', 'html': html}
    except Exception as e:
        logger.exception("Error getting NGINX site")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/nginx/site/save', tags=["Protocols"])
async def api_nginx_site_save(request: Request, server_id: int, req: NginxSiteSaveRequest):
    """Save editable NGINX site index.html."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        if protocol_base(req.protocol) != 'nginx':
            return JSONResponse({'error': 'Invalid protocol type'}, status_code=400)
        server = data['servers'][server_id]
        ssh = get_ssh(server)
        ssh.connect()
        from managers.nginx_manager import NginxManager
        mgr = NginxManager(ssh, req.protocol)
        mgr.save_site_index(req.protocol, req.html)
        ssh.disconnect()
        return {'status': 'success'}
    except Exception as e:
        logger.exception("Error saving NGINX site")
        return JSONResponse({'error': str(e)}, status_code=500)

@app.get('/api/servers/{server_id}/connections', tags=["Connections"])
async def api_get_connections(request: Request, server_id: int, protocol: str = Query(default='awg')):
    if not protocol:
        protocol = 'awg'
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = await load_data_async()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        cache_key = f'conn:{server_id}:{protocol}'
        clients = api_cache.get(cache_key, ttl=5)
        if clients is None:
            def _fetch_clients(ssh):
                manager = get_protocol_manager(ssh, protocol)
                return _manager_call(manager, 'get_clients', protocol) or []

            clients = await asyncio.to_thread(run_ssh, server, _fetch_clients)
            api_cache.set(cache_key, clients)
        else:
            clients = [dict(c) for c in clients]

        # Enrich with user info from user_connections
        user_conns = data.get('user_connections', [])
        users = data.get('users', [])
        users_map = {u['id']: u for u in users}
        for client in clients:
            cid = client.get('clientId', '')
            ud = client.get('userData')
            if not isinstance(ud, dict):
                ud = {}
                client['userData'] = ud
            for uc in user_conns:
                if uc.get('client_id') == cid and uc.get('server_id') == server_id and uc.get('protocol') == protocol:
                    uid = uc.get('user_id')
                    u = users_map.get(uid)
                    if u:
                        client['assigned_user'] = u['username']
                        client['assigned_user_id'] = uid
                    conn_name = (uc.get('name') or '').strip()
                    current_name = (ud.get('clientName') or '').strip()
                    if conn_name and (
                        not current_name
                        or current_name.startswith('External (')
                        or current_name == 'External (native app)'
                    ):
                        ud['clientName'] = conn_name
                    break
        return {'clients': clients}
    except Exception as e:
        logger.exception("Error getting connections")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/connections/add', tags=["Connections"])
async def api_add_connection(request: Request, server_id: int, req: AddConnectionRequest):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)

        protocol = req.protocol
        server = data['servers'][server_id]
        if protocol_base(protocol) == 'aivpn':
            from managers.aivpn_manager import resolve_provision_protocol
            protocol = resolve_provision_protocol(server, 'aivpn')

        if protocol_base(protocol) == 'xui':
            from managers.xui_api import xui_create_vless_config
            from managers.xui_servers import get_xui_server, ensure_xui_servers
            ensure_xui_servers(data.setdefault('settings', {}))
            panel = get_xui_server(data.get('settings') or {}, req.xui_panel_id)
            panel_id = (panel or {}).get('id') or ''
            inbound = req.xui_inbound_id or (panel or {}).get('default_inbound_id') or None
            created = await xui_create_vless_config(
                data.get('settings', {}),
                name=req.name,
                inbound_id=inbound,
                panel_id=panel_id or None,
            )
            result = {'client_id': created['client_id'], 'config': created.get('config') or ''}
            if result.get('config'):
                sub = created.get('subscription_url') or ''
                result['vpn_link'] = sub if sub else (
                    result['config'] if str(result['config']).startswith('http') else generate_vpn_link(result['config'])
                )
            if req.user_id and result.get('client_id'):
                conn = {
                    'id': str(uuid.uuid4()),
                    'user_id': req.user_id,
                    'server_id': server_id,
                    'protocol': 'xui',
                    'client_id': result['client_id'],
                    'name': req.name,
                    'xui_panel_id': panel_id,
                    'created_at': datetime.now().isoformat(),
                }
                data['user_connections'].append(conn)
                save_data(data)
            return result

        proto_info = server.get('protocols', {}).get(protocol, {})
        port = proto_info.get('port', '55424')
        ssh = get_ssh(server)
        ssh.connect()
        manager = get_protocol_manager(ssh, protocol)
        
        if protocol_base(protocol) == 'telemt':
            result = manager.add_client(
                protocol, req.name, get_server_connect_host(server, protocol), port,
                telemt_quota=req.telemt_quota,
                telemt_max_ips=req.telemt_max_ips,
                telemt_expiry=req.telemt_expiry,
                secret=req.telemt_secret,
                user_ad_tag=req.telemt_ad_tag,
                max_tcp_conns=req.telemt_max_conns
            )
        elif protocol_base(protocol) == 'wireguard':
            result = manager.add_client(req.name, get_server_connect_host(server, protocol))
        else:
            result = manager.add_client(protocol, req.name, get_server_connect_host(server, protocol), port)
        ssh.disconnect()
        invalidate_server_reads(server_id, protocol)

        if result.get('config'):
            result['vpn_link'] = generate_vpn_link(result['config'])
        result['protocol'] = protocol

        # Link connection to user if specified
        if req.user_id and result.get('client_id'):
            conn = {
                'id': str(uuid.uuid4()),
                'user_id': req.user_id,
                'server_id': server_id,
                'protocol': protocol,
                'client_id': result['client_id'],
                'name': req.name,
                'created_at': datetime.now().isoformat(),
            }
            data['user_connections'].append(conn)
            save_data(data)

        return result
    except Exception as e:
        logger.exception("Error adding connection")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/connections/remove', tags=["Connections"])
async def api_remove_connection(request: Request, server_id: int, req: ConnectionActionRequest):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if not req.client_id:
            return JSONResponse({'error': 'Client ID is required'}, status_code=400)

        if protocol_base(req.protocol) == 'xui':
            from managers.xui_api import xui_delete_client
            await xui_delete_client(data.get('settings', {}), req.client_id)
        else:
            if server_id >= len(data['servers']):
                return JSONResponse({'error': 'Server not found'}, status_code=404)
            server = data['servers'][server_id]
            ssh = get_ssh(server)
            ssh.connect()
            manager = get_protocol_manager(ssh, req.protocol)
            _manager_call(manager, 'remove_client', req.protocol, req.client_id)
            ssh.disconnect()
        invalidate_server_reads(server_id, req.protocol)
        # Remove from user_connections
        data['user_connections'] = [
            c for c in data.get('user_connections', [])
            if not (c.get('client_id') == req.client_id and c.get('server_id') == server_id
                    and c.get('protocol') == req.protocol)
        ]
        save_data(data)
        return {'status': 'success'}
    except Exception as e:
        logger.exception("Error removing connection")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/connections/edit', tags=["Connections"])
async def api_edit_connection(request: Request, server_id: int, req: EditConnectionRequest):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        
        ssh = get_ssh(server)
        ssh.connect()
        manager = get_protocol_manager(ssh, req.protocol)
        
        edit_params = {}
        if protocol_base(req.protocol) == 'telemt':
            edit_params['telemt_quota'] = req.telemt_quota
            edit_params['telemt_max_ips'] = req.telemt_max_ips
            edit_params['telemt_expiry'] = req.telemt_expiry
            edit_params['secret'] = req.telemt_secret
            edit_params['user_ad_tag'] = req.telemt_ad_tag
            edit_params['max_tcp_conns'] = req.telemt_max_conns
            
        result = manager.edit_client(req.protocol, req.client_id, edit_params)
        ssh.disconnect()
        invalidate_server_reads(server_id, req.protocol)
        return result
    except Exception as e:
        logger.exception("Error editing connection")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/connections/config', tags=["Connections"])
async def api_get_connection_config(request: Request, server_id: int, req: ConnectionActionRequest):
    # Admin panel endpoint (server/users UI). Accept session admin/support OR Bearer token.
    admin = _check_admin(request)
    user = admin or get_current_user(request)
    if not user:
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if not req.client_id:
            return JSONResponse({'error': 'Client ID is required'}, status_code=400)
        # Non-admin users can only view their own connections
        if not admin and user.get('role') == 'user':
            owned = any(
                c for c in data.get('user_connections', [])
                if c.get('client_id') == req.client_id and c.get('server_id') == server_id and c.get('user_id') == user['id']
            )
            if not owned:
                return JSONResponse({'error': 'Forbidden'}, status_code=403)
        elif not admin and user.get('role') not in ('admin', 'support'):
            return JSONResponse({'error': 'Forbidden'}, status_code=403)

        if protocol_base(req.protocol) == 'xui':
            from managers.xui_api import xui_get_config
            config = await xui_get_config(data.get('settings', {}), req.client_id)
            vpn_link = config if str(config).startswith('http') else (generate_vpn_link(config) if config else '')
            return {'config': config, 'vpn_link': vpn_link}

        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        proto_info = server.get('protocols', {}).get(req.protocol, {})
        port = proto_info.get('port', '55424')
        ssh = get_ssh(server)
        ssh.connect()
        manager = get_protocol_manager(ssh, req.protocol)
        config = _manager_call(manager, 'get_client_config', req.protocol, req.client_id, get_server_connect_host(server, req.protocol), port)
        ssh.disconnect()
        vpn_link = generate_vpn_link(config) if config else ''
        return {'config': config, 'vpn_link': vpn_link}
    except Exception as e:
        logger.exception("Error getting connection config")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/connections/move', tags=["Connections"])
async def api_move_connections(request: Request, server_id: int, req: MoveConnectionsRequest):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    if not req.client_ids:
        return JSONResponse({'error': 'No connections selected'}, status_code=400)
    try:
        result = await asyncio.to_thread(
            _move_connections_sync,
            server_id,
            req.target_server_id,
            req.protocol,
            req.client_ids,
            req.target_protocol,
            bool(req.delete_source),
        )
        if not result.get('moved'):
            return JSONResponse(
                {'error': result.get('message') or 'Move failed', **result},
                status_code=400,
            )
        invalidate_server_reads(server_id, req.protocol)
        invalidate_server_reads(req.target_server_id, req.target_protocol or req.protocol)
        return result
    except ValueError as e:
        return JSONResponse({'error': str(e)}, status_code=400)
    except Exception as e:
        logger.exception('Error moving connections')
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/servers/{server_id}/connections/toggle', tags=["Connections"])
async def api_toggle_connection(request: Request, server_id: int, req: ToggleConnectionRequest):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        if not req.client_id:
            return JSONResponse({'error': 'Client ID is required'}, status_code=400)
        if protocol_base(req.protocol) == 'xui':
            from managers.xui_api import xui_toggle_client
            await xui_toggle_client(data.get('settings', {}), req.client_id, req.enable)
            return {'status': 'success'}
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        ssh = get_ssh(server)
        ssh.connect()
        manager = get_protocol_manager(ssh, req.protocol)
        _manager_call(manager, 'toggle_client', req.protocol, req.client_id, req.enable)
        ssh.disconnect()
        invalidate_server_reads(server_id, req.protocol)
        return {'status': 'success'}
    except Exception as e:
        logger.exception("Error toggling connection")
        return JSONResponse({'error': str(e)}, status_code=500)


# ======================== USER API (admin only) ========================

@app.get('/api/users', tags=["Users"])
async def api_list_users(request: Request, search: str = '', page: int = 1, size: int = 10):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = await load_data_async()
    all_users = data.get('users', [])
    conns = data.get('user_connections', [])
    conn_counts = Counter(c.get('user_id') for c in conns if c.get('user_id'))
    
    # Filter
    filtered = []
    search = search.lower()
    for u in all_users:
        if search:
            match = (search in u['username'].lower() or 
                     (u.get('email') and search in u['email'].lower()) or 
                     (u.get('telegramId') and search in str(u['telegramId']).lower()))
            if not match:
                continue
        filtered.append(u)
        
    total = len(filtered)
    start = (page - 1) * size
    end = start + size
    page_items = filtered[start:end]
    
    users = []
    for u in page_items:
        users.append({
            'id': u['id'], 'username': u['username'], 'role': u['role'],
            'enabled': u.get('enabled', True),
            'created_at': u.get('created_at', ''),
            'telegramId': u.get('telegramId'),
            'email': u.get('email'),
            'description': u.get('description'),
            'connections_count': conn_counts.get(u['id'], 0),
            'traffic_used': u.get('traffic_used', 0),
            'traffic_total': u.get('traffic_total', 0),
            'traffic_limit': u.get('traffic_limit', 0),
            'traffic_reset_strategy': u.get('traffic_reset_strategy', 'never'),
            'last_reset_at': u.get('last_reset_at'),
            "expiration_date": u.get("expiration_date"),
            "expire_after_first_use": bool(u.get("expire_after_first_use")),
            "expiration_days": int(u.get("expiration_days") or 0),
            'share_enabled': u.get('share_enabled', False),
            'share_token': u.get('share_token'),
            'has_share_password': bool(u.get('share_password_hash')),
            'source': (
                'Remnawave' if u.get('remnawave_uuid')
                else ('3x-ui' if u.get('xui_email') else 'Local')
            )
        })
    return {
        'users': users,
        'total': total,
        'page': page,
        'size': size,
        'pages': (total + size - 1) // size
    }


@app.post('/api/users/add', tags=["Users"])
async def api_add_user(request: Request, req: AddUserRequest):
    cur = get_current_user(request)
    if not cur or cur['role'] != 'admin':
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        lang = request.cookies.get('lang', 'ru')
        # Check duplicate
        if any(u['username'] == req.username for u in data.get('users', [])):
            return JSONResponse({'error': _t('user_exists', lang)}, status_code=400)
        if req.role not in ('admin', 'support', 'user'):
            return JSONResponse({'error': 'Invalid role'}, status_code=400)
        new_user = {
            'id': str(uuid.uuid4()),
            'username': req.username,
            'password_hash': hash_password(req.password),
            'role': req.role,
            'telegramId': req.telegramId,
            'email': req.email,
            'description': req.description,
            'traffic_limit': int(req.traffic_limit * 1024**3) if req.traffic_limit else 0,
            'traffic_reset_strategy': req.traffic_reset_strategy or 'never',
            'traffic_used': 0,
            'traffic_total': 0,
            'last_reset_at': datetime.now().isoformat(),
            'expiration_date': None if req.expire_after_first_use else req.expiration_date,
            'expire_after_first_use': bool(req.expire_after_first_use),
            'expiration_days': int(req.expiration_days or 0) if req.expire_after_first_use else 0,
            'enabled': True,
            'created_at': datetime.now().isoformat(),
            'remnawave_uuid': None,
            'xui_email': None,
            'share_enabled': False,
            'share_token': secrets.token_urlsafe(16),
            'share_password_hash': None,
        }
        if new_user['expire_after_first_use'] and new_user['expiration_days'] <= 0:
            return JSONResponse({'error': 'expiration_days must be > 0 when start-after-first-use is enabled'}, status_code=400)
        data['users'].append(new_user)
        save_data(data)

        result = {'status': 'success', 'user_id': new_user['id']}

        # Auto-create connection if server & protocol specified
        if req.server_id is not None and req.protocol:
            if req.server_id < len(data['servers']):
                server = data['servers'][req.server_id]
                proto_info = server.get('protocols', {}).get(req.protocol, {})
                port = proto_info.get('port', '55424')
                conn_name = req.connection_name or f"{req.username}_vpn"
                ssh = get_ssh(server)
                ssh.connect()
                manager = get_protocol_manager(ssh, req.protocol)
                if protocol_base(req.protocol) == 'telemt':
                    conn_result = manager.add_client(
                        req.protocol, conn_name, get_server_connect_host(server, req.protocol), port,
                        telemt_quota=req.telemt_quota,
                        telemt_max_ips=req.telemt_max_ips,
                        telemt_expiry=req.telemt_expiry,
                        secret=req.telemt_secret,
                        user_ad_tag=req.telemt_ad_tag,
                        max_tcp_conns=req.telemt_max_conns
                    )
                else:
                    conn_result = manager.add_client(req.protocol, conn_name, get_server_connect_host(server, req.protocol), port)
                ssh.disconnect()

                if conn_result.get('client_id'):
                    conn = {
                        'id': str(uuid.uuid4()),
                        'user_id': new_user['id'],
                        'server_id': req.server_id,
                        'protocol': req.protocol,
                        'client_id': conn_result['client_id'],
                        'name': conn_name,
                        'created_at': datetime.now().isoformat(),
                    }
                    data = load_data()  # reload
                    data['user_connections'].append(conn)
                    save_data(data)
                    result['connection_created'] = True
                    if conn_result.get('config'):
                        result['config'] = conn_result['config']
                        result['vpn_link'] = generate_vpn_link(conn_result['config'])
        return result
    except Exception as e:
        logger.exception("Error adding user")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/users/{user_id}/update', tags=["Users"])
async def api_update_user(request: Request, user_id: str, req: UpdateUserRequest):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        user = next((u for u in data['users'] if u['id'] == user_id), None)
        if not user:
            return JSONResponse({'error': 'User not found'}, status_code=404)
            
        if req.telegramId is not None: user['telegramId'] = req.telegramId
        if req.email is not None: user['email'] = req.email
        if req.description is not None: user['description'] = req.description
        if req.traffic_limit is not None: 
            new_limit = int(req.traffic_limit * 1024**3)
            user['traffic_limit'] = new_limit
        
        if req.traffic_reset_strategy is not None:
            user['traffic_reset_strategy'] = req.traffic_reset_strategy
            user['last_reset_at'] = datetime.now().isoformat()
            
        req_fields = getattr(req, 'model_fields_set', getattr(req, '__fields_set__', set()))
        if 'expire_after_first_use' in req_fields or 'expiration_days' in req_fields or 'expiration_date' in req_fields:
            after_first = bool(req.expire_after_first_use) if req.expire_after_first_use is not None else bool(user.get('expire_after_first_use'))
            days = int(req.expiration_days) if req.expiration_days is not None else int(user.get('expiration_days') or 0)
            if after_first:
                if days <= 0:
                    return JSONResponse({'error': 'expiration_days must be > 0 when start-after-first-use is enabled'}, status_code=400)
                user['expire_after_first_use'] = True
                user['expiration_days'] = days
                # Keep existing absolute date if countdown already started; otherwise wait for first use
                if not user.get('expiration_date'):
                    user['expiration_date'] = None
                elif 'expiration_date' in req_fields and req.expiration_date:
                    # Admin can still override absolute end date after start
                    user['expiration_date'] = req.expiration_date or None
            else:
                user['expire_after_first_use'] = False
                user['expiration_days'] = 0
                if 'expiration_date' in req_fields:
                    user['expiration_date'] = req.expiration_date or None
        elif 'expiration_date' in req_fields:
            user['expiration_date'] = req.expiration_date or None
            user['expire_after_first_use'] = False
            user['expiration_days'] = 0

        if req.password:
            user['password_hash'] = hash_password(req.password)
            
        save_data(data)
        
        # Auto re-enable if traffic limit increased beyond usage
        if req.traffic_limit is not None:
            if new_limit > 0 and user.get('traffic_used', 0) < new_limit and not user.get('enabled', True):
                await perform_toggle_user(data, user_id, True)
                save_data(data)

        return {'status': 'success'}
    except Exception as e:
        logger.exception("Error updating user")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/users/{user_id}/delete', tags=["Users"])
async def api_delete_user(request: Request, user_id: str):
    cur = get_current_user(request)
    if not cur or cur['role'] != 'admin':
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    lang = request.cookies.get('lang', 'ru')
    if cur['id'] == user_id:
        return JSONResponse({'error': _t('cannot_delete_self', lang)}, status_code=400)
    try:
        data = load_data()
        success = await perform_delete_user(data, user_id)
        if not success:
            return JSONResponse({'error': 'User not found'}, status_code=404)
        save_data(data)
        return {'status': 'success'}
    except Exception as e:
        logger.exception("Error deleting user")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/users/{user_id}/toggle', tags=["Users"])
async def api_toggle_user(request: Request, user_id: str, req: ToggleUserRequest):
    cur = get_current_user(request)
    if not cur or cur['role'] != 'admin':
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        success = await perform_toggle_user(data, user_id, req.enabled)
        if not success:
            return JSONResponse({'error': 'User not found'}, status_code=404)
        save_data(data)
        return {'status': 'success', 'enabled': req.enabled}
    except Exception as e:
        logger.exception("Error toggling user")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/users/{user_id}/connections/add', tags=["Users"])
async def api_add_user_connection(request: Request, user_id: str, req: AddUserConnectionRequest):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        user = next((u for u in data['users'] if u['id'] == user_id), None)
        if not user:
            return JSONResponse({'error': 'User not found'}, status_code=404)
        protocol = req.protocol
        if protocol_base(protocol) == 'aivpn':
            from managers.aivpn_manager import resolve_provision_protocol
            if req.server_id >= len(data['servers']):
                return JSONResponse({'error': 'Server not found'}, status_code=404)
            protocol = resolve_provision_protocol(data['servers'][req.server_id], 'aivpn')

        if protocol_base(protocol) not in CLIENT_VPN_BASES:
            return JSONResponse(
                {'error': f'Protocol "{protocol}" does not support user connections'},
                status_code=400,
            )

        if protocol_base(protocol) == 'xui':
            from managers.xui_servers import get_xui_server, ensure_xui_servers
            ensure_xui_servers(data.setdefault('settings', {}))
            panel = get_xui_server(data.get('settings') or {}, req.xui_panel_id)
            if not panel:
                return JSONResponse({'error': 'Add a 3x-ui server in Settings first'}, status_code=400)
            panel_id = panel.get('id') or ''
            if req.client_id:
                from managers.xui_api import xui_get_config
                config = await xui_get_config(data.get('settings', {}), req.client_id, panel_id=panel_id)
                result = {'client_id': req.client_id, 'config': config, 'subscription_url': config if str(config).startswith('http') else ''}
            else:
                inbound = req.xui_inbound_id or panel.get('default_inbound_id') or None
                if not inbound:
                    return JSONResponse({'error': 'Select a VLESS inbound from 3x-ui'}, status_code=400)
                from managers.xui_api import xui_create_vless_config
                created = await xui_create_vless_config(
                    data.get('settings', {}),
                    name=req.name or user.get('username') or 'user',
                    inbound_id=inbound,
                    panel_id=panel_id,
                )
                result = {
                    'client_id': created['client_id'],
                    'config': created.get('config') or '',
                    'subscription_url': created.get('subscription_url') or '',
                }
            sid = req.server_id if data['servers'] and req.server_id < len(data['servers']) else 0
            if result.get('client_id'):
                conn = {
                    'id': str(uuid.uuid4()),
                    'user_id': user_id,
                    'server_id': sid,
                    'protocol': 'xui',
                    'client_id': result['client_id'],
                    'name': req.name,
                    'xui_panel_id': panel_id,
                    'created_at': datetime.now().isoformat(),
                }
                async with DATA_LOCK:
                    data = load_data()
                    data['user_connections'].append(conn)
                    save_data(data)
            resp = {'status': 'success'}
            if result.get('config'):
                resp['config'] = result['config']
                sub = result.get('subscription_url') or ''
                resp['subscription_url'] = sub
                resp['vpn_link'] = sub if sub else (
                    result['config'] if str(result['config']).startswith('http') else generate_vpn_link(result['config'])
                )
            return resp

        if req.server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][req.server_id]
        proto_info = server.get('protocols', {}).get(protocol, {})
        port = proto_info.get('port', '55424')
        ssh = get_ssh(server)
        await asyncio.to_thread(ssh.connect)
        try:
            manager = get_protocol_manager(ssh, protocol)

            if req.client_id:
                # Link existing client
                config = await asyncio.to_thread(
                    _manager_call, manager, 'get_client_config',
                    protocol, req.client_id, get_server_connect_host(server, protocol), port,
                )
                result = {'client_id': req.client_id, 'config': config}
            elif protocol_base(protocol) == 'telemt':
                result = await asyncio.to_thread(
                    manager.add_client, protocol, req.name, get_server_connect_host(server, protocol), port,
                    telemt_quota=req.telemt_quota,
                    telemt_max_ips=req.telemt_max_ips,
                    telemt_expiry=req.telemt_expiry,
                    secret=req.telemt_secret,
                    user_ad_tag=req.telemt_ad_tag,
                    max_tcp_conns=req.telemt_max_conns,
                )
            elif protocol_base(protocol) == 'wireguard':
                result = await asyncio.to_thread(manager.add_client, req.name, get_server_connect_host(server, protocol))
            else:
                result = await asyncio.to_thread(
                    _manager_call, manager, 'add_client',
                    protocol, req.name, get_server_connect_host(server, protocol), port,
                )
        finally:
            await asyncio.to_thread(ssh.disconnect)

        if result.get('client_id'):
            conn = {
                'id': str(uuid.uuid4()),
                'user_id': user_id,
                'server_id': req.server_id,
                'protocol': protocol,
                'client_id': result['client_id'],
                'name': req.name,
                'created_at': datetime.now().isoformat(),
            }
            async with DATA_LOCK:
                data = load_data()
                data['user_connections'].append(conn)
                save_data(data)

        resp = {'status': 'success'}
        if result.get('config'):
            resp['config'] = result['config']
            resp['vpn_link'] = generate_vpn_link(result['config'])
        return resp
    except Exception as e:
        logger.exception("Error adding user connection")
        return JSONResponse({'error': str(e) or e.__class__.__name__}, status_code=500)


@app.get('/api/users/{user_id}/connections', tags=["Users"])
async def api_get_user_connections(request: Request, user_id: str):
    user = get_current_user(request)
    if not user:
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    # Users can only see their own, admin/support can see all
    if user['role'] == 'user' and user['id'] != user_id:
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    conns = [c for c in data.get('user_connections', []) if c['user_id'] == user_id]
    for c in conns:
        if protocol_base(c.get('protocol', '')) == 'xui':
            c['server_name'] = '3x-ui'
            continue
        sid = c.get('server_id', 0)
        if sid < len(data['servers']):
            c['server_name'] = data['servers'][sid].get('name', '')
    return {'connections': conns}


# ======================== MY CONNECTIONS API (for user role) ========================

@app.get('/api/my/connections', tags=["Self-service"])
async def api_my_connections(request: Request):
    user = get_current_user(request)
    if not user:
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    conns = [c for c in data.get('user_connections', []) if c['user_id'] == user['id']]
    for c in conns:
        if protocol_base(c.get('protocol', '')) == 'xui':
            c['server_name'] = '3x-ui'
            continue
        sid = c.get('server_id', 0)
        if sid < len(data['servers']):
            c['server_name'] = data['servers'][sid].get('name', '')
        else:
            c['server_name'] = 'Unknown'
    return {'connections': conns}


@app.post('/api/users/{user_id}/share/setup', tags=["Users"])
async def api_user_share_setup(user_id: str, req: ShareSetupRequest, request: Request):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    user = next((u for u in data['users'] if u['id'] == user_id), None)
    if not user:
        return JSONResponse({'error': 'User not found'}, status_code=404)
    
    user['share_enabled'] = req.enabled
    if not user.get('share_token'):
        user['share_token'] = secrets.token_urlsafe(16)
    if req.password:
        user['share_password_hash'] = hash_password(req.password)
    elif req.password == "": # Clear
        user['share_password_hash'] = None
        
    save_data(data)
    return {'status': 'success', 'share_token': user.get('share_token')}


@app.get('/share/{token}', response_class=HTMLResponse, tags=["System Templates"])
async def share_page(token: str, request: Request):
    data = load_data()
    user = next((u for u in data['users'] if u.get('share_token') == token), None)
    if not user or not user.get('share_enabled'):
        lang = request.cookies.get('lang', 'ru')
        return HTMLResponse(f"<h1>{_t('share_not_found', lang)}</h1><p>{_t('share_not_found_desc', lang)}</p>", status_code=404)
    
    auth_session_key = f'share_auth_{token}'
    need_password = bool(user.get('share_password_hash')) and not request.session.get(auth_session_key)
    
    return tpl(request, 'user_share.html', 
               share_user=user, 
               need_password=need_password, 
               token=token)


@app.post('/api/share/{token}/auth', tags=["Sharing"])
async def api_share_auth(token: str, req: ShareAuthRequest, request: Request):
    data = load_data()
    user = next((u for u in data['users'] if u.get('share_token') == token), None)
    if not user or not user.get('share_enabled'):
        return JSONResponse({'error': 'Link expired or disabled'}, status_code=404)
    
    if verify_password(req.password, user.get('share_password_hash', '')):
        request.session[f'share_auth_{token}'] = True
        return {'status': 'success'}
    else:
        lang = request.cookies.get('lang', 'ru')
        return JSONResponse({'error': _t('wrong_share_password', lang)}, status_code=401)


@app.get('/api/share/{token}/connections', tags=["Sharing"])
async def api_share_connections(token: str, request: Request):
    data = load_data()
    user = next((u for u in data['users'] if u.get('share_token') == token), None)
    if not user or not user.get('share_enabled'):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    
    if user.get('share_password_hash'):
        if not request.session.get(f'share_auth_{token}'):
            return JSONResponse({'error': 'Unauthorized'}, status_code=401)
            
    conns = [dict(c) for c in data.get('user_connections', []) if c['user_id'] == user['id']]
    for c in conns:
        sid = c['server_id']
        if sid < len(data['servers']):
            c['server_name'] = data['servers'][sid].get('name') or data['servers'][sid]['host']
        else:
            c['server_name'] = 'Unknown'
            
    return {'connections': conns, 'username': user['username']}


@app.post('/api/share/{token}/config/{connection_id}', tags=["Sharing"])
async def api_share_config(token: str, connection_id: str, request: Request):
    data = load_data()
    user = next((u for u in data['users'] if u.get('share_token') == token), None)
    if not user or not user.get('share_enabled'):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    
    if user.get('share_password_hash'):
        if not request.session.get(f'share_auth_{token}'):
            return JSONResponse({'error': 'Unauthorized'}, status_code=401)
            
    conn = next((c for c in data.get('user_connections', []) if c['id'] == connection_id and c['user_id'] == user['id']), None)
    if not conn:
        return JSONResponse({'error': 'Not found'}, status_code=404)
        
    try:
        from managers.user_expiration import maybe_start_user_expiration, user_is_expired
        if user_is_expired(user):
            return JSONResponse({'error': 'Subscription expired'}, status_code=403)
        if maybe_start_user_expiration(data, user['id']):
            save_data(data)

        if protocol_base(conn.get('protocol', '')) == 'xui':
            from managers.xui_api import xui_get_config
            config = await xui_get_config(
                data.get('settings', {}),
                conn['client_id'],
                panel_id=conn.get('xui_panel_id') or None,
            )
            vpn_link = config if str(config).startswith('http') else (generate_vpn_link(config) if config else '')
            return {
                'config': config,
                'vpn_link': vpn_link,
                'subscription_url': config if str(config).startswith('http') else '',
                'expires_at': user.get('expiration_date'),
            }

        sid = conn['server_id']
        server = data['servers'][sid]
        proto_info = server.get('protocols', {}).get(conn['protocol'], {})
        port = proto_info.get('port', '55424')
        ssh = get_ssh(server)
        ssh.connect()
        # Use appropriate manager for the protocol
        manager = get_protocol_manager(ssh, conn['protocol'])
        config = _manager_call(manager, 'get_client_config', conn['protocol'], conn['client_id'], get_server_connect_host(server, conn['protocol']), port)
        ssh.disconnect()
        vpn_link = generate_vpn_link(config) if config else ''
        return {'config': config, 'vpn_link': vpn_link, 'expires_at': user.get('expiration_date')}
    except Exception as e:
        logger.exception("Error getting shared config")
        return JSONResponse({'error': str(e)}, status_code=500)


# ======================== Guest access (no registration) ========================

def _guest_settings(data: Optional[dict] = None) -> dict:
    if data is None:
        data = load_data()
    guest = dict((data.get('settings') or {}).get('guest') or {})
    defaults = {
        'enabled': False,
        'token': '',
        'password_hash': None,
        'user_id': '',
        'allow_create': False,
        'create_protocol': 'xui',
        'create_server_id': 0,
        'create_inbound_id': 0,
        'create_xui_panel_id': '',
        'create_allow_server_choice': True,
    }
    defaults.update(guest)
    return defaults


def _resolve_guest(token: str, request: Request):
    """Return (data, guest_cfg, holder_user, error_response)."""
    data = load_data()
    guest = _guest_settings(data)
    if not guest.get('enabled') or not guest.get('token') or guest.get('token') != token:
        return data, guest, None, JSONResponse({'error': 'Forbidden'}, status_code=403)
    if guest.get('password_hash') and not request.session.get(f'guest_auth_{token}'):
        return data, guest, None, JSONResponse({'error': 'Unauthorized'}, status_code=401)
    holder = None
    uid = guest.get('user_id') or ''
    if uid:
        holder = next((u for u in data['users'] if u['id'] == uid), None)
    return data, guest, holder, None


def _enrich_guest_conn(c: dict, data: dict) -> dict:
    out = dict(c)
    if protocol_base(out.get('protocol', '')) == 'xui':
        out['server_name'] = '3x-ui'
    else:
        sid = out.get('server_id', 0)
        if sid < len(data['servers']):
            out['server_name'] = data['servers'][sid].get('name') or data['servers'][sid]['host']
        else:
            out['server_name'] = 'Unknown'
    return out


@app.get('/guest/{token}', response_class=HTMLResponse, tags=["System Templates"])
async def guest_page(token: str, request: Request):
    data = load_data()
    guest = _guest_settings(data)
    lang = request.cookies.get('lang', 'ru')
    if not guest.get('enabled') or guest.get('token') != token:
        return HTMLResponse(
            f"<h1>{_t('guest_not_found', lang)}</h1><p>{_t('guest_not_found_desc', lang)}</p>",
            status_code=404,
        )
    need_password = bool(guest.get('password_hash')) and not request.session.get(f'guest_auth_{token}')
    return tpl(
        request,
        'guest.html',
        need_password=need_password,
        token=token,
        allow_create=bool(guest.get('allow_create')),
        create_protocol=guest.get('create_protocol') or 'xui',
    )


@app.post('/api/guest/{token}/auth', tags=["Guest"])
async def api_guest_auth(token: str, req: ShareAuthRequest, request: Request):
    data = load_data()
    guest = _guest_settings(data)
    if not guest.get('enabled') or guest.get('token') != token:
        return JSONResponse({'error': 'Link expired or disabled'}, status_code=404)
    if not guest.get('password_hash'):
        request.session[f'guest_auth_{token}'] = True
        return {'status': 'success'}
    if verify_password(req.password, guest.get('password_hash') or ''):
        request.session[f'guest_auth_{token}'] = True
        return {'status': 'success'}
    lang = request.cookies.get('lang', 'ru')
    return JSONResponse({'error': _t('wrong_guest_password', lang)}, status_code=401)


@app.get('/api/guest/{token}/connections', tags=["Guest"])
async def api_guest_connections(token: str, request: Request):
    data, guest, holder, err = _resolve_guest(token, request)
    if err:
        return err
    allow_choice = bool(guest.get('create_allow_server_choice', True))
    protocol = guest.get('create_protocol') or 'xui'
    servers = _pickable_servers_for_protocol(data, protocol) if (
        guest.get('allow_create') and allow_choice and protocol_base(protocol) != 'xui'
    ) else []
    meta = {
        'allow_create': bool(guest.get('allow_create')),
        'create_protocol': protocol,
        'allow_server_choice': bool(servers),
        'default_server_id': int(guest.get('create_server_id') or 0),
        'servers': servers,
    }
    if not holder:
        return {'connections': [], **meta}
    conns = [
        _enrich_guest_conn(c, data)
        for c in data.get('user_connections', [])
        if c['user_id'] == holder['id']
    ]
    return {'connections': conns, **meta}


@app.post('/api/guest/{token}/config/{connection_id}', tags=["Guest"])
async def api_guest_config(token: str, connection_id: str, request: Request):
    data, guest, holder, err = _resolve_guest(token, request)
    if err:
        return err
    if not holder:
        return JSONResponse({'error': 'Not found'}, status_code=404)
    conn = next(
        (c for c in data.get('user_connections', []) if c['id'] == connection_id and c['user_id'] == holder['id']),
        None,
    )
    if not conn:
        return JSONResponse({'error': 'Not found'}, status_code=404)
    try:
        from managers.user_expiration import maybe_start_user_expiration, user_is_expired
        if user_is_expired(holder):
            return JSONResponse({'error': 'Subscription expired'}, status_code=403)
        if maybe_start_user_expiration(data, holder['id']):
            save_data(data)
        return await _fetch_connection_config_payload(data, conn, expires_at=holder.get('expiration_date'))
    except Exception as e:
        logger.exception("Error getting guest config")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/guest/{token}/create', tags=["Guest"])
async def api_guest_create(token: str, req: GuestCreateRequest, request: Request):
    """Create a new VPN config for a guest (no registration)."""
    data, guest, holder, err = _resolve_guest(token, request)
    if err:
        return err
    if not guest.get('allow_create'):
        return JSONResponse({'error': 'Guest config creation is disabled'}, status_code=403)
    if not holder:
        return JSONResponse({'error': 'Guest user is not configured in settings'}, status_code=400)

    protocol = guest.get('create_protocol') or 'xui'
    name = (req.name or 'Guest VPN').strip() or 'Guest VPN'
    # Unique-ish name to avoid collisions
    name = f"{name}_{secrets.token_hex(3)}"
    allow_choice = bool(guest.get('create_allow_server_choice', True))

    try:
        from managers.user_expiration import maybe_start_user_expiration, user_is_expired
        if user_is_expired(holder):
            return JSONResponse({'error': 'Subscription expired'}, status_code=403)

        if protocol_base(protocol) == 'xui':
            sid = 0
        else:
            try:
                sid = _resolve_chosen_server_id(
                    data,
                    protocol=protocol,
                    default_server_id=int(guest.get('create_server_id') or 0),
                    requested_server_id=req.server_id,
                    allow_choice=allow_choice,
                )
            except ValueError as ve:
                return JSONResponse({'error': str(ve)}, status_code=400)

        if protocol_base(protocol) == 'aivpn':
            from managers.aivpn_manager import resolve_provision_protocol
            protocol = resolve_provision_protocol(data['servers'][sid], 'aivpn')
        elif protocol_base(protocol) != 'xui':
            protocol = _match_protocol_on_server(data['servers'][sid], protocol)

        if protocol_base(protocol) == 'xui':
            from managers.xui_api import xui_create_vless_config
            from managers.xui_servers import get_xui_server, ensure_xui_servers
            ensure_xui_servers(data.setdefault('settings', {}))
            panel = get_xui_server(data.get('settings') or {}, guest.get('create_xui_panel_id') or None)
            if not panel:
                return JSONResponse({'error': 'Add a 3x-ui server in Settings first'}, status_code=400)
            panel_id = panel.get('id') or ''
            created = await xui_create_vless_config(
                data.get('settings', {}),
                name=name,
                inbound_id=guest.get('create_inbound_id') or panel.get('default_inbound_id') or None,
                panel_id=panel_id,
            )
            result = {
                'client_id': created['client_id'],
                'config': created.get('config') or '',
                'subscription_url': created.get('subscription_url') or '',
                'xui_panel_id': panel_id,
            }
            sid = 0
            protocol = 'xui'
        else:
            server = data['servers'][sid]
            proto_info = server.get('protocols', {}).get(protocol, {})
            port = proto_info.get('port', '55424')
            ssh = get_ssh(server)
            await asyncio.to_thread(ssh.connect)
            try:
                manager = get_protocol_manager(ssh, protocol)
                if protocol_base(protocol) == 'wireguard':
                    result = await asyncio.to_thread(manager.add_client, name, get_server_connect_host(server, protocol))
                else:
                    result = await asyncio.to_thread(
                        _manager_call, manager, 'add_client',
                        protocol, name, get_server_connect_host(server, protocol), port,
                    )
            finally:
                await asyncio.to_thread(ssh.disconnect)

        if not result.get('client_id'):
            return JSONResponse({'error': 'Failed to create config'}, status_code=500)

        conn = {
            'id': str(uuid.uuid4()),
            'user_id': holder['id'],
            'server_id': sid,
            'protocol': protocol,
            'client_id': result['client_id'],
            'name': name,
            'created_at': datetime.now().isoformat(),
        }
        if result.get('xui_panel_id'):
            conn['xui_panel_id'] = result['xui_panel_id']
        async with DATA_LOCK:
            data = load_data()
            data['user_connections'].append(conn)
            maybe_start_user_expiration(data, holder['id'])
            save_data(data)

        config = result.get('config') or ''
        subscription_url = result.get('subscription_url') or ''
        vpn_link = subscription_url or (config if str(config).startswith('http') else (generate_vpn_link(config) if config else ''))
        return {
            'status': 'success',
            'connection': _enrich_guest_conn(conn, data),
            'config': config,
            'subscription_url': subscription_url,
            'vpn_link': vpn_link,
            'expires_at': next((u.get('expiration_date') for u in data.get('users', []) if u.get('id') == holder['id']), None),
        }
    except Exception as e:
        logger.exception("Error creating guest config")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/settings/guest/regenerate_token', tags=["Settings"])
async def api_guest_regenerate_token(request: Request):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    guest = _guest_settings(data)
    guest['token'] = secrets.token_urlsafe(16)
    data.setdefault('settings', {})['guest'] = guest
    save_data(data)
    return {'status': 'success', 'token': guest['token']}


# ======================== Invite links (limited config creation) ========================

def _server_supports_protocol(server: dict, protocol: str) -> bool:
    """True if server has an installed client VPN matching protocol (or any for aivpn)."""
    base = protocol_base(protocol)
    if base == 'xui':
        return False
    protocols = server.get('protocols') or {}
    for key, info in protocols.items():
        if not isinstance(info, dict) or not info.get('installed'):
            continue
        kb = protocol_base(key)
        if kb not in CLIENT_VPN_BASES or kb == 'xui':
            continue
        if base == 'aivpn' or kb == base or key == protocol:
            return True
    return False


def _match_protocol_on_server(server: dict, protocol: str) -> str:
    """Map requested protocol to an installed key on this server (prefer exact)."""
    protocols = server.get('protocols') or {}
    if protocol in protocols and isinstance(protocols.get(protocol), dict) and protocols[protocol].get('installed'):
        return protocol
    base = protocol_base(protocol)
    if base == 'aivpn':
        return protocol
    candidates = [
        key for key, info in protocols.items()
        if isinstance(info, dict) and info.get('installed') and protocol_base(key) == base
    ]
    if not candidates:
        return protocol
    candidates.sort()
    return candidates[0]


def _pickable_servers_for_protocol(data: dict, protocol: str) -> list:
    """Safe server list for end-user pickers (name/host/id only)."""
    out = []
    for idx, server in enumerate(data.get('servers') or []):
        if not isinstance(server, dict):
            continue
        if not _server_supports_protocol(server, protocol):
            continue
        out.append({
            'id': idx,
            'name': server.get('name') or server.get('host') or f'Server {idx + 1}',
            'host': server.get('host') or '',
        })
    return out


def _resolve_chosen_server_id(
    data: dict,
    *,
    protocol: str,
    default_server_id: int,
    requested_server_id: Optional[int],
    allow_choice: bool,
) -> int:
    """Pick server_id for guest/invite create; validate against installed protocols."""
    servers = data.get('servers') or []
    default_sid = int(default_server_id or 0)
    if not allow_choice or requested_server_id is None:
        sid = default_sid
    else:
        sid = int(requested_server_id)
    if sid < 0 or sid >= len(servers):
        raise ValueError('Server not found')
    if protocol_base(protocol) != 'xui' and not _server_supports_protocol(servers[sid], protocol):
        raise ValueError('Selected server does not have the required protocol')
    return sid


def _invite_public_view(link: dict, data: Optional[dict] = None) -> dict:
    max_uses = int(link.get('max_uses') or 0)
    used = int(link.get('used_count') or 0)
    remaining = None if max_uses <= 0 else max(0, max_uses - used)
    exhausted = remaining is not None and remaining <= 0
    duration_days = int(link.get('duration_days') or 0)
    protocol = link.get('protocol') or 'awg'
    allow_server_choice = bool(link.get('allow_server_choice', True)) and protocol_base(protocol) != 'xui'
    servers = []
    if data is not None and allow_server_choice:
        servers = _pickable_servers_for_protocol(data, protocol)
    return {
        'id': link.get('id'),
        'name': link.get('name') or 'Invite',
        'token': link.get('token'),
        'enabled': bool(link.get('enabled', True)),
        'max_uses': max_uses,
        'used_count': used,
        'remaining': remaining,
        'unlimited': max_uses <= 0,
        'expired': False,
        'exhausted': exhausted,
        'has_password': bool(link.get('password_hash')),
        'protocol': protocol,
        'server_id': int(link.get('server_id') or 0),
        'allow_server_choice': allow_server_choice,
        'servers': servers,
        'duration_days': duration_days,
        'user_id': link.get('user_id') or '',
        'note': link.get('note') or '',
        'created_at': link.get('created_at'),
        'available': bool(link.get('enabled', True)) and not exhausted,
    }


def _find_invite(data: dict, token: str) -> Optional[dict]:
    return next((x for x in data.get('invite_links', []) if x.get('token') == token), None)


def _invite_auth_ok(link: dict, request: Request) -> bool:
    if not link.get('password_hash'):
        return True
    return bool(request.session.get(f"invite_auth_{link.get('token')}"))


def _enrich_invite_conn(c: dict, data: dict) -> dict:
    out = dict(c)
    if protocol_base(out.get('protocol', '')) == 'xui':
        out['server_name'] = '3x-ui'
    else:
        sid = int(out.get('server_id') or 0)
        if sid < len(data.get('servers') or []):
            srv = data['servers'][sid]
            out['server_name'] = srv.get('name') or srv.get('host') or ''
        else:
            out['server_name'] = 'Unknown'
    return out


async def _fetch_connection_config_payload(data: dict, conn: dict, expires_at: Optional[str] = None) -> dict:
    """Shared config fetch for guest/invite/share self-service surfaces."""
    if protocol_base(conn.get('protocol', '')) == 'xui':
        from managers.xui_api import xui_get_config
        config = await xui_get_config(
            data.get('settings', {}),
            conn['client_id'],
            panel_id=conn.get('xui_panel_id') or None,
        )
        vpn_link = config if str(config).startswith('http') else (generate_vpn_link(config) if config else '')
        return {
            'config': config,
            'vpn_link': vpn_link,
            'subscription_url': config if str(config).startswith('http') else '',
            'expires_at': expires_at,
        }

    sid = int(conn.get('server_id') or 0)
    if sid >= len(data.get('servers') or []):
        raise RuntimeError('Server not found')
    server = data['servers'][sid]
    protocol = conn['protocol']
    proto_info = server.get('protocols', {}).get(protocol, {})
    port = proto_info.get('port', '55424')
    ssh = get_ssh(server)
    await asyncio.to_thread(ssh.connect)
    try:
        manager = get_protocol_manager(ssh, protocol)
        config = await asyncio.to_thread(
            _manager_call, manager, 'get_client_config',
            protocol, conn['client_id'], get_server_connect_host(server, protocol), port,
        )
    finally:
        await asyncio.to_thread(ssh.disconnect)
    vpn_link = generate_vpn_link(config) if config else ''
    return {'config': config, 'vpn_link': vpn_link, 'expires_at': expires_at}


def _expiry_ms_from_duration_days(duration_days: int) -> int:
    """3x-ui expiryTime is unix ms; 0 means no expiry. Starts now (on redeem)."""
    days = int(duration_days or 0)
    if days <= 0:
        return 0
    return int((datetime.now().timestamp() + days * 86400) * 1000)


async def _create_config_for_protocol(
    data: dict,
    *,
    protocol: str,
    name: str,
    server_id: int = 0,
    xui_inbound_id: Optional[int] = None,
    xui_panel_id: Optional[str] = None,
    duration_days: int = 0,
) -> dict:
    """Create VPN client; returns {client_id, config, subscription_url, protocol, server_id}."""
    protocol = protocol or 'xui'
    if protocol_base(protocol) == 'aivpn':
        from managers.aivpn_manager import resolve_provision_protocol
        sid = int(server_id or 0)
        if sid >= len(data.get('servers') or []):
            raise RuntimeError('Server not found')
        protocol = resolve_provision_protocol(data['servers'][sid], 'aivpn')
    if protocol_base(protocol) == 'xui':
        from managers.xui_api import xui_create_vless_config
        from managers.xui_servers import get_xui_server, ensure_xui_servers
        ensure_xui_servers(data.get('settings') or {})
        panel = get_xui_server(data.get('settings') or {}, xui_panel_id)
        if not panel:
            raise RuntimeError('Add a 3x-ui server in Settings first')
        panel_id = panel.get('id') or ''
        inbound = int(xui_inbound_id or 0) or int(panel.get('default_inbound_id') or 0) or None
        if not inbound:
            raise RuntimeError('Select a VLESS inbound from 3x-ui')
        expiry_ms = _expiry_ms_from_duration_days(duration_days)
        created = await xui_create_vless_config(
            data.get('settings', {}),
            name=name,
            inbound_id=inbound,
            expiry_time=expiry_ms,
            panel_id=panel_id,
        )
        return {
            'client_id': created['client_id'],
            'config': created.get('config') or '',
            'subscription_url': created.get('subscription_url') or '',
            'sub_id': created.get('sub_id') or '',
            'protocol': 'xui',
            'server_id': 0,
            'xui_panel_id': panel_id,
            'xui_inbound_id': int(created.get('inbound_id') or 0),
            'expires_at': (
                datetime.fromtimestamp(expiry_ms / 1000).isoformat()
                if expiry_ms > 0 else None
            ),
        }

    sid = int(server_id or 0)
    if sid >= len(data['servers']):
        raise RuntimeError('Server not found')
    server = data['servers'][sid]
    proto_info = server.get('protocols', {}).get(protocol, {})
    port = proto_info.get('port', '55424')
    ssh = get_ssh(server)
    await asyncio.to_thread(ssh.connect)
    try:
        manager = get_protocol_manager(ssh, protocol)
        if protocol_base(protocol) == 'wireguard':
            result = await asyncio.to_thread(manager.add_client, name, get_server_connect_host(server, protocol))
        else:
            result = await asyncio.to_thread(
                _manager_call, manager, 'add_client',
                protocol, name, get_server_connect_host(server, protocol), port,
            )
    finally:
        await asyncio.to_thread(ssh.disconnect)
    if not result.get('client_id'):
        raise RuntimeError('Failed to create config')
    return {
        'client_id': result['client_id'],
        'config': result.get('config') or '',
        'subscription_url': '',
        'protocol': protocol,
        'server_id': sid,
        'expires_at': None,
    }


@app.get('/invites', response_class=HTMLResponse, tags=["System Templates"])
async def invites_page(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url='/login', status_code=302)
    if user['role'] not in ('admin', 'support'):
        return RedirectResponse(url='/my', status_code=302)
    data = load_data()
    from managers.xui_servers import list_xui_servers, get_xui_server, ensure_xui_servers
    ensure_xui_servers(data.setdefault('settings', {}))
    xui_servers = list_xui_servers(data.get('settings') or {})
    primary = get_xui_server(data.get('settings') or {}, None)
    any_sub = any((s.get('sub_url') or '').strip() for s in xui_servers)
    return tpl(
        request,
        'invites.html',
        invites=[_invite_public_view(x) for x in data.get('invite_links', [])],
        users=data.get('users', []),
        servers=data.get('servers', []),
        xui_servers=xui_servers,
        xui_configured=bool(xui_servers),
        xui_sub_url=(primary or {}).get('sub_url') or '',
        xui_has_sub_url=any_sub,
        xui_default_inbound=int((primary or {}).get('default_inbound_id') or 0),
        xui_default_panel_id=(primary or {}).get('id') or '',
    )


@app.get('/api/invites', tags=["Invites"])
async def api_list_invites(request: Request):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    return {'invites': [_invite_public_view(x) for x in data.get('invite_links', [])]}


@app.post('/api/invites', tags=["Invites"])
async def api_create_invite(request: Request, req: InviteCreateRequest):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    if req.max_uses < 0:
        return JSONResponse({'error': 'max_uses must be >= 0'}, status_code=400)
    if req.duration_days < 0:
        return JSONResponse({'error': 'duration_days must be >= 0'}, status_code=400)
    data = load_data()
    if req.user_id and not any(u['id'] == req.user_id for u in data['users']):
        return JSONResponse({'error': 'User not found'}, status_code=400)
    protocol = req.protocol or 'xui'
    inbound_id = int(req.xui_inbound_id or 0)
    panel_id = (req.xui_panel_id or '').strip()
    if protocol_base(protocol) == 'xui':
        from managers.xui_servers import get_xui_server, ensure_xui_servers
        ensure_xui_servers(data.setdefault('settings', {}))
        panel = get_xui_server(data.get('settings') or {}, panel_id or None)
        if not panel:
            return JSONResponse({'error': 'Add a 3x-ui server in Settings first'}, status_code=400)
        panel_id = panel.get('id') or ''
        if not inbound_id:
            inbound_id = int(panel.get('default_inbound_id') or 0)
        if not inbound_id:
            return JSONResponse({'error': 'Select a VLESS inbound from 3x-ui'}, status_code=400)
    link = {
        'id': str(uuid.uuid4()),
        'name': (req.name or 'Invite').strip() or 'Invite',
        'token': secrets.token_urlsafe(16),
        'enabled': bool(req.enabled),
        'max_uses': int(req.max_uses),
        'used_count': 0,
        'user_id': req.user_id or '',
        'protocol': protocol,
        'server_id': int(req.server_id or 0),
        'xui_inbound_id': inbound_id,
        'xui_panel_id': panel_id,
        'password_hash': hash_password(req.password) if req.password else None,
        'expires_at': None,
        'duration_days': int(req.duration_days or 0),
        'note': req.note or '',
        'allow_server_choice': bool(req.allow_server_choice),
        'created_at': datetime.now().isoformat(),
    }
    data.setdefault('invite_links', []).append(link)
    save_data(data)
    view = _invite_public_view(link, data)
    return {'status': 'success', 'invite': view, 'url': f"/invite/{link['token']}"}


@app.put('/api/invites/{invite_id}', tags=["Invites"])
async def api_update_invite(request: Request, invite_id: str, req: InviteUpdateRequest):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    link = next((x for x in data.get('invite_links', []) if x.get('id') == invite_id), None)
    if not link:
        return JSONResponse({'error': 'Not found'}, status_code=404)
    if req.name is not None:
        link['name'] = req.name.strip() or link['name']
    if req.max_uses is not None:
        if req.max_uses < 0:
            return JSONResponse({'error': 'max_uses must be >= 0'}, status_code=400)
        link['max_uses'] = int(req.max_uses)
    if req.user_id is not None:
        if req.user_id and not any(u['id'] == req.user_id for u in data['users']):
            return JSONResponse({'error': 'User not found'}, status_code=400)
        link['user_id'] = req.user_id
    if req.protocol is not None:
        link['protocol'] = req.protocol
    if req.server_id is not None:
        link['server_id'] = int(req.server_id)
    if req.xui_inbound_id is not None:
        link['xui_inbound_id'] = int(req.xui_inbound_id)
    if req.xui_panel_id is not None:
        link['xui_panel_id'] = (req.xui_panel_id or '').strip()
    if req.duration_days is not None:
        if req.duration_days < 0:
            return JSONResponse({'error': 'duration_days must be >= 0'}, status_code=400)
        link['duration_days'] = int(req.duration_days)
    if req.clear_password:
        link['password_hash'] = None
    elif req.password:
        link['password_hash'] = hash_password(req.password)
    if req.note is not None:
        link['note'] = req.note
    if req.enabled is not None:
        link['enabled'] = bool(req.enabled)
    if req.allow_server_choice is not None:
        link['allow_server_choice'] = bool(req.allow_server_choice)
    if req.reset_used:
        link['used_count'] = 0
    if protocol_base(link.get('protocol') or 'xui') == 'xui':
        from managers.xui_servers import get_xui_server, ensure_xui_servers
        ensure_xui_servers(data.setdefault('settings', {}))
        panel = get_xui_server(data.get('settings') or {}, link.get('xui_panel_id') or None)
        if not panel:
            return JSONResponse({'error': 'Add a 3x-ui server in Settings first'}, status_code=400)
        if not link.get('xui_panel_id'):
            link['xui_panel_id'] = panel.get('id') or ''
        if not int(link.get('xui_inbound_id') or 0):
            link['xui_inbound_id'] = int(panel.get('default_inbound_id') or 0)
        if not int(link.get('xui_inbound_id') or 0):
            return JSONResponse({'error': 'Select a VLESS inbound from 3x-ui'}, status_code=400)
    save_data(data)
    return {'status': 'success', 'invite': _invite_public_view(link, data)}


@app.delete('/api/invites/{invite_id}', tags=["Invites"])
async def api_delete_invite(request: Request, invite_id: str):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    before = len(data.get('invite_links', []))
    data['invite_links'] = [x for x in data.get('invite_links', []) if x.get('id') != invite_id]
    if len(data['invite_links']) == before:
        return JSONResponse({'error': 'Not found'}, status_code=404)
    save_data(data)
    return {'status': 'success'}


@app.get('/invite/{token}', response_class=HTMLResponse, tags=["System Templates"])
async def invite_public_page(token: str, request: Request):
    data = load_data()
    link = _find_invite(data, token)
    lang = request.cookies.get('lang', 'ru')
    if not link:
        return HTMLResponse(
            f"<h1>{_t('invite_not_found', lang)}</h1><p>{_t('invite_not_found_desc', lang)}</p>",
            status_code=404,
        )
    view = _invite_public_view(link, data)
    need_password = bool(link.get('password_hash')) and not _invite_auth_ok(link, request)
    return tpl(
        request,
        'invite.html',
        invite=view,
        need_password=need_password,
        token=token,
    )


@app.post('/api/invite/{token}/auth', tags=["Invites"])
async def api_invite_auth(token: str, req: ShareAuthRequest, request: Request):
    data = load_data()
    link = _find_invite(data, token)
    if not link or not link.get('enabled'):
        return JSONResponse({'error': 'Link expired or disabled'}, status_code=404)
    if not link.get('password_hash'):
        request.session[f'invite_auth_{token}'] = True
        return {'status': 'success'}
    if verify_password(req.password, link.get('password_hash') or ''):
        request.session[f'invite_auth_{token}'] = True
        return {'status': 'success'}
    lang = request.cookies.get('lang', 'ru')
    return JSONResponse({'error': _t('wrong_invite_password', lang)}, status_code=401)


@app.get('/api/invite/{token}/info', tags=["Invites"])
async def api_invite_info(token: str, request: Request):
    data = load_data()
    link = _find_invite(data, token)
    if not link:
        return JSONResponse({'error': 'Not found'}, status_code=404)
    if not _invite_auth_ok(link, request):
        return JSONResponse({'error': 'Unauthorized'}, status_code=401)
    view = _invite_public_view(link, data)
    # Don't leak admin note / ids beyond what's needed
    return {
        'name': view['name'],
        'available': view['available'],
        'enabled': view['enabled'],
        'expired': view['expired'],
        'exhausted': view['exhausted'],
        'unlimited': view['unlimited'],
        'remaining': view['remaining'],
        'max_uses': view['max_uses'],
        'used_count': view['used_count'],
        'protocol': view['protocol'],
        'allow_server_choice': view['allow_server_choice'],
        'server_id': view['server_id'],
        'servers': view.get('servers') or [],
        'duration_days': view['duration_days'],
    }


@app.get('/api/invite/{token}/connections', tags=["Invites"])
async def api_invite_connections(token: str, request: Request):
    """List configs created via this invite (re-copy without consuming another use)."""
    data = load_data()
    link = _find_invite(data, token)
    if not link:
        return JSONResponse({'error': 'Not found'}, status_code=404)
    if not _invite_auth_ok(link, request):
        return JSONResponse({'error': 'Unauthorized'}, status_code=401)
    invite_id = link.get('id')
    holder_id = link.get('user_id') or ''
    conns = [
        _enrich_invite_conn(c, data)
        for c in data.get('user_connections', [])
        if c.get('invite_id') == invite_id and (not holder_id or c.get('user_id') == holder_id)
    ]
    conns.sort(key=lambda c: c.get('created_at') or '', reverse=True)
    return {
        'connections': conns,
        'invite': _invite_public_view(link, data),
    }


@app.post('/api/invite/{token}/config/{connection_id}', tags=["Invites"])
async def api_invite_config(token: str, connection_id: str, request: Request):
    data = load_data()
    link = _find_invite(data, token)
    if not link:
        return JSONResponse({'error': 'Not found'}, status_code=404)
    if not _invite_auth_ok(link, request):
        return JSONResponse({'error': 'Unauthorized'}, status_code=401)
    invite_id = link.get('id')
    holder_id = link.get('user_id') or ''
    conn = next(
        (
            c for c in data.get('user_connections', [])
            if c.get('id') == connection_id
            and c.get('invite_id') == invite_id
            and (not holder_id or c.get('user_id') == holder_id)
        ),
        None,
    )
    if not conn:
        return JSONResponse({'error': 'Not found'}, status_code=404)
    try:
        return await _fetch_connection_config_payload(data, conn, expires_at=conn.get('expires_at'))
    except Exception as e:
        logger.exception('Error getting invite config')
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/invite/{token}/create', tags=["Invites"])
async def api_invite_create_config(token: str, req: InviteRedeemRequest, request: Request):
    data = load_data()
    link = _find_invite(data, token)
    if not link:
        return JSONResponse({'error': 'Not found'}, status_code=404)
    if not _invite_auth_ok(link, request):
        return JSONResponse({'error': 'Unauthorized'}, status_code=401)

    view = _invite_public_view(link, data)
    if not view['available']:
        if view['expired']:
            return JSONResponse({'error': 'Invite link expired'}, status_code=403)
        if view['exhausted']:
            return JSONResponse({'error': 'Invite link has no remaining uses'}, status_code=403)
        return JSONResponse({'error': 'Invite link is disabled'}, status_code=403)

    holder_id = link.get('user_id') or ''
    if not holder_id or not any(u['id'] == holder_id for u in data['users']):
        return JSONResponse({'error': 'Invite holder user is not configured'}, status_code=400)

    protocol = link.get('protocol') or 'xui'
    allow_choice = bool(link.get('allow_server_choice', True))
    try:
        if protocol_base(protocol) == 'xui':
            sid = int(link.get('server_id') or 0)
        else:
            sid = _resolve_chosen_server_id(
                data,
                protocol=protocol,
                default_server_id=int(link.get('server_id') or 0),
                requested_server_id=req.server_id,
                allow_choice=allow_choice,
            )
    except ValueError as ve:
        return JSONResponse({'error': str(ve)}, status_code=400)

    # Reserve a use slot under lock
    async with DATA_LOCK:
        data = load_data()
        link = _find_invite(data, token)
        if not link:
            return JSONResponse({'error': 'Not found'}, status_code=404)
        view = _invite_public_view(link, data)
        if not view['available']:
            return JSONResponse({'error': 'Invite link is no longer available'}, status_code=403)
        link['used_count'] = int(link.get('used_count') or 0) + 1
        save_data(data)

    name = (req.name or 'Invite VPN').strip() or 'Invite VPN'
    name = f"{name}_{secrets.token_hex(3)}"
    try:
        data = load_data()
        protocol = link.get('protocol') or 'xui'
        if protocol_base(protocol) == 'aivpn' and sid < len(data.get('servers') or []):
            from managers.aivpn_manager import resolve_provision_protocol
            protocol = resolve_provision_protocol(data['servers'][sid], 'aivpn')
        elif protocol_base(protocol) != 'xui' and sid < len(data.get('servers') or []):
            protocol = _match_protocol_on_server(data['servers'][sid], protocol)
        created = await _create_config_for_protocol(
            data,
            protocol=protocol,
            name=name,
            server_id=sid,
            xui_inbound_id=int(link.get('xui_inbound_id') or 0) or None,
            xui_panel_id=link.get('xui_panel_id') or None,
            duration_days=int(link.get('duration_days') or 0),
        )
        conn = {
            'id': str(uuid.uuid4()),
            'user_id': holder_id,
            'server_id': created['server_id'],
            'protocol': created['protocol'],
            'client_id': created['client_id'],
            'name': name,
            'invite_id': link.get('id'),
            'xui_panel_id': created.get('xui_panel_id') or link.get('xui_panel_id') or '',
            'created_at': datetime.now().isoformat(),
        }
        if created.get('expires_at'):
            conn['expires_at'] = created['expires_at']
        async with DATA_LOCK:
            data = load_data()
            data.setdefault('user_connections', []).append(conn)
            save_data(data)
        config = created.get('config') or ''
        subscription_url = created.get('subscription_url') or ''
        vpn_link = subscription_url or (generate_vpn_link(config) if config else '')
        data = load_data()
        link = _find_invite(data, token) or link
        return {
            'status': 'success',
            'config': config,
            'subscription_url': subscription_url,
            'vpn_link': vpn_link,
            'expires_at': created.get('expires_at'),
            'connection': _enrich_invite_conn(conn, data),
            'invite': _invite_public_view(link, data),
        }
    except Exception as e:
        # Roll back reserved use
        try:
            async with DATA_LOCK:
                data = load_data()
                link = _find_invite(data, token)
                if link and int(link.get('used_count') or 0) > 0:
                    link['used_count'] = int(link['used_count']) - 1
                    save_data(data)
        except Exception:
            logger.exception('Failed to roll back invite use count')
        logger.exception('Error creating invite config')
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/my/connections/{connection_id}/config', tags=["Self-service"])
async def api_my_connection_config(request: Request, connection_id: str):
    user = get_current_user(request)
    if not user:
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        from managers.user_expiration import maybe_start_user_expiration, user_is_expired
        data = load_data()
        panel_user = next((u for u in data.get('users', []) if u['id'] == user['id']), None)
        if panel_user and user_is_expired(panel_user):
            return JSONResponse({'error': 'Subscription expired'}, status_code=403)
        if panel_user and maybe_start_user_expiration(data, user['id']):
            save_data(data)

        conn = next(
            (c for c in data.get('user_connections', []) if c['id'] == connection_id and c['user_id'] == user['id']),
            None
        )
        if not conn:
            return JSONResponse({'error': 'Connection not found'}, status_code=404)

        if protocol_base(conn.get('protocol', '')) == 'xui':
            from managers.xui_api import xui_get_config
            config = await xui_get_config(
                data.get('settings', {}),
                conn['client_id'],
                panel_id=conn.get('xui_panel_id') or None,
            )
            vpn_link = config if str(config).startswith('http') else (generate_vpn_link(config) if config else '')
            expires_at = None
            panel_user = next((u for u in data.get('users', []) if u['id'] == user['id']), None)
            if panel_user:
                expires_at = panel_user.get('expiration_date')
            return {
                'config': config,
                'vpn_link': vpn_link,
                'subscription_url': config if str(config).startswith('http') else '',
                'expires_at': expires_at,
            }

        sid = conn['server_id']
        if sid >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][sid]
        proto_info = server.get('protocols', {}).get(conn['protocol'], {})
        port = proto_info.get('port', '55424')
        ssh = get_ssh(server)
        ssh.connect()
        # Use appropriate manager for the protocol (fixes Telemt/Xray not working for users)
        manager = get_protocol_manager(ssh, conn['protocol'])
        config = _manager_call(manager, 'get_client_config', conn['protocol'], conn['client_id'], get_server_connect_host(server, conn['protocol']), port)
        ssh.disconnect()
        vpn_link = generate_vpn_link(config) if config else ''
        expires_at = None
        panel_user = next((u for u in data.get('users', []) if u['id'] == user['id']), None)
        if panel_user:
            expires_at = panel_user.get('expiration_date')
        return {'config': config, 'vpn_link': vpn_link, 'expires_at': expires_at}
    except Exception as e:
        logger.exception("Error getting my connection config")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.get('/support', response_class=HTMLResponse, tags=["System Templates"])
async def support_page(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse('/login', status_code=302)
    data = load_data()
    donate = dict((data.get('settings') or {}).get('donate') or {})
    if not donate.get('enabled', True):
        return RedirectResponse('/my', status_code=302)
    return tpl(request, 'support.html', donate=donate)


@app.get('/settings', response_class=HTMLResponse, tags=["System Templates"])
async def settings_page(request: Request):
    user = _check_admin(request)
    if not user:
        return RedirectResponse('/login', status_code=302)
    data = load_data()
    from managers.xui_servers import list_xui_servers, public_server_view, ensure_xui_servers
    settings = data.setdefault('settings', {})
    before = json.dumps(settings.get('xui_servers') or [], sort_keys=True, default=str)
    ensure_xui_servers(settings)
    after = json.dumps(settings.get('xui_servers') or [], sort_keys=True, default=str)
    if before != after:
        save_data(data)
    xui_servers = [public_server_view(s) for s in list_xui_servers(settings)]
    return tpl(
        request,
        'settings.html',
        settings=data.get('settings', {}),
        servers=data.get('servers', []),
        users=data.get('users', []),
        xui_servers=xui_servers,
        current_version=CURRENT_VERSION,
    )


@app.get('/api/settings', tags=["Settings"])
async def api_get_settings(request: Request):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    return data.get('settings', {})


@app.get('/api/settings/check_updates', tags=["Settings"])
async def api_check_updates(request: Request):
    """Proxy latest release/tag lookup to avoid browser CORS blocks on the update host."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        updater = UpdateManager(application_path, CURRENT_VERSION)
        mode = updater.detect_mode()
        remote = await asyncio.to_thread(resolve_latest_remote_version)
        latest = (remote.get('latest_version') or '').strip()
        html_url = (remote.get('html_url') or f'{RELEASES_REPO_URL}/releases').strip()
        body = (remote.get('body') or '')[:4000]
        current = CURRENT_VERSION
        update_available = bool(latest) and version_gt(latest, current)
        return {
            'current_version': current,
            'latest_version': latest,
            'update_available': update_available,
            'html_url': html_url,
            'releases_url': remote.get('releases_url') or f'{RELEASES_REPO_URL}/releases',
            'body': body,
            'source': remote.get('source') or 'none',
            'can_auto_update': bool(mode.get('can_auto_update')),
            'update_mode': mode.get('update_method') or mode.get('mode'),
            'mode': mode,
        }
    except Exception as e:
        logger.exception('Error checking for updates')
        return JSONResponse({'error': str(e)}, status_code=502)


async def _fetch_latest_release_tag() -> str:
    remote = await asyncio.to_thread(resolve_latest_remote_version)
    return (remote.get('latest_version') or '').strip()


@app.post('/api/settings/apply_update', tags=["Settings"])
async def api_apply_update(request: Request, req: ApplyUpdateRequest):
    """Install a release tag (git checkout or archive download) and restart the panel."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    updater = UpdateManager(application_path, CURRENT_VERSION)
    target = (req.target_version or '').strip()
    if not target:
        try:
            target = await _fetch_latest_release_tag()
        except Exception as e:
            logger.exception('Failed to resolve latest tag for apply_update')
            return JSONResponse({'error': str(e)}, status_code=502)
    if not target:
        return JSONResponse({'error': 'No target version specified'}, status_code=400)

    result = await asyncio.to_thread(
        updater.apply_update,
        target,
        bool(req.allow_dirty),
    )
    if result.get('status') != 'success':
        status_code = 409 if result.get('needs_confirm_dirty') else 500
        return JSONResponse({'error': result.get('message') or 'Update failed', **result}, status_code=status_code)

    if result.get('restart'):
        UpdateManager.schedule_restart(application_path, 1.5)
    return enrich_update_result(request, result)


@app.post('/api/settings/upgrade_panel', tags=["Settings"])
async def api_upgrade_panel(request: Request):
    """One-click: fetch latest release, install if newer, restart."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    updater = UpdateManager(application_path, CURRENT_VERSION)
    mode = updater.detect_mode()
    if not mode.get('can_auto_update'):
        return JSONResponse({
            'error': (
                'In-panel update is not available for this install. '
                'Use git clone / writable app directory, or rebuild Docker on the host.'
            ),
            'mode': mode,
        }, status_code=400)
    try:
        latest = await _fetch_latest_release_tag()
    except Exception as e:
        return JSONResponse({'error': str(e)}, status_code=502)
    if not latest:
        return JSONResponse({'error': 'Could not resolve latest release tag'}, status_code=502)
    if not version_gt(latest, CURRENT_VERSION):
        return {
            'status': 'success',
            'up_to_date': True,
            'current_version': CURRENT_VERSION,
            'latest_version': latest,
            'message': 'Already on the latest version',
        }

    result = await asyncio.to_thread(updater.apply_update, latest, True)
    if result.get('status') != 'success':
        return JSONResponse({'error': result.get('message') or 'Update failed', **result}, status_code=500)
    if result.get('restart'):
        UpdateManager.schedule_restart(application_path, 1.5)
    result['up_to_date'] = False
    result['previous_version'] = CURRENT_VERSION
    return enrich_update_result(request, result)


@app.get('/api/settings/tunnels/status', tags=["Settings"])
async def api_tunnels_status(request: Request):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    return {
        'local_server': get_panel_local_url(request),
        'cloudflare': get_tunnel_status('cloudflare'),
        'ngrok': get_tunnel_status('ngrok'),
        'warp': get_warp_status(),
        'nordvpn': get_nordvpn_status(),
    }


@app.post('/api/settings/tunnels/{provider}/install', tags=["Settings"])
async def api_tunnel_install(request: Request, provider: str):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    if provider not in TUNNEL_RUNTIMES:
        return JSONResponse({'error': 'Unsupported tunnel provider'}, status_code=400)
    try:
        await asyncio.to_thread(install_tunnel_binary, provider)
        return get_tunnel_status(provider)
    except Exception as e:
        logger.exception(f"Error installing {provider} tunnel")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/settings/tunnels/{provider}/start', tags=["Settings"])
async def api_tunnel_start(request: Request, provider: str, payload: TunnelStartRequest = TunnelStartRequest()):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    if provider not in TUNNEL_RUNTIMES:
        return JSONResponse({'error': 'Unsupported tunnel provider'}, status_code=400)
    try:
        local_url = get_panel_tunnel_target_url()
        await asyncio.to_thread(start_tunnel, provider, local_url, payload.authtoken or '')
        status = await wait_for_tunnel_url(provider)
        if not status.get('running'):
            return JSONResponse({'error': status.get('last_error') or 'Tunnel process stopped'}, status_code=500)
        return status
    except Exception as e:
        logger.exception(f"Error starting {provider} tunnel")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/settings/tunnels/{provider}/stop', tags=["Settings"])
async def api_tunnel_stop(request: Request, provider: str):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    if provider not in TUNNEL_RUNTIMES:
        return JSONResponse({'error': 'Unsupported tunnel provider'}, status_code=400)
    try:
        await asyncio.to_thread(stop_tunnel, provider)
        return get_tunnel_status(provider)
    except Exception as e:
        logger.exception(f"Error stopping {provider} tunnel")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.delete('/api/settings/tunnels/{provider}', tags=["Settings"])
async def api_tunnel_delete(request: Request, provider: str):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    if provider not in TUNNEL_RUNTIMES:
        return JSONResponse({'error': 'Unsupported tunnel provider'}, status_code=400)
    try:
        await asyncio.to_thread(delete_tunnel_binary, provider)
        return get_tunnel_status(provider)
    except Exception as e:
        logger.exception(f"Error deleting {provider} tunnel")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/settings/warp/connect', tags=["Settings"])
async def api_warp_connect(request: Request):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        return await asyncio.to_thread(enable_warp)
    except Exception as e:
        logger.exception("Error connecting Cloudflare WARP")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/settings/warp/disconnect', tags=["Settings"])
async def api_warp_disconnect(request: Request):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        return await asyncio.to_thread(disable_warp)
    except Exception as e:
        logger.exception("Error disconnecting Cloudflare WARP")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/settings/nordvpn/connect', tags=["Settings"])
async def api_nordvpn_connect(request: Request, req: NordvpnConnectRequest = NordvpnConnectRequest()):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        return await asyncio.to_thread(enable_nordvpn, req.country or '', req.city or '')
    except Exception as e:
        logger.exception("Error connecting NordVPN")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.post('/api/settings/nordvpn/disconnect', tags=["Settings"])
async def api_nordvpn_disconnect(request: Request):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        return await asyncio.to_thread(disable_nordvpn)
    except Exception as e:
        logger.exception("Error disconnecting NordVPN")
        return JSONResponse({'error': str(e)}, status_code=500)


# @app.post('/api/settings/save')
# async def api_save_settings(request: Request, body: SaveSettingsRequest):
#     _check_admin(request)
#     data = load_data()
#     data['settings'] = body.dict()
#     save_data(data)
    
#     # Trigger sync if enabled
#     if body.sync.remnawave_sync_users:
#         await sync_users_with_remnawave(data)
#         save_data(data)
        
#     return {'status': 'success'}

@app.post('/api/settings/save', tags=["Settings"])
async def save_settings(request: Request, payload: SaveSettingsRequest):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    data['settings']['appearance'] = payload.appearance.dict()
    data['settings']['sync'] = payload.sync.dict()
    data['settings']['captcha'] = payload.captcha.dict()
    data['settings']['telegram'] = payload.telegram.dict()
    data['settings']['ssl'] = payload.ssl.dict()

    existing_guest = dict(data.get('settings', {}).get('guest') or {})
    guest = payload.guest.dict()
    password = (guest.pop('password', None) or '').strip()
    clear_password = bool(guest.pop('clear_password', False))
    token = (guest.get('token') or existing_guest.get('token') or '').strip()
    if guest.get('enabled') and not token:
        token = secrets.token_urlsafe(16)
    guest['token'] = token
    if clear_password:
        guest['password_hash'] = None
    elif password:
        guest['password_hash'] = hash_password(password)
    else:
        guest['password_hash'] = existing_guest.get('password_hash')
    data['settings']['guest'] = guest
    data['settings']['donate'] = payload.donate.dict()

    save_data(data)
    logger.info("Settings saved (including captcha and telegram)")

    # Handle bot start/stop based on new telegram settings
    tg_cfg = payload.telegram
    if tg_cfg.enabled and tg_cfg.token:
        if not tg_bot.is_running():
            logger.info("Starting Telegram bot (settings save)...")
            tg_bot.launch_bot(tg_cfg.token, load_data, generate_vpn_link, save_data)
    else:
        if tg_bot.is_running():
            logger.info("Stopping Telegram bot (settings save)...")
            asyncio.create_task(tg_bot.stop_bot())

    return {"status": "success", "bot_running": tg_bot.is_running(), "guest_token": token}


@app.post('/api/settings/telegram/toggle', tags=["Settings"])
async def api_telegram_toggle(request: Request):
    """Quick enable/disable of the bot without a full settings save."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    tg_cfg = data.get('settings', {}).get('telegram', {})
    token = tg_cfg.get('token', '')
    if not token:
        return JSONResponse({'error': 'Telegram token not set in settings'}, status_code=400)

    if tg_bot.is_running():
        await tg_bot.stop_bot()
        tg_cfg['enabled'] = False
        data['settings']['telegram'] = tg_cfg
        save_data(data)
        return {'status': 'stopped', 'bot_running': False}
    else:
        tg_bot.launch_bot(token, load_data, generate_vpn_link, save_data)
        tg_cfg['enabled'] = True
        data['settings']['telegram'] = tg_cfg
        save_data(data)
        return {'status': 'started', 'bot_running': True}

@app.post('/api/settings/sync_now', tags=["Settings"])
async def api_sync_now(request: Request):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    count, msg = await sync_users_with_remnawave(data)
    return {'status': 'success', 'count': count, 'message': msg}


@app.post('/api/settings/sync_delete', tags=["Settings"])
async def api_sync_delete(request: Request):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    to_delete_ids = [u['id'] for u in data['users'] if u.get('remnawave_uuid')]
    if to_delete_ids:
        await perform_mass_operations(delete_uids=to_delete_ids)
    return {'status': 'success', 'count': len(to_delete_ids)}


@app.post('/api/settings/xui_sync_now', tags=["Settings"])
async def api_xui_sync_now(request: Request):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()

    try:
        body = await request.json()
    except Exception:
        body = {}
    if isinstance(body, dict) and body:
        sync_cfg = data.setdefault('settings', {}).setdefault('sync', {})
        for key in (
            'xui_url', 'xui_username', 'xui_password', 'xui_api_token',
            'xui_create_conns', 'xui_server_id', 'xui_protocol', 'xui_sync_users', 'xui_sync',
            'xui_inbound_id', 'xui_sub_url',
        ):
            if key in body and body[key] is not None:
                sync_cfg[key] = body[key]
        async with DATA_LOCK:
            current = load_data()
            current.setdefault('settings', {}).setdefault('sync', {}).update(sync_cfg)
            save_data(current)
        data = current

    count, msg = await sync_users_with_xui(data, force=True)
    ok = count > 0 or (isinstance(msg, str) and msg.startswith('Successfully'))
    return {
        'status': 'success' if ok else 'error',
        'count': count,
        'message': msg,
    }


@app.post('/api/settings/xui_sync_delete', tags=["Settings"])
async def api_xui_sync_delete(request: Request):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    to_delete_ids = [u['id'] for u in data['users'] if u.get('xui_email')]
    if to_delete_ids:
        await perform_mass_operations(delete_uids=to_delete_ids)
    return {'status': 'success', 'count': len(to_delete_ids)}


@app.get('/api/settings/xui/inbounds', tags=["Settings"])
async def api_xui_list_inbounds(request: Request, panel_id: str = ''):
    """List VLESS inbounds from a 3x-ui panel (by panel_id or primary)."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        from managers.xui_api import xui_list_vless_inbounds
        from managers.xui_servers import ensure_xui_servers, get_xui_server
        ensure_xui_servers(data.setdefault('settings', {}))
        panel = get_xui_server(data.get('settings') or {}, panel_id or None)
        if not panel:
            return JSONResponse({'error': 'No 3x-ui servers configured'}, status_code=400)
        inbounds = await xui_list_vless_inbounds(data.get('settings', {}), panel_id=panel.get('id'))
        return {
            'inbounds': inbounds,
            'panel_id': panel.get('id'),
            'panel_name': panel.get('name'),
            'sub_url': panel.get('sub_url') or '',
        }
    except Exception as e:
        logger.exception("Error listing 3x-ui inbounds")
        return JSONResponse({'error': str(e)}, status_code=500)


@app.get('/api/settings/xui/servers', tags=["Settings"])
async def api_xui_list_servers(request: Request):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    from managers.xui_servers import list_xui_servers, public_server_view, ensure_xui_servers
    ensure_xui_servers(data.setdefault('settings', {}))
    servers = [public_server_view(s) for s in list_xui_servers(data.get('settings') or {})]
    return {'servers': servers}


@app.post('/api/settings/xui/servers', tags=["Settings"])
async def api_xui_create_server(request: Request, req: XuiServerRequest):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        from managers.xui_servers import upsert_xui_server, public_server_view, ensure_xui_servers
        ensure_xui_servers(data.setdefault('settings', {}))
        server = upsert_xui_server(data['settings'], req.model_dump())
        save_data(data)
        return {'status': 'success', 'server': public_server_view(server)}
    except Exception as e:
        logger.exception('Error creating 3x-ui server')
        return JSONResponse({'error': str(e)}, status_code=400)


@app.put('/api/settings/xui/servers/{panel_id}', tags=["Settings"])
async def api_xui_update_server(request: Request, panel_id: str, req: XuiServerRequest):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        data = load_data()
        from managers.xui_servers import upsert_xui_server, public_server_view, get_xui_server, ensure_xui_servers
        ensure_xui_servers(data.setdefault('settings', {}))
        if not get_xui_server(data.get('settings') or {}, panel_id):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = upsert_xui_server(data['settings'], req.model_dump(), panel_id=panel_id)
        save_data(data)
        return {'status': 'success', 'server': public_server_view(server)}
    except Exception as e:
        logger.exception('Error updating 3x-ui server')
        return JSONResponse({'error': str(e)}, status_code=400)


@app.delete('/api/settings/xui/servers/{panel_id}', tags=["Settings"])
async def api_xui_delete_server(request: Request, panel_id: str):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    from managers.xui_servers import delete_xui_server, ensure_xui_servers
    ensure_xui_servers(data.setdefault('settings', {}))
    if not delete_xui_server(data['settings'], panel_id):
        return JSONResponse({'error': 'Server not found'}, status_code=404)
    save_data(data)
    return {'status': 'success'}


@app.get('/api/servers/{server_id}/{protocol}/clients', tags=["Connections"])
async def api_get_server_clients(request: Request, server_id: int, protocol: str):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        if not protocol or protocol_base(protocol) not in CLIENT_VPN_BASES:
            return JSONResponse(
                {'error': f'Protocol "{protocol}" does not support client listing'},
                status_code=400,
            )
        data = await load_data_async()
        if server_id >= len(data['servers']):
            return JSONResponse({'error': 'Server not found'}, status_code=404)
        server = data['servers'][server_id]
        cache_key = f'clients:{server_id}:{protocol}'
        clients = api_cache.get(cache_key, ttl=8)
        if clients is None:
            def _fetch(ssh):
                manager = get_protocol_manager(ssh, protocol)
                if not hasattr(manager, 'get_clients'):
                    raise AttributeError(f'Manager for "{protocol}" has no get_clients')
                return _manager_call(manager, 'get_clients', protocol) or []

            try:
                clients = await asyncio.to_thread(run_ssh, server, _fetch)
            except AttributeError as e:
                return JSONResponse({'error': str(e)}, status_code=400)
            api_cache.set(cache_key, clients)

        # Filter: only show clients that are not assigned to anyone in the panel
        assigned_ids = {
            c['client_id']
            for c in data.get('user_connections', [])
            if c.get('server_id') == server_id and c.get('protocol') == protocol
        }

        filtered = []
        for c in clients or []:
            cid = c.get('clientId') or c.get('client_id') or c.get('id')
            if not cid or cid in assigned_ids:
                continue
            filtered.append({
                'id': cid,
                'name': (c.get('userData') or {}).get('clientName')
                    or c.get('name')
                    or c.get('email')
                    or 'Unnamed',
            })

        return {'clients': filtered}
    except Exception as e:
        logger.exception("Error getting server clients")
        return JSONResponse({'error': str(e) or e.__class__.__name__}, status_code=500)


@app.get('/api/settings/tokens', tags=["API Tokens"])
async def api_list_tokens(request: Request):
    """List metadata for every API token. The raw token value is never
    returned by this endpoint — only its prefix and timestamps are visible
    after creation, by design."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    data = load_data()
    users_by_id = {u['id']: u for u in data.get('users', [])}
    tokens = []
    for t in data.get('api_tokens', []):
        owner = users_by_id.get(t.get('user_id'))
        tokens.append({
            'id': t.get('id'),
            'name': t.get('name', ''),
            'token_prefix': t.get('token_prefix', ''),
            'created_at': t.get('created_at'),
            'last_used_at': t.get('last_used_at'),
            'owner': owner['username'] if owner else None,
            'owner_id': t.get('user_id'),
        })
    return {'tokens': tokens}


@app.post('/api/settings/tokens', tags=["API Tokens"])
async def api_create_token(request: Request, req: CreateApiTokenRequest):
    """Issue a new bearer token. The full token value is returned **once** in
    the response and never persisted in plaintext — only its SHA-256 hash is
    stored, so a leaked data.json file alone cannot be used to authenticate.
    Save the value at creation time; if it's lost the token must be recreated.
    """
    cur = _check_admin(request)
    if not cur:
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    name = (req.name or '').strip()
    if not name:
        return JSONResponse({'error': 'Token name is required'}, status_code=400)

    raw = _generate_api_token()
    token_id = str(uuid.uuid4())
    # Show enough of the token in the UI to identify it later, but not enough
    # to reconstruct it: the prefix + first 4 chars of the secret part.
    token_prefix = raw[:len(API_TOKEN_PREFIX) + 4]

    entry = {
        'id': token_id,
        'name': name,
        'token_hash': _hash_api_token(raw),
        'token_prefix': token_prefix,
        'user_id': cur['id'],
        'created_at': datetime.now().isoformat(),
        'last_used_at': None,
    }
    async with DATA_LOCK:
        await asyncio.to_thread(insert_api_token, entry)

    # `token` is returned only here — subsequent reads will not see it.
    return {
        'status': 'success',
        'id': token_id,
        'name': name,
        'token': raw,
        'token_prefix': token_prefix,
        'created_at': entry['created_at'],
    }


@app.delete('/api/settings/tokens/{token_id}', tags=["API Tokens"])
async def api_revoke_token(request: Request, token_id: str):
    """Permanently revoke a token. The associated bearer value can never be
    used again, even if the same name is reissued — every token has its own hash."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    async with DATA_LOCK:
        deleted = await asyncio.to_thread(delete_api_token, token_id)
        if not deleted:
            return JSONResponse({'error': 'Token not found'}, status_code=404)
    return {'status': 'success'}


@app.get('/api/settings/backup/download', tags=["Settings"])
async def api_backup_download(request: Request):
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        content = await asyncio.to_thread(export_database_sql)
    except Exception as e:
        logger.exception('Database backup failed')
        return JSONResponse({'error': str(e)}, status_code=500)
    filename = backup_filename()
    return StreamingResponse(
        io.BytesIO(content),
        media_type='application/sql',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'},
    )


@app.get('/api/settings/backup/download/json', tags=["Settings"])
async def api_backup_download_json(request: Request):
    """Legacy JSON export (same shape as old data.json)."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    payload = await asyncio.to_thread(export_data_dict)
    content = json.dumps(payload, indent=2, ensure_ascii=False).encode('utf-8')
    return StreamingResponse(
        io.BytesIO(content),
        media_type='application/json',
        headers={'Content-Disposition': 'attachment; filename="data.json"'},
    )


@app.post('/api/settings/backup/restore', tags=["Settings"])
@app.post('/api/settings/backup/import', tags=["Settings"])
async def api_backup_restore(request: Request, file: UploadFile = File(...)):
    """Import panel database from a .sql / .sql.gz dump or legacy data.json."""
    if not _check_admin(request):
        return JSONResponse({'error': 'Forbidden'}, status_code=403)
    try:
        content = await file.read()
        if not content:
            return JSONResponse({'error': 'Empty file'}, status_code=400)

        filename = (file.filename or '').lower()
        is_gzip = filename.endswith('.gz') or content[:2] == b'\x1f\x8b'
        is_json = (
            not is_gzip
            and (filename.endswith('.json') or content.lstrip()[:1] in (b'{', b'['))
        )

        if is_json:
            try:
                backup_data = json.loads(content)
            except json.JSONDecodeError:
                return JSONResponse({'error': 'Invalid JSON format'}, status_code=400)

            required_keys = ['servers', 'users']
            missing = [k for k in required_keys if k not in backup_data]
            if missing:
                return JSONResponse({'error': f'Invalid structure. Missing keys: {", ".join(missing)}'}, status_code=400)

            if not isinstance(backup_data['servers'], list) or not isinstance(backup_data['users'], list):
                return JSONResponse({'error': 'Invalid structure: servers and users must be lists'}, status_code=400)

            backup_data.setdefault('user_connections', [])
            backup_data.setdefault('api_tokens', [])
            backup_data.setdefault('invite_links', [])
            backup_data.setdefault('settings', {})

            try:
                backup_data = normalize_import_data(backup_data)
                async with DATA_LOCK:
                    save_data(backup_data, replace_tokens=True)
            except Exception as e:
                invalidate_data_cache()
                logger.exception('JSON backup restore failed')
                return JSONResponse({'error': f'Import failed: {e}'}, status_code=400)
            return {'status': 'success', 'format': 'json'}

        try:
            await asyncio.to_thread(restore_database_sql, content)
        except Exception as e:
            logger.exception('Database restore failed')
            return JSONResponse({'error': str(e)}, status_code=400)
        return {'status': 'success', 'format': 'sql'}
    except Exception as e:
        logger.exception("Error during restore")
        return JSONResponse({'error': str(e)}, status_code=500)


if __name__ == '__main__':
    data = load_data()
    ssl_conf = data.get('settings', {}).get('ssl', {})
    
    cert_file = ssl_conf.get('cert_path')
    key_file = ssl_conf.get('key_path')
    
    # If text is provided, create temporary files
    temp_dir = os.path.join(os.getcwd(), 'ssl_temp')
    if ssl_conf.get('enabled'):
        if ssl_conf.get('cert_text') or ssl_conf.get('key_text'):
            if not os.path.exists(temp_dir):
                os.makedirs(temp_dir)
            
            if ssl_conf.get('cert_text'):
                cert_file = os.path.join(temp_dir, 'cert.pem')
                with open(cert_file, 'w') as f:
                    f.write(ssl_conf['cert_text'].strip() + '\n')
            
            if ssl_conf.get('key_text'):
                key_file = os.path.join(temp_dir, 'key.pem')
                with open(key_file, 'w') as f:
                    f.write(ssl_conf['key_text'].strip() + '\n')

    port = get_panel_listen_port(data)
    uvicorn_kwargs = {
        "app": app,
        "host": "0.0.0.0",
        "port": port,
    }
    logger.info(f"Amnezia Web Panel {CURRENT_VERSION} listening on http://0.0.0.0:{port}")
    
    if panel_ssl_active(data) and cert_file and key_file:
        if os.path.exists(cert_file) and os.path.exists(key_file):
            logger.info(f"Starting panel with HTTPS enabled on domain: {ssl_conf.get('domain')} at port {uvicorn_kwargs['port']}")
            uvicorn_kwargs["ssl_certfile"] = cert_file
            uvicorn_kwargs["ssl_keyfile"] = key_file
        else:
            logger.error("SSL certificates not found at specified paths. Starting with HTTP.")

    uvicorn.run(**uvicorn_kwargs)
