"""Panel self-update from the configured Gitea repository (git or release archive)."""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import zipfile
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_REPO_URL = 'https://git.de4ima.uk/Evilfox/Amnezia-Web-Panel-main'
DEFAULT_GIT_URL = 'https://git.de4ima.uk/Evilfox/Amnezia-Web-Panel-main.git'
DEFAULT_API_LATEST = 'https://git.de4ima.uk/api/v1/repos/Evilfox/Amnezia-Web-Panel-main/releases/latest'
DEFAULT_API_TAGS = 'https://git.de4ima.uk/api/v1/repos/Evilfox/Amnezia-Web-Panel-main/tags'
UPDATE_REMOTE = 'panel-update'

ARCHIVE_SKIP_DIRS = frozenset({
    '__pycache__', '.git', 'bin', 'data', 'node_modules', '.venv', 'venv', '.cursor',
})
ARCHIVE_SKIP_FILES = frozenset({
    '.env', 'data.json', 'tunnels_state.json',
})


def _env(name: str, default: str) -> str:
    return (os.environ.get(name) or default).strip()


def repo_url() -> str:
    return _env('PANEL_UPDATE_REPO_URL', DEFAULT_REPO_URL).rstrip('/')


def git_url() -> str:
    return _env('PANEL_UPDATE_GIT_URL', DEFAULT_GIT_URL)


def api_latest_url() -> str:
    return _env('PANEL_UPDATE_API_LATEST', DEFAULT_API_LATEST)


def api_tags_url() -> str:
    return _env('PANEL_UPDATE_API_TAGS', DEFAULT_API_TAGS)


def parse_version(value: str) -> tuple:
    """Parse semver-ish tags like v2.3.0 / 2.3.0-beta into a comparable tuple."""
    raw = (value or '').strip()
    if not raw:
        return (0, 0, 0, 1, '')
    raw = raw.lstrip('vV')
    main, _, pre = raw.partition('-')
    parts = []
    for piece in main.split('.'):
        if piece.isdigit():
            parts.append(int(piece))
        else:
            m = re.match(r'(\d+)', piece or '')
            parts.append(int(m.group(1)) if m else 0)
    while len(parts) < 3:
        parts.append(0)
    pre_rank = 0 if not pre else 1
    return (parts[0], parts[1], parts[2], pre_rank, pre)


def version_gt(a: str, b: str) -> bool:
    return parse_version(a) > parse_version(b)


def normalize_tag(value: str) -> str:
    tag = (value or '').strip()
    if not tag:
        return ''
    return tag if tag.startswith('v') else f'v{tag}'


def pick_newest_tag(tags: list[str]) -> str:
    """Return the highest semver-ish tag from a list (empty if none)."""
    best = ''
    for raw in tags or []:
        tag = normalize_tag(str(raw or ''))
        if not tag:
            continue
        if not best or version_gt(tag, best):
            best = tag
    return best


def http_get_json(url: str, timeout: float = 15.0) -> object:
    req = urllib.request.Request(
        url,
        headers={'Accept': 'application/json', 'User-Agent': 'Amnezia-Web-Panel-Updater'},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode('utf-8', errors='replace') or 'null')


def resolve_latest_remote_version() -> dict:
    """Pick newest version from Gitea releases/latest and /tags (tags win if newer)."""
    latest = ''
    html_url = f'{repo_url()}/releases'
    body = ''
    source = ''

    try:
        data = http_get_json(api_latest_url())
        if isinstance(data, dict):
            cand = normalize_tag(data.get('tag_name') or data.get('name') or '')
            if cand:
                latest = cand
                html_url = (data.get('html_url') or html_url).strip() or html_url
                body = (data.get('body') or '')[:4000]
                source = 'release'
    except Exception as exc:
        logger.info('Release API lookup failed: %s', exc)

    try:
        tags_payload = http_get_json(f'{api_tags_url()}?limit=50')
        names = []
        if isinstance(tags_payload, list):
            for item in tags_payload:
                if isinstance(item, dict):
                    names.append(item.get('name') or '')
                else:
                    names.append(str(item))
        tag_best = pick_newest_tag(names)
        if tag_best and (not latest or version_gt(tag_best, latest)):
            latest = tag_best
            html_url = f'{repo_url()}/releases/tag/{tag_best}'
            body = ''
            source = 'tag'
    except Exception as exc:
        logger.info('Tags API lookup failed: %s', exc)

    return {
        'latest_version': latest,
        'html_url': html_url,
        'body': body,
        'source': source or 'none',
        'releases_url': f'{repo_url()}/releases',
    }


def _run(cmd: list, cwd: str, timeout: int = 120) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding='utf-8',
            errors='replace',
        )
        return proc.returncode, (proc.stdout or '').strip(), (proc.stderr or '').strip()
    except FileNotFoundError:
        return 127, '', f'Command not found: {cmd[0]}'
    except subprocess.TimeoutExpired:
        return 124, '', f'Timeout running: {" ".join(cmd)}'


class UpdateManager:
    def __init__(self, app_root: str, current_version: str):
        self.app_root = os.path.abspath(app_root)
        self.current_version = current_version

    def _in_docker(self) -> bool:
        return os.path.exists('/.dockerenv') or os.environ.get('PANEL_IN_DOCKER') == '1'

    def _docker_update_allowed(self) -> bool:
        if os.environ.get('PANEL_UPDATE_DISABLE_DOCKER', '').strip().lower() in ('1', 'true', 'yes'):
            return False
        # In-container archive updates are allowed by default when /app is writable.
        return True

    def _app_root_writable(self) -> bool:
        probe = os.path.join(self.app_root, '.panel_update_write_probe')
        try:
            with open(probe, 'w', encoding='utf-8') as fh:
                fh.write('ok')
            os.remove(probe)
            return True
        except OSError:
            return False

    def detect_mode(self) -> dict:
        frozen = bool(getattr(sys, 'frozen', False))
        in_docker = self._in_docker()
        git_dir = os.path.join(self.app_root, '.git')
        is_git = os.path.isdir(git_dir)
        git_ok = False
        if is_git and not frozen:
            code, _, _ = _run(['git', '--version'], self.app_root, timeout=10)
            git_ok = code == 0

        writable = self._app_root_writable()
        can_git = bool(git_ok and is_git and not frozen)
        can_archive = bool(
            writable
            and not frozen
            and (not in_docker or self._docker_update_allowed())
        )
        can_auto = can_git or can_archive

        if can_git:
            method = 'git'
        elif can_archive:
            method = 'archive'
        elif in_docker:
            method = 'docker'
        elif frozen:
            method = 'binary'
        else:
            method = 'manual'

        return {
            'mode': method,
            'update_method': method,
            'can_auto_update': can_auto,
            'can_git_update': can_git,
            'can_archive_update': can_archive,
            'is_git': is_git,
            'frozen': frozen,
            'in_docker': in_docker,
            'writable': writable,
            'app_root': self.app_root,
            'repo_url': repo_url(),
            'git_url': git_url(),
        }

    def _ensure_update_remote(self) -> Optional[str]:
        code, out, err = _run(['git', 'remote'], self.app_root, timeout=15)
        if code != 0:
            return err or out or 'git remote failed'
        remotes = set((out or '').split())
        target = git_url()
        if UPDATE_REMOTE in remotes:
            code, _, err = _run(
                ['git', 'remote', 'set-url', UPDATE_REMOTE, target],
                self.app_root,
                timeout=15,
            )
        else:
            code, _, err = _run(
                ['git', 'remote', 'add', UPDATE_REMOTE, target],
                self.app_root,
                timeout=15,
            )
        if code != 0:
            return err or 'Failed to configure update remote'
        return None

    def working_tree_dirty(self) -> bool:
        code, out, _ = _run(['git', 'status', '--porcelain'], self.app_root, timeout=30)
        return code == 0 and bool(out.strip())

    def _pip_install(self) -> tuple[bool, str]:
        req = os.path.join(self.app_root, 'requirements.txt')
        if not os.path.isfile(req):
            return True, ''
        code_p, out_p, err_p = _run(
            [sys.executable, '-m', 'pip', 'install', '-r', req],
            self.app_root,
            timeout=300,
        )
        log = (out_p or err_p or '')[:1500]
        return code_p == 0, log

    def _apply_git_update(self, target: str, allow_dirty: bool) -> dict:
        if not allow_dirty and self.working_tree_dirty():
            return {
                'status': 'error',
                'message': (
                    'Working tree has local changes. Confirm update anyway to force checkout, '
                    'or commit/stash changes first.'
                ),
                'needs_confirm_dirty': True,
            }

        err = self._ensure_update_remote()
        if err:
            return {'status': 'error', 'message': err}

        code, out, stderr = _run(
            ['git', 'fetch', '--tags', '--force', UPDATE_REMOTE],
            self.app_root,
            timeout=180,
        )
        if code != 0:
            return {'status': 'error', 'message': f'git fetch failed: {stderr or out or code}'}

        # Ensure tag is present locally
        code, _, _ = _run(
            ['git', 'rev-parse', '-q', '--verify', f'refs/tags/{target}'],
            self.app_root,
            timeout=15,
        )
        if code != 0:
            _run(
                ['git', 'fetch', '--depth', '1', UPDATE_REMOTE, f'refs/tags/{target}:refs/tags/{target}'],
                self.app_root,
                timeout=120,
            )

        checkout_ref = f'tags/{target}'
        code, out, stderr = _run(
            ['git', 'checkout', '--force', checkout_ref],
            self.app_root,
            timeout=60,
        )
        if code != 0:
            code_m, out_m, err_m = _run(
                ['git', 'checkout', '--force', '-B', 'main', f'{UPDATE_REMOTE}/main'],
                self.app_root,
                timeout=60,
            )
            if code_m != 0:
                return {
                    'status': 'error',
                    'message': f'git checkout {target} failed: {stderr or out or err_m or out_m}',
                }
            checkout_ref = f'{UPDATE_REMOTE}/main'

        ok, pip_log = self._pip_install()
        if not ok:
            return {
                'status': 'error',
                'message': f'pip install failed after checkout: {pip_log[:500]}',
                'checkout': checkout_ref,
                'method': 'git',
            }

        return {
            'status': 'success',
            'message': f'Updated to {target} via git. Panel will restart.',
            'target_version': target,
            'checkout': checkout_ref,
            'pip': pip_log[:500],
            'method': 'git',
            'restart': True,
        }

    def _archive_urls(self, tag: str) -> list[str]:
        urls: list[str] = []
        api_base = api_latest_url().rsplit('/releases/latest', 1)[0]
        for endpoint in (f'{api_base}/releases/tags/{tag}', api_latest_url()):
            try:
                req = urllib.request.Request(
                    endpoint,
                    headers={'Accept': 'application/json', 'User-Agent': 'Amnezia-Web-Panel-Updater'},
                )
                with urllib.request.urlopen(req, timeout=30) as resp:
                    payload = json.loads(resp.read().decode('utf-8', errors='replace') or '{}')
                zipball = (payload.get('zipball_url') or '').strip()
                if zipball:
                    urls.append(zipball)
            except Exception:
                pass
        base = repo_url()
        urls.extend([
            f'{base}/archive/{tag}.zip',
            f'{api_base}/archive/{tag}.zip',
        ])
        seen = set()
        ordered: list[str] = []
        for url in urls:
            if url and url not in seen:
                seen.add(url)
                ordered.append(url)
        return ordered

    def _download_archive(self, tag: str, dest_path: str) -> None:
        last_err = 'unknown error'
        for url in self._archive_urls(tag):
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Amnezia-Web-Panel-Updater'})
                with urllib.request.urlopen(req, timeout=180) as resp:
                    with open(dest_path, 'wb') as out:
                        shutil.copyfileobj(resp, out)
                if os.path.getsize(dest_path) > 1024:
                    return
                last_err = f'empty archive from {url}'
            except urllib.error.HTTPError as e:
                last_err = f'HTTP {e.code} for {url}'
            except Exception as e:
                last_err = str(e)
        raise RuntimeError(f'Failed to download release archive: {last_err}')

    @staticmethod
    def _extract_zip_root(extract_dir: str) -> str:
        entries = [e for e in os.listdir(extract_dir) if e not in ('.', '..')]
        if len(entries) == 1:
            only = os.path.join(extract_dir, entries[0])
            if os.path.isdir(only):
                return only
        return extract_dir

    def _verify_tree(self, root: str) -> Optional[str]:
        app_py = os.path.join(root, 'app.py')
        if not os.path.isfile(app_py):
            return 'Release archive is missing app.py'
        code, _, err = _run([sys.executable, '-m', 'py_compile', app_py], root, timeout=60)
        if code != 0:
            return f'Updated app.py failed validation: {err or code}'
        return None

    def _sync_tree(self, src_root: str) -> None:
        for root, dirs, files in os.walk(src_root):
            dirs[:] = [d for d in dirs if d not in ARCHIVE_SKIP_DIRS]
            rel = os.path.relpath(root, src_root)
            dest_root = self.app_root if rel in ('.', '') else os.path.join(self.app_root, rel)
            os.makedirs(dest_root, exist_ok=True)
            for fname in files:
                if fname in ARCHIVE_SKIP_FILES:
                    continue
                src_file = os.path.join(root, fname)
                dest_file = os.path.join(dest_root, fname)
                shutil.copy2(src_file, dest_file)

    def _apply_archive_update(self, target: str) -> dict:
        tmpdir = tempfile.mkdtemp(prefix='panel-update-')
        zip_path = os.path.join(tmpdir, f'{target}.zip')
        extract_dir = os.path.join(tmpdir, 'extract')
        try:
            self._download_archive(target, zip_path)
            os.makedirs(extract_dir, exist_ok=True)
            with zipfile.ZipFile(zip_path, 'r') as zf:
                zf.extractall(extract_dir)
            src_root = self._extract_zip_root(extract_dir)
            if not os.path.isdir(src_root):
                return {'status': 'error', 'message': 'Invalid release archive layout'}
            verify_err = self._verify_tree(src_root)
            if verify_err:
                return {'status': 'error', 'message': verify_err, 'method': 'archive'}
            self._sync_tree(src_root)
        except Exception as e:
            return {'status': 'error', 'message': str(e), 'method': 'archive'}
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

        ok, pip_log = self._pip_install()
        if not ok:
            return {
                'status': 'error',
                'message': f'Files updated but pip install failed: {pip_log[:500]}',
                'method': 'archive',
            }

        return {
            'status': 'success',
            'message': f'Updated to {target} from release archive. Panel will restart.',
            'target_version': target,
            'pip': pip_log[:500],
            'method': 'archive',
            'restart': True,
        }

    def apply_update(self, target_version: str, allow_dirty: bool = False) -> dict:
        mode = self.detect_mode()
        target = normalize_tag(target_version)
        if not target or not re.match(r'^v\d+(\.\d+){0,3}([.-][\w.]+)?$', target):
            return {'status': 'error', 'message': f'Invalid target version: {target_version}'}

        if mode.get('can_git_update'):
            return self._apply_git_update(target, allow_dirty)
        if mode.get('can_archive_update'):
            return self._apply_archive_update(target)

        hint = (
            'Cannot update from inside this install. '
            'Use a git clone or writable source directory, or rebuild the Docker image on the host.'
        )
        if mode.get('in_docker'):
            hint = (
                'Docker image install: on the host run '
                '`git pull && docker compose up -d --build` '
                '(or set PANEL_UPDATE_ALLOW_DOCKER=1 if /app is bind-mounted).'
            )
        return {'status': 'error', 'message': hint, 'mode': mode}

    @staticmethod
    def schedule_restart(app_root: str, delay_sec: float = 1.5) -> None:
        in_docker = os.path.exists('/.dockerenv') or os.environ.get('PANEL_IN_DOCKER') == '1'

        def _restart():
            time.sleep(max(0.5, float(delay_sec)))
            cwd = os.path.abspath(app_root or os.getcwd())
            argv = [sys.executable] + sys.argv
            logger.info('Restarting panel after update: %s (cwd=%s, docker=%s)', argv, cwd, in_docker)
            if in_docker:
                # Let Docker restart policy bring the container back with updated /app files.
                os._exit(0)
            try:
                os.chdir(cwd)
                proc = subprocess.Popen(
                    argv,
                    cwd=cwd,
                    start_new_session=True,
                    close_fds=(os.name != 'nt'),
                )
                time.sleep(2.0)
                if proc.poll() is None:
                    logger.info('New panel process started (pid=%s), stopping old process', proc.pid)
                    os._exit(0)
            except Exception:
                logger.exception('subprocess restart failed; trying execv')
            try:
                os.chdir(cwd)
                os.execv(sys.executable, argv)
            except Exception:
                logger.exception('Failed to restart after update')
                os._exit(1)

        threading.Thread(target=_restart, name='panel-update-restart', daemon=False).start()
