"""
Mieru protocol manager — native mita server package (systemd).

Installs pinned release from https://github.com/enfein/mieru
Server binary: mita (systemd service), client: mieru.
Share links: mierus://user:pass@host?port=...&protocol=TCP&profile=default
"""

from __future__ import annotations

import json
import logging
import re
import secrets
import shlex
import string
import time
from urllib.parse import quote

logger = logging.getLogger(__name__)

MIERU_RELEASE = '3.28.0'
GITHUB_RELEASE = f'https://github.com/enfein/mieru/releases/download/v{MIERU_RELEASE}'
# Official mita UDS (v3.x). Older docs sometimes mention /var/run/mita.sock.
MITA_SOCK = '/var/run/mita/mita.sock'
MITA_SOCK_LEGACY = '/var/run/mita.sock'
# Official package persists applied config here. If this file has portBindings
# but no users, `mita run` (systemd) auto-starts the proxy and FATAL-exits
# with "socks5 server listening failed: no user found", crashing the daemon.
MITA_CONFIG_PB = '/etc/mita/server.conf.pb'
MITA_CONFIG_JSON = '/etc/mita/server.conf.json'


def _q(value):
    return shlex.quote(str(value))


def _rand_token(length=16):
    alphabet = string.ascii_lowercase + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def _sanitize_username(name):
    base = re.sub(r'[^a-zA-Z0-9_-]', '', (name or 'user').strip())[:24] or 'user'
    return f'{base}_{_rand_token(4)}'


class MieruManager:
    PROTOCOL = 'mieru'
    SERVICE_NAME = 'mita'
    BASE_DIR = '/opt/amnezia/mieru'
    DEFAULT_PORT = 2999

    def __init__(self, ssh, protocol='mieru'):
        self.ssh = ssh
        self.protocol = protocol or self.PROTOCOL
        self.base_dir = self.BASE_DIR
        self.clients_path = f'{self.base_dir}/clients.json'
        self.meta_path = f'{self.base_dir}/metadata.json'
        self.config_path = f'{self.base_dir}/server_config.json'

    # ===================== STATUS =====================

    def check_docker_installed(self):
        return True

    def _mita_installed(self):
        out, _, code = self.ssh.run_command('command -v mita 2>/dev/null')
        return code == 0 and bool(out.strip())

    def check_protocol_installed(self, protocol_type=None):
        return self._mita_installed() and self._panel_installed()

    def _panel_installed(self):
        out, _, code = self.ssh.run_sudo_command(f"test -f {_q(self.meta_path)} && echo yes")
        return code == 0 and 'yes' in out

    def _proxy_running(self):
        out, _, code = self.ssh.run_sudo_command('mita status 2>/dev/null')
        if code != 0:
            return False
        return 'RUNNING' in (out or '').upper()

    def check_container_running(self, protocol_type=None):
        return self._proxy_running()

    def get_logs(self, protocol_type=None, tail=200):
        tail = max(20, min(int(tail or 200), 2000))
        out, err, code = self.ssh.run_sudo_command(
            f"journalctl -u {self.SERVICE_NAME} -n {tail} --no-pager 2>&1",
            timeout=30,
        )
        text = (out or err or '').strip()
        if not text:
            status, _, _ = self.ssh.run_sudo_command('mita status 2>&1')
            text = (status or '').strip()
        if not text:
            text = f'(no logs: exit {code})'
        return text

    def get_container_diagnostics(self, protocol_type=None):
        running = self._proxy_running()
        out, _, _ = self.ssh.run_sudo_command(
            f"systemctl is-active {self.SERVICE_NAME} 2>/dev/null"
        )
        daemon_active = (out or '').strip() == 'active'
        diag = {
            'status': 'running' if running else ('idle' if daemon_active else 'stopped'),
            'running': running,
            'error_summary': '',
            'recent_logs': self.get_logs(protocol_type, tail=40),
        }
        if not self._mita_installed():
            diag['status'] = 'missing'
            diag['error_summary'] = 'mita package not installed'
        elif not running and daemon_active:
            status_out, _, _ = self.ssh.run_sudo_command('mita status 2>&1')
            if 'IDLE' in (status_out or '').upper():
                diag['error_summary'] = 'Proxy stopped (mita status IDLE)'
            elif status_out.strip():
                diag['error_summary'] = status_out.strip().splitlines()[-1][:160]
        elif not daemon_active:
            diag['error_summary'] = f'{self.SERVICE_NAME} systemd service is not active'
        return diag

    def get_server_status(self, protocol_type=None):
        protocol_type = protocol_type or self.protocol
        exists = self.check_protocol_installed(protocol_type)
        running = self.check_container_running(protocol_type) if exists else False
        meta = self._read_metadata() if exists else {}
        clients = self._read_clients() if exists else []
        port = int(meta.get('port') or self.DEFAULT_PORT)
        return {
            'container_exists': exists,
            'container_running': running,
            'port': port,
            'release': meta.get('release') or MIERU_RELEASE,
            'clients_count': len(clients),
            'protocol': protocol_type,
            'base_protocol': self.PROTOCOL,
            'instance': 1,
            'container_name': self.SERVICE_NAME,
        }

    # ===================== IO HELPERS =====================

    def _read_file(self, path):
        out, _, code = self.ssh.run_sudo_command(f"cat {_q(path)} 2>/dev/null")
        return out if code == 0 else ''

    def _write_file(self, path, content):
        import base64
        b64 = base64.b64encode((content or '').encode('utf-8')).decode('ascii')
        script = (
            f"mkdir -p $(dirname {_q(path)}) && "
            f"echo {_q(b64)} | base64 -d > {_q(path)} && "
            f"chmod 644 {_q(path)}"
        )
        out, err, code = self.ssh.run_sudo_command(f"sh -c {_q(script)}", timeout=30)
        if code != 0:
            raise RuntimeError(f'Failed to write {path}: {err or out}')

    def _read_metadata(self):
        raw = self._read_file(self.meta_path).strip()
        if not raw:
            return {}
        try:
            data = json.loads(raw)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _write_metadata(self, meta):
        self._write_file(self.meta_path, json.dumps(meta, indent=2))

    def _read_clients(self):
        raw = self._read_file(self.clients_path).strip()
        if not raw:
            return []
        try:
            data = json.loads(raw)
            return data if isinstance(data, list) else []
        except Exception:
            return []

    def _write_clients(self, clients):
        self._write_file(self.clients_path, json.dumps(clients, indent=2))

    def _make_bootstrap_client(self):
        return {
            'id': secrets.token_hex(8),
            'name': 'panel-bootstrap',
            'username': f'panel_{_rand_token(6)}',
            'password': _rand_token(20),
            'enabled': True,
            'bootstrap': True,
        }

    def _ensure_bootstrap_clients(self, clients):
        """Guarantee at least one enabled user so mita never starts with empty users."""
        clients = [c for c in (clients or []) if isinstance(c, dict)]
        enabled = [
            c for c in clients
            if c.get('enabled', True)
            and (c.get('username') or c.get('name') or c.get('id'))
            and (c.get('password') or '').strip()
        ]
        if enabled:
            return clients
        bootstrap = next((c for c in clients if c.get('bootstrap')), None)
        if bootstrap:
            bootstrap['enabled'] = True
            if not (bootstrap.get('password') or '').strip():
                bootstrap['password'] = _rand_token(20)
            if not (bootstrap.get('username') or '').strip():
                bootstrap['username'] = f'panel_{_rand_token(6)}'
            return clients
        clients.append(self._make_bootstrap_client())
        return clients

    def _daemon_needs_heal(self):
        failed, _, _ = self.ssh.run_sudo_command(
            f"systemctl is-failed {self.SERVICE_NAME} 2>/dev/null"
        )
        if (failed or '').strip() == 'failed':
            return True
        active, _, _ = self.ssh.run_sudo_command(
            f"systemctl is-active {self.SERVICE_NAME} 2>/dev/null"
        )
        # Daemon is up — ignore historical journal lines from earlier crashes.
        if (active or '').strip() == 'active':
            return False
        journal, _, _ = self.ssh.run_sudo_command(
            f"journalctl -u {self.SERVICE_NAME} -n 30 --no-pager --since '10 min ago' 2>&1",
            timeout=30,
        )
        return 'no user found' in (journal or '').lower()

    def _heal_mita_store(self, log=None):
        """Break the systemd crash loop caused by empty users in server.conf.pb.

        `mita run` auto-starts the proxy when portBindings exist; with zero users
        it FATAL-exits and never keeps the RPC socket up for `mita apply`.
        Wiping the store lets the daemon stay IDLE so we can re-apply a valid config.
        """
        if log is not None:
            log.append('healing mita store (empty users / crash loop)')
        self.ssh.run_sudo_command(
            f"systemctl stop {self.SERVICE_NAME} 2>/dev/null || true; "
            f"systemctl reset-failed {self.SERVICE_NAME} 2>/dev/null || true; "
            f"rm -f {_q(MITA_SOCK)} {_q(MITA_SOCK_LEGACY)} /var/run/mita/*.sock "
            f"{_q(MITA_CONFIG_PB)} {_q(MITA_CONFIG_JSON)} 2>/dev/null || true; "
            f"mkdir -p /var/run/mita /etc/mita 2>/dev/null || true",
            timeout=60,
        )
        # systemd StartLimitBurst: wait out "Start request repeated too quickly".
        time.sleep(6)

        clients = self._ensure_bootstrap_clients(self._read_clients())
        self._write_clients(clients)
        meta = self._read_metadata()
        port = int(meta.get('port') or self.DEFAULT_PORT)
        config = self._build_server_config(port, clients)
        self._write_file(self.config_path, json.dumps(config, indent=2))

        self.ssh.run_sudo_command(
            f"systemctl reset-failed {self.SERVICE_NAME} 2>/dev/null || true; "
            f"systemctl start {self.SERVICE_NAME}",
            timeout=60,
        )
        if not self._wait_for_rpc(timeout=60):
            # Second attempt after another rate-limit window.
            self.ssh.run_sudo_command(
                f"systemctl reset-failed {self.SERVICE_NAME} 2>/dev/null || true; "
                f"systemctl restart {self.SERVICE_NAME}",
                timeout=60,
            )
            time.sleep(3)
            if not self._wait_for_rpc(timeout=45):
                journal, _, _ = self.ssh.run_sudo_command(
                    f"journalctl -u {self.SERVICE_NAME} -n 50 --no-pager 2>&1",
                    timeout=30,
                )
                raise RuntimeError(
                    'mita daemon still not ready after heal. '
                    f'journal: {(journal or "").strip()[-600:]}'
                )
        out, err, code = self._mita_cli(
            ['apply', 'config', _q(self.config_path)],
            timeout=60,
        )
        if code != 0:
            raise RuntimeError(
                f'mita apply after heal failed: {(err or out or "").strip()}'
            )
        if log is not None:
            log.append('mita config re-applied with bootstrap user')

    def _ensure_daemon(self, log=None):
        """Ensure mita systemd unit is up and RPC socket answers."""
        self.ssh.run_sudo_command(
            f"systemctl enable {self.SERVICE_NAME} 2>/dev/null || true; "
            f"mkdir -p /var/run/mita /etc/mita 2>/dev/null || true",
            timeout=30,
        )
        # Official package expects the operating user in group `mita`.
        user_out, _, _ = self.ssh.run_command('id -un 2>/dev/null || echo root')
        op_user = (user_out or 'root').strip() or 'root'
        if op_user != 'root':
            self.ssh.run_sudo_command(
                f"usermod -a -G mita {_q(op_user)} 2>/dev/null || true",
                timeout=15,
            )

        if self._daemon_needs_heal():
            self._heal_mita_store(log)
            if log is not None:
                log.append('mita daemon is active')
            return

        self.ssh.run_sudo_command(
            f"systemctl start {self.SERVICE_NAME} 2>/dev/null || "
            f"systemctl restart {self.SERVICE_NAME} 2>/dev/null || true",
            timeout=60,
        )
        if not self._wait_for_rpc(timeout=45):
            # Crash loop / wrong socket / rate-limit — wipe store and recover.
            self._heal_mita_store(log)
        if log is not None:
            log.append('mita daemon is active')

    def _wait_for_rpc(self, timeout=30):
        deadline = time.time() + timeout
        sock_check = (
            f"(test -S {_q(MITA_SOCK)} || test -S {_q(MITA_SOCK_LEGACY)}) && echo ok"
        )
        while time.time() < deadline:
            # Prefer CLI status: if it answers IDLE/RUNNING, RPC is up
            # regardless of which sock path we expected.
            status_out, _, status_code = self.ssh.run_sudo_command(
                'mita status 2>&1',
                timeout=20,
            )
            text = (status_out or '').upper()
            if status_code == 0 and ('IDLE' in text or 'RUNNING' in text):
                return True
            sock_out, _, sock_code = self.ssh.run_sudo_command(sock_check)
            if sock_code == 0 and 'ok' in (sock_out or ''):
                time.sleep(1)
                continue
            time.sleep(1.5)
        return False

    def _mita_cli(self, args, timeout=60):
        """Run mita CLI as root so group/socket ACL is not an issue."""
        cmd = f"mita {' '.join(args)} 2>&1"
        return self.ssh.run_sudo_command(cmd, timeout=timeout)

    def _build_server_config(self, port, clients):
        clients = self._ensure_bootstrap_clients(clients)
        users = []
        for c in clients:
            if not c.get('enabled', True):
                continue
            username = (c.get('username') or c.get('name') or c.get('id') or '').strip()
            password = (c.get('password') or '').strip()
            if not username or not password:
                continue
            users.append({'name': username, 'password': password})
        # mita FATAL-exits on empty users during proxy start ("no user found").
        if not users:
            bootstrap = self._make_bootstrap_client()
            users = [{'name': bootstrap['username'], 'password': bootstrap['password']}]
        return {
            'portBindings': [{'port': int(port), 'protocol': 'TCP'}],
            'users': users,
            'loggingLevel': 'INFO',
            'mtu': 1400,
        }

    def _apply_config(self, config, reload_only=False):
        self._ensure_daemon()
        self._write_file(self.config_path, json.dumps(config, indent=2))
        out, err, code = self._mita_cli(
            ['apply', 'config', _q(self.config_path)],
            timeout=60,
        )
        if code != 0:
            # Recover from transient EOF / unavailable RPC.
            if self._is_rpc_error(out, err):
                self._ensure_daemon()
                out, err, code = self._mita_cli(
                    ['apply', 'config', _q(self.config_path)],
                    timeout=60,
                )
            if code != 0:
                raise RuntimeError((err or out or 'mita apply config failed').strip())

        if reload_only:
            # users/loggingLevel can hot-reload; fall back to full restart.
            reload_out, reload_err, reload_code = self._mita_cli(['reload'], timeout=30)
            if reload_code == 0:
                return
            logger.info('mita reload failed, falling back to stop/start: %s',
                        (reload_err or reload_out or '').strip())

        self._restart_proxy()

    def _is_rpc_error(self, *parts):
        text = ' '.join(str(p or '') for p in parts).lower()
        return any(token in text for token in (
            'rpc error',
            'unavailable',
            'error reading from server',
            'eof',
            'no such file or directory',
            'mita.sock',
            'connection refused',
        ))

    def _restart_proxy(self):
        # Always push a config that includes users before start — recovers hosts
        # whose /etc/mita/server.conf.pb lost the users list.
        try:
            meta = self._read_metadata()
            port = int(meta.get('port') or self.DEFAULT_PORT)
            clients = self._ensure_bootstrap_clients(self._read_clients())
            self._write_clients(clients)
            config = self._build_server_config(port, clients)
            self._write_file(self.config_path, json.dumps(config, indent=2))
            apply_out, apply_err, apply_code = self._mita_cli(
                ['apply', 'config', _q(self.config_path)],
                timeout=60,
            )
            if apply_code != 0 and self._is_rpc_error(apply_out, apply_err):
                self._heal_mita_store()
            elif apply_code != 0:
                logger.warning(
                    'mita apply before start failed: %s',
                    (apply_err or apply_out or '').strip(),
                )
        except Exception as e:
            logger.warning('pre-start config sync failed: %s', e)

        self._mita_cli(['stop'], timeout=30)
        time.sleep(1)
        last_err = ''
        for attempt in range(1, 4):
            out, err, code = self._mita_cli(['start'], timeout=60)
            if code == 0:
                time.sleep(1)
                if self._proxy_running():
                    return
                last_err = (out or err or 'mita start returned ok but status is not RUNNING').strip()
            else:
                last_err = (err or out or 'mita start failed').strip()
            if 'no user found' in last_err.lower() or self._daemon_needs_heal():
                self._heal_mita_store()
                continue
            if self._is_rpc_error(last_err) or attempt < 3:
                self.ssh.run_sudo_command(
                    f"systemctl restart {self.SERVICE_NAME} 2>/dev/null || true",
                    timeout=60,
                )
                if not self._wait_for_rpc(timeout=30):
                    self._heal_mita_store()
                time.sleep(1)
                continue
            break
        journal, _, _ = self.ssh.run_sudo_command(
            f"journalctl -u {self.SERVICE_NAME} -n 30 --no-pager 2>&1",
            timeout=30,
        )
        raise RuntimeError(
            f'{last_err}. journal: {(journal or "").strip()[-400:]}'
        )

    def _sync_server(self, reload_only=True):
        meta = self._read_metadata()
        port = int(meta.get('port') or self.DEFAULT_PORT)
        clients = self._ensure_bootstrap_clients(self._read_clients())
        self._write_clients(clients)
        config = self._build_server_config(port, clients)
        self._apply_config(config, reload_only=reload_only)

    def _open_firewall_port(self, port):
        script = f"""
PORT={int(port)}
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi active; then
  ufw allow "$PORT"/tcp || true
fi
if command -v firewall-cmd >/dev/null 2>&1; then
  firewall-cmd --permanent --add-port="$PORT"/tcp 2>/dev/null || true
  firewall-cmd --reload 2>/dev/null || true
fi
"""
        self.ssh.run_sudo_script(script, timeout=60)

    def _package_url(self):
        arch_out, _, _ = self.ssh.run_command('uname -m')
        arch = (arch_out or '').strip().lower()
        _, _, deb_code = self.ssh.run_command('command -v dpkg 2>/dev/null')
        _, _, rpm_code = self.ssh.run_command('command -v rpm 2>/dev/null')
        use_deb = deb_code == 0 or rpm_code != 0
        if use_deb:
            if arch in ('aarch64', 'arm64'):
                return f'{GITHUB_RELEASE}/mita_{MIERU_RELEASE}_arm64.deb', 'deb'
            return f'{GITHUB_RELEASE}/mita_{MIERU_RELEASE}_amd64.deb', 'deb'
        if arch in ('aarch64', 'arm64'):
            return f'{GITHUB_RELEASE}/mita-{MIERU_RELEASE}-1.aarch64.rpm', 'rpm'
        return f'{GITHUB_RELEASE}/mita-{MIERU_RELEASE}-1.x86_64.rpm', 'rpm'

    def _install_package(self, log):
        url, pkg_type = self._package_url()
        tmp = f'/tmp/mita_{MIERU_RELEASE}'
        if pkg_type == 'deb':
            tmp += '.deb'
            install_cmd = f"dpkg -i {_q(tmp)} || apt-get install -f -y"
        else:
            tmp += '.rpm'
            install_cmd = f"rpm -Uvh --force {_q(tmp)}"
        out, err, code = self.ssh.run_sudo_command(
            f"curl -fL {_q(url)} -o {_q(tmp)} 2>&1",
            timeout=300,
        )
        if code != 0:
            raise RuntimeError(f'Failed to download mita package: {err or out}')
        log.append(f'Downloaded mita v{MIERU_RELEASE}')
        out, err, code = self.ssh.run_sudo_command(install_cmd, timeout=180)
        if code != 0:
            raise RuntimeError(f'Failed to install mita package: {err or out}')
        log.append('Installed mita package')
        self._ensure_daemon(log)

    def _build_share_uri(self, host, port, username, password, name=''):
        user = quote(username or '', safe='')
        pw = quote(password or '', safe='')
        params = f"port={int(port)}&protocol=TCP&profile=default"
        link = f"mierus://{user}:{pw}@{host}?{params}"
        if name:
            link += f"#{quote(name, safe='')}"
        return link

    def _build_client_json(self, host, port, username, password):
        return json.dumps({
            'profiles': [{
                'profileName': 'default',
                'user': {'name': username, 'password': password},
                'servers': [{
                    'ipAddress': host,
                    'domainName': '',
                    'portBindings': [{'port': int(port), 'protocol': 'TCP'}],
                }],
                'mtu': 1400,
                'multiplexing': {'level': 'MULTIPLEXING_LOW'},
                'handshakeMode': 'HANDSHAKE_STANDARD',
            }],
            'activeProfile': 'default',
            'rpcPort': 8964,
            'socks5Port': 1080,
            'loggingLevel': 'INFO',
            'socks5ListenLAN': False,
        }, indent=2)

    # ===================== INSTALL / REMOVE =====================

    def install_protocol(self, protocol_type=None, port=None):
        protocol_type = protocol_type or self.protocol
        port = int(port or self.DEFAULT_PORT)
        if port < 1025 or port > 65535:
            return {'status': 'error', 'message': 'Port must be between 1025 and 65535'}

        log = []
        try:
            if not self._mita_installed():
                self._install_package(log)
            else:
                log.append(f'mita already installed, configuring panel (v{MIERU_RELEASE})')
                self._ensure_daemon(log)

            self.ssh.run_sudo_command(f"mkdir -p {_q(self.base_dir)}")
            meta = {'port': port, 'release': MIERU_RELEASE}
            self._write_metadata(meta)
            bootstrap = self._make_bootstrap_client()
            self._write_clients([bootstrap])
            log.append(f'Prepared {self.base_dir}')

            config = self._build_server_config(port, [bootstrap])
            self._apply_config(config, reload_only=False)
            self._open_firewall_port(port)
            log.append(f'Started mita proxy on TCP {port}')
            return {
                'status': 'success',
                'message': f'Mieru v{MIERU_RELEASE} installed',
                'log': log,
                'port': str(port),
                'release': MIERU_RELEASE,
            }
        except Exception as e:
            return {'status': 'error', 'message': str(e), 'log': log}

    def remove_container(self, protocol_type=None):
        self.ssh.run_sudo_command('mita stop 2>/dev/null || true', timeout=30)
        self.ssh.run_sudo_command(f"rm -rf {_q(self.base_dir)}")
        return True

    def start_service(self):
        self._ensure_daemon()
        # Re-apply panel clients (with bootstrap) then start — fixes empty-users store.
        self._sync_server(reload_only=False)

    def stop_service(self):
        self.ssh.run_sudo_command('mita stop 2>/dev/null || true', timeout=30)

    def get_server_config(self, protocol_type=None):
        out, _, code = self.ssh.run_sudo_command('mita describe config 2>/dev/null')
        if code == 0 and (out or '').strip():
            return out
        return self._read_file(self.config_path)

    def save_server_config(self, protocol_type=None, config_text=''):
        raw = (config_text or '').strip()
        if not raw:
            raise RuntimeError('Config is empty')
        try:
            parsed = json.loads(raw)
        except Exception as e:
            raise RuntimeError(f'Invalid JSON config: {e}') from e
        if not isinstance(parsed, dict):
            raise RuntimeError('Config must be a JSON object')
        users = parsed.get('users')
        if not isinstance(users, list) or not any(
            isinstance(u, dict) and (u.get('name') or '').strip()
            and ((u.get('password') or '').strip() or (u.get('hashedPassword') or '').strip())
            for u in users
        ):
            bootstrap = self._make_bootstrap_client()
            parsed['users'] = [{
                'name': bootstrap['username'],
                'password': bootstrap['password'],
            }]
            clients = self._ensure_bootstrap_clients(self._read_clients())
            self._write_clients(clients)
        self._apply_config(parsed, reload_only=False)
        return True

    # ===================== CLIENTS =====================

    def get_clients(self, protocol_type=None):
        clients = self._read_clients()
        result = []
        for c in clients:
            if c.get('bootstrap'):
                continue
            cname = c.get('name') or c.get('id')
            result.append({
                'clientId': c.get('id'),
                'client_id': c.get('id'),
                'id': c.get('id'),
                'name': cname,
                'email': cname,
                'enabled': c.get('enabled', True),
                'userData': {'clientName': cname, 'enabled': c.get('enabled', True)},
            })
        return result

    def add_client(self, protocol_type, name, host, port=None):
        meta = self._read_metadata()
        port = int(port or meta.get('port') or self.DEFAULT_PORT)
        client_id = secrets.token_hex(8)
        username = _sanitize_username(name)
        password = _rand_token(20)
        clients = self._read_clients()
        clients.append({
            'id': client_id,
            'name': name or username,
            'username': username,
            'password': password,
            'enabled': True,
        })
        self._write_clients(clients)
        self._sync_server(reload_only=True)
        config = self._build_share_uri(host, port, username, password, name or username)
        json_config = self._build_client_json(host, port, username, password)
        return {
            'clientId': client_id,
            'client_id': client_id,
            'id': client_id,
            'name': name or username,
            'config': config,
            'json_config': json_config,
        }

    def get_client_config(self, protocol_type, client_id, host, port=None):
        meta = self._read_metadata()
        port = int(port or meta.get('port') or self.DEFAULT_PORT)
        clients = self._read_clients()
        client = next((c for c in clients if c.get('id') == client_id), None)
        if not client or client.get('bootstrap'):
            return ''
        if not client.get('enabled', True):
            return ''
        username = client.get('username') or client.get('name') or client_id
        password = client.get('password') or ''
        name = client.get('name') or username
        return self._build_share_uri(host, port, username, password, name)

    def remove_client(self, protocol_type, client_id):
        clients = [c for c in self._read_clients() if c.get('id') != client_id]
        clients = self._ensure_bootstrap_clients(clients)
        self._write_clients(clients)
        self._sync_server(reload_only=True)
        return True

    def toggle_client(self, protocol_type, client_id, enabled):
        clients = self._read_clients()
        for c in clients:
            if c.get('id') == client_id:
                c['enabled'] = bool(enabled)
        clients = self._ensure_bootstrap_clients(clients)
        self._write_clients(clients)
        self._sync_server(reload_only=True)
        return True
