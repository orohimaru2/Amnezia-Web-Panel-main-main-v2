"""
NaiveProxy manager — Caddy + klzgrad/forwardproxy (naive fork).

Server side is the naïve Caddy forward_proxy from:
  https://github.com/klzgrad/naiveproxy
  https://github.com/klzgrad/forwardproxy

Uses the official prebuilt Caddy binary on amd64, or builds via xcaddy on other
arches. Clients authenticate with HTTP basic auth; share links are
naive+https://user:pass@domain URIs (NekoRay / sing-box compatible).
Requires free TCP 80 (ACME) and 443 (HTTPS / HTTP2 proxy).
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


def _q(value):
    return shlex.quote(str(value))


def _rand_token(length=16):
    alphabet = string.ascii_lowercase + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


class NaiveProxyManager:
    PROTOCOL = 'naiveproxy'
    CONTAINER_NAME = 'amnezia-naiveproxy'
    IMAGE_NAME = 'amnezia-naiveproxy:local'
    BASE_DIR = '/opt/amnezia/naiveproxy'
    DEFAULT_PORT = 443
    # Official Caddy+forwardproxy naive build (linux amd64)
    CADDY_RELEASE = 'v2.11.2-naive'
    CADDY_URL = (
        'https://github.com/klzgrad/forwardproxy/releases/download/'
        f'{CADDY_RELEASE}/caddy-forwardproxy-naive.tar.xz'
    )

    def __init__(self, ssh, protocol='naiveproxy'):
        self.ssh = ssh
        self.protocol = protocol or self.PROTOCOL
        self.container_name = self.CONTAINER_NAME
        self.base_dir = self.BASE_DIR
        self.caddyfile_path = f'{self.base_dir}/Caddyfile'
        self.clients_path = f'{self.base_dir}/clients.json'
        self.meta_path = f'{self.base_dir}/metadata.json'
        self.html_dir = f'{self.base_dir}/html'
        self.bin_dir = f'{self.base_dir}/bin'
        self.data_dir = f'{self.base_dir}/caddy-data'
        self.config_dir = f'{self.base_dir}/caddy-config'

    # ===================== STATUS =====================

    def check_docker_installed(self):
        out, _, code = self.ssh.run_command("docker --version 2>/dev/null")
        if code != 0:
            return False
        out2, _, _ = self.ssh.run_command(
            "systemctl is-active docker 2>/dev/null || service docker status 2>/dev/null"
        )
        return 'active' in out2 or 'running' in out2.lower()

    def check_protocol_installed(self, protocol_type=None):
        out, _, _ = self.ssh.run_sudo_command(
            f"docker ps -a --filter name=^{self.CONTAINER_NAME}$ --format '{{{{.Names}}}}'"
        )
        return self.CONTAINER_NAME in out.strip().split('\n')

    def check_container_running(self, protocol_type=None):
        out, _, _ = self.ssh.run_sudo_command(
            f"docker ps --filter name=^{self.CONTAINER_NAME}$ --format '{{{{.Status}}}}'"
        )
        return 'Up' in out

    def get_logs(self, protocol_type=None, tail=200):
        tail = max(20, min(int(tail or 200), 2000))
        out, err, code = self.ssh.run_sudo_command(
            f"docker logs --tail {tail} --timestamps {self.CONTAINER_NAME} 2>&1",
            timeout=30,
        )
        text = (out or err or '').strip()
        if code != 0 and not text:
            text = f'(no logs: exit {code})'
        return text

    def get_container_diagnostics(self, protocol_type=None):
        fmt = (
            '{{.State.Status}}|{{.State.Running}}|{{.State.ExitCode}}|'
            '{{.State.OOMKilled}}|{{.State.Error}}|{{.State.FinishedAt}}|'
            '{{.State.StartedAt}}'
        )
        out, _, code = self.ssh.run_sudo_command(
            f"docker inspect -f '{fmt}' {self.CONTAINER_NAME} 2>/dev/null"
        )
        diag = {
            'status': 'unknown',
            'running': False,
            'exit_code': None,
            'error_summary': '',
            'recent_logs': '',
        }
        if code == 0 and out.strip():
            parts = out.strip().split('|')
            while len(parts) < 7:
                parts.append('')
            diag['status'] = parts[0]
            diag['running'] = parts[1].lower() == 'true'
            try:
                diag['exit_code'] = int(parts[2])
            except ValueError:
                diag['exit_code'] = parts[2]
            if parts[3].lower() == 'true':
                diag['error_summary'] = 'OOM killed'
            elif parts[4]:
                diag['error_summary'] = parts[4]
            elif not diag['running'] and diag['exit_code'] not in (0, '0', None, ''):
                diag['error_summary'] = f'Exited with code {diag["exit_code"]}'
        diag['recent_logs'] = self.get_logs(protocol_type, tail=80)
        if not diag['error_summary'] and not diag['running']:
            logs = diag['recent_logs'].lower()
            if 'address already in use' in logs or 'bind:' in logs:
                diag['error_summary'] = (
                    'TCP 80/443 already in use — free them or stop conflicting services'
                )
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
            'domain': meta.get('domain') or '',
            'email': meta.get('email') or '',
            'clients_count': len(clients),
            'protocol': protocol_type,
            'base_protocol': self.PROTOCOL,
            'instance': 1,
            'container_name': self.CONTAINER_NAME,
        }

    # ===================== IO HELPERS =====================

    def _validate_domain(self, domain):
        domain = (domain or '').strip().lower()
        if not domain or len(domain) > 253:
            raise ValueError('Domain is required')
        if not re.match(r'^(?!-)[a-z0-9.-]+(?<!-)$', domain) or '.' not in domain:
            raise ValueError('Invalid domain name')
        return domain

    def _validate_email(self, email):
        email = (email or '').strip()
        if not email or '@' not in email:
            raise ValueError('Valid Let\'s Encrypt email is required')
        return email

    def _read_file(self, path):
        out, _, code = self.ssh.run_sudo_command(f"cat {_q(path)} 2>/dev/null")
        return out if code == 0 else ''

    def _write_file(self, path, content):
        # Write via base64 to avoid shell escaping issues
        import base64
        b64 = base64.b64encode((content or '').encode('utf-8')).decode('ascii')
        script = (
            f"mkdir -p $(dirname {_q(path)}) && "
            f"echo {_q(b64)} | base64 -d > {_q(path)}"
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
        self._write_file(self.meta_path, json.dumps(meta, indent=2, ensure_ascii=False))

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
        self._write_file(self.clients_path, json.dumps(clients, indent=2, ensure_ascii=False))

    def _caddy_auth_lines(self, clients):
        lines = []
        for c in clients:
            if c.get('enabled', True) is False:
                continue
            user = (c.get('username') or '').strip()
            password = (c.get('password') or '').strip()
            if not user or not password:
                continue
            # Credentials are alphanumeric from our generator — safe in Caddyfile
            lines.append(f'    basic_auth {user} {password}')
        return lines

    def _build_caddyfile(self, domain, email, clients, probe_path):
        auth_lines = self._caddy_auth_lines(clients)
        if not auth_lines:
            # Keep a non-shared bootstrap user so the proxy is never open
            auth_lines = [f'    basic_auth bootstrap {_rand_token(24)}']
        auth_block = '\n'.join(auth_lines)
        # probe_resistance looks like a fake domain to browsers
        probe = (probe_path or _rand_token(12)).strip('/')
        if '.' not in probe:
            probe = f'{probe}.com'
        return f"""{{
  order forward_proxy before file_server
  admin off
  log {{
    exclude http.log.error
  }}
}}
:443, {domain} {{
  tls {email}
  encode
  forward_proxy {{
{auth_block}
    hide_ip
    hide_via
    probe_resistance {probe}
  }}
  file_server {{
    root /var/www/html
  }}
}}
"""

    def _write_config_from_clients(self):
        meta = self._read_metadata()
        domain = meta.get('domain') or ''
        email = meta.get('email') or ''
        if not domain or not email:
            raise RuntimeError('Domain and email are required in metadata')
        clients = self._read_clients()
        probe = meta.get('probe_resistance') or _rand_token(12)
        if not meta.get('probe_resistance'):
            meta['probe_resistance'] = probe
            self._write_metadata(meta)
        text = self._build_caddyfile(domain, email, clients, probe)
        self._write_file(self.caddyfile_path, text)

    def _ensure_placeholder_site(self):
        index = f'{self.html_dir}/index.html'
        existing = self._read_file(index)
        if existing.strip():
            return
        html = (
            '<!DOCTYPE html><html><head><meta charset="utf-8">'
            '<title>Welcome</title></head><body><h1>It works</h1></body></html>\n'
        )
        self._write_file(index, html)

    def _host_arch(self):
        out, _, _ = self.ssh.run_command("uname -m")
        return (out or '').strip().lower()

    def _prepare_caddy_binary(self, log):
        """Download official amd64 build or compile with xcaddy for other arches."""
        self.ssh.run_sudo_command(f"mkdir -p {_q(self.bin_dir)}")
        arch = self._host_arch()
        caddy_path = f'{self.bin_dir}/caddy'

        if arch in ('x86_64', 'amd64'):
            script = f"""
set -e
cd {_q(self.bin_dir)}
curl -fsSL -o caddy-forwardproxy-naive.tar.xz {_q(self.CADDY_URL)}
tar -xf caddy-forwardproxy-naive.tar.xz
if [ -f caddy-forwardproxy-naive/caddy ]; then
  cp -f caddy-forwardproxy-naive/caddy ./caddy
elif [ -f caddy ]; then
  true
else
  echo "caddy binary not found in archive" >&2
  exit 1
fi
chmod +x ./caddy
./caddy version
"""
            out, err, code = self.ssh.run_sudo_command(f"bash -lc {_q(script)}", timeout=300)
            if code != 0:
                raise RuntimeError(f'Failed to download NaiveProxy Caddy: {err or out}')
            log.append(f'Downloaded official Caddy+forwardproxy ({self.CADDY_RELEASE})')
            return caddy_path

        # arm64 / other: build with xcaddy inside golang image
        build_script = f"""
set -e
docker pull golang:1.22-bookworm
docker run --rm -v {_q(self.bin_dir)}:/out -w /tmp golang:1.22-bookworm bash -lc '
set -e
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
/go/bin/xcaddy build --with github.com/caddyserver/forwardproxy=github.com/klzgrad/forwardproxy@naive
cp -f caddy /out/caddy
chmod +x /out/caddy
'
{_q(caddy_path)} version
"""
        out, err, code = self.ssh.run_sudo_command(f"bash -lc {_q(build_script)}", timeout=900)
        if code != 0:
            raise RuntimeError(f'Failed to build NaiveProxy Caddy for {arch}: {err or out}')
        log.append(f'Built Caddy+forwardproxy via xcaddy for {arch}')
        return caddy_path

    def _build_docker_image(self, log):
        dockerfile = f"""FROM debian:bookworm-slim
RUN apt-get update \\
 && apt-get install -y --no-install-recommends ca-certificates \\
 && rm -rf /var/lib/apt/lists/*
COPY caddy /usr/bin/caddy
RUN chmod +x /usr/bin/caddy
WORKDIR /etc/caddy
EXPOSE 80 443
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
"""
        self._write_file(f'{self.bin_dir}/Dockerfile', dockerfile)
        out, err, code = self.ssh.run_sudo_command(
            f"docker build -t {self.IMAGE_NAME} {_q(self.bin_dir)}",
            timeout=300,
        )
        if code != 0:
            raise RuntimeError(f'Failed to build Docker image: {err or out}')
        log.append(f'Built image {self.IMAGE_NAME}')

    def _start_container(self):
        self.ssh.run_sudo_command(
            f"docker rm -fv {self.CONTAINER_NAME} 2>/dev/null || true"
        )
        self.ssh.run_sudo_command(f"mkdir -p {_q(self.data_dir)} {_q(self.config_dir)} {_q(self.html_dir)}")
        run_cmd = (
            f"docker run -d --name {self.CONTAINER_NAME} --restart unless-stopped "
            f"--network host "
            f"-v {_q(self.base_dir)}:/etc/caddy "
            f"-v {_q(self.html_dir)}:/var/www/html "
            f"-v {_q(self.data_dir)}:/data "
            f"-v {_q(self.config_dir)}:/config "
            f"-e XDG_DATA_HOME=/data "
            f"-e XDG_CONFIG_HOME=/config "
            f"{self.IMAGE_NAME}"
        )
        _, err, code = self.ssh.run_sudo_command(run_cmd, timeout=60)
        if code != 0:
            raise RuntimeError(f'Failed to start NaiveProxy: {err}')
        time.sleep(2.0)
        if not self.check_container_running():
            diag = self.get_container_diagnostics()
            raise RuntimeError(
                diag.get('error_summary')
                or 'NaiveProxy container exited — free TCP 80/443 and check logs'
            )
        return True

    def _reload_container(self):
        try:
            self._write_config_from_clients()
            # Prefer graceful reload; fall back to recreate
            out, _, code = self.ssh.run_sudo_command(
                f"docker exec {self.CONTAINER_NAME} caddy reload "
                f"--config /etc/caddy/Caddyfile --adapter caddyfile 2>&1",
                timeout=30,
            )
            if code != 0:
                logger.warning('Caddy reload failed (%s), recreating container', out)
                self._start_container()
        except Exception as e:
            logger.warning('NaiveProxy reload failed: %s', e)
            self._start_container()

    def _build_share_uri(self, domain, username, password, name, port=443):
        """v2rayN / NekoRay / sing-box compatible share link.

        Always include an explicit port — without `:443` v2rayN often treats
        the port as empty/80 and shows «Свойство Порт недопустимо» / SSL errors.
        """
        # Keep credentials unescaped when alphanumeric (our generator); quote otherwise.
        user = quote(username or '', safe='')
        pw = quote(password or '', safe='')
        host = (domain or '').strip().lower()
        port = int(port or 443)
        if port < 1 or port > 65535:
            port = 443
        # Remark: ASCII-safe, no spaces that break some importers
        remark = re.sub(r'[^\w.\-]+', '-', (name or 'naiveproxy').strip())[:48] or 'naiveproxy'
        return f'naive+https://{user}:{pw}@{host}:{port}#{remark}'

    # ===================== INSTALL / REMOVE =====================

    def install_protocol(self, protocol_type=None, port=None, domain=None, email=None):
        protocol_type = protocol_type or self.protocol
        if not self.check_docker_installed():
            return {'status': 'error', 'message': 'Docker not installed'}

        try:
            domain = self._validate_domain(domain)
            email = self._validate_email(email)
        except ValueError as e:
            return {'status': 'error', 'message': str(e)}

        port = int(port or self.DEFAULT_PORT)
        if port not in (443,):
            # Caddy ACME + naive typically bind :443; keep simple for beta
            port = 443

        log = []
        self.ssh.run_sudo_command(f"mkdir -p {_q(self.base_dir)} {_q(self.html_dir)} {_q(self.bin_dir)}")

        if self.check_protocol_installed(protocol_type):
            self.ssh.run_sudo_command(f"docker rm -fv {self.CONTAINER_NAME} 2>/dev/null || true")
            log.append('Removed previous container')

        try:
            self._prepare_caddy_binary(log)
            self._build_docker_image(log)
        except Exception as e:
            return {'status': 'error', 'message': str(e), 'log': log}

        self._write_clients([])
        meta = {
            'domain': domain,
            'email': email,
            'port': port,
            'probe_resistance': _rand_token(12),
            'caddy_release': self.CADDY_RELEASE,
        }
        self._write_metadata(meta)
        self._ensure_placeholder_site()
        try:
            self._write_config_from_clients()
        except Exception as e:
            return {'status': 'error', 'message': str(e), 'log': log}
        log.append('Wrote Caddyfile (forward_proxy + ACME TLS)')

        try:
            self._start_container()
        except Exception as e:
            return {'status': 'error', 'message': str(e), 'log': log}

        log.append(
            f'Started {self.CONTAINER_NAME} on TCP 443 (host network). '
            'Ports 80 and 443 must stay free for ACME and HTTPS.'
        )
        return {
            'status': 'success',
            'message': 'NaiveProxy installed',
            'log': log,
            'port': str(port),
            'domain': domain,
            'email': email,
        }

    def remove_container(self, protocol_type=None):
        self.ssh.run_sudo_command(f"docker rm -fv {self.CONTAINER_NAME} 2>/dev/null || true")
        self.ssh.run_sudo_command(f"rm -rf {_q(self.base_dir)}")
        return True

    def get_server_config(self, protocol_type=None):
        return self._read_file(self.caddyfile_path)

    def save_server_config(self, protocol_type=None, config_text=''):
        self._write_file(self.caddyfile_path, config_text or '')
        self._reload_container()
        return True

    def get_settings(self):
        meta = self._read_metadata()
        return {
            'port': int(meta.get('port') or self.DEFAULT_PORT),
            'domain': meta.get('domain') or '',
            'email': meta.get('email') or '',
            'protocol': self.protocol,
        }

    def update_settings(self, domain=None, email=None):
        meta = self._read_metadata()
        try:
            if domain is not None and str(domain).strip():
                meta['domain'] = self._validate_domain(domain)
            if email is not None and str(email).strip():
                meta['email'] = self._validate_email(email)
        except ValueError as e:
            return {'status': 'error', 'message': str(e)}
        if not meta.get('domain') or not meta.get('email'):
            return {'status': 'error', 'message': 'Domain and email are required'}
        meta['port'] = int(meta.get('port') or self.DEFAULT_PORT)
        self._write_metadata(meta)
        try:
            self._write_config_from_clients()
            self._start_container()
        except Exception as e:
            return {'status': 'error', 'message': str(e), **self.get_settings()}
        return {'status': 'success', 'message': 'NaiveProxy settings updated', **self.get_settings()}

    # ===================== CLIENTS =====================

    def get_clients(self, protocol_type=None):
        clients = self._read_clients()
        result = []
        for c in clients:
            cname = c.get('name') or c.get('username') or c.get('id')
            result.append({
                'clientId': c.get('id'),
                'client_id': c.get('id'),
                'id': c.get('id'),
                'name': cname,
                'email': cname,
                'enabled': c.get('enabled', True),
                'userData': {
                    'clientName': cname,
                    'enabled': c.get('enabled', True),
                    'username': c.get('username'),
                },
            })
        return result

    def add_client(self, protocol_type, name, host, port=None):
        meta = self._read_metadata()
        domain = meta.get('domain') or host
        port = int(port or meta.get('port') or self.DEFAULT_PORT)
        client_id = secrets.token_hex(8)
        username = f'u{client_id[:8]}'
        password = _rand_token(20)
        clients = self._read_clients()
        clients.append({
            'id': client_id,
            'name': name or f'client-{client_id[:6]}',
            'username': username,
            'password': password,
            'enabled': True,
        })
        self._write_clients(clients)
        self._reload_container()
        config = self._build_share_uri(domain, username, password, name or client_id, port)
        return {'client_id': client_id, 'config': config}

    def get_client_config(self, protocol_type, client_id, host, port=None):
        meta = self._read_metadata()
        domain = meta.get('domain') or host
        port = int(port or meta.get('port') or self.DEFAULT_PORT)
        clients = self._read_clients()
        client = next((c for c in clients if c.get('id') == client_id), None)
        if not client:
            raise RuntimeError('Client not found')
        if client.get('enabled', True) is False:
            raise RuntimeError('Client is disabled')
        return self._build_share_uri(
            domain,
            client.get('username'),
            client.get('password'),
            client.get('name') or client_id,
            port,
        )

    def remove_client(self, protocol_type, client_id):
        clients = [c for c in self._read_clients() if c.get('id') != client_id]
        self._write_clients(clients)
        self._reload_container()
        return True

    def toggle_client(self, protocol_type, client_id, enable=True):
        clients = self._read_clients()
        found = False
        for c in clients:
            if c.get('id') == client_id:
                c['enabled'] = bool(enable)
                found = True
                break
        if not found:
            raise RuntimeError('Client not found')
        self._write_clients(clients)
        self._reload_container()
        return True
