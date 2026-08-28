"""
Hysteria 2 protocol manager — official tobyxdd/hysteria image (apernet/hysteria).

Installs Hysteria with Let's Encrypt TLS for an admin-provided domain
(certbot standalone on port 80), host networking, BBR, and salamander obfs.
Clients use password auth (Happ/INCY-compatible); share links are hy2:// URIs.
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


class HysteriaManager:
    PROTOCOL = 'hysteria'
    CONTAINER_NAME = 'amnezia-hysteria'
    IMAGE_NAME = 'tobyxdd/hysteria:v2'
    CERTBOT_IMAGE = 'certbot/certbot:latest'
    BASE_DIR = '/opt/amnezia/hysteria'
    DEFAULT_PORT = 8998

    def __init__(self, ssh, protocol='hysteria'):
        self.ssh = ssh
        self.protocol = protocol or self.PROTOCOL
        self.instance = self._instance_index(self.protocol)
        self.container_name = self._container_name(self.protocol)
        self.base_dir = self._base_dir(self.protocol)
        self.config_path = f'{self.base_dir}/server.yaml'
        self.clients_path = f'{self.base_dir}/clients.json'
        self.meta_path = f'{self.base_dir}/metadata.json'
        self.cert_path = f'{self.base_dir}/cert.crt'
        self.key_path = f'{self.base_dir}/private.key'
        self.letsencrypt_dir = f'{self.base_dir}/letsencrypt'

    def _instance_index(self, protocol=None):
        parts = str(protocol or self.protocol or '').split('__', 1)
        if len(parts) == 2:
            try:
                return max(1, int(parts[1]))
            except ValueError:
                return 1
        return 1

    def _container_name(self, protocol=None):
        idx = self._instance_index(protocol or self.protocol)
        return self.CONTAINER_NAME if idx <= 1 else f'{self.CONTAINER_NAME}-{idx}'

    def _base_dir(self, protocol=None):
        idx = self._instance_index(protocol or self.protocol)
        return self.BASE_DIR if idx <= 1 else f'{self.BASE_DIR}-{idx}'

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
        name = self._container_name(protocol_type or self.protocol)
        out, _, _ = self.ssh.run_sudo_command(
            f"docker ps -a --filter name=^{name}$ --format '{{{{.Names}}}}'"
        )
        return name in out.strip().split('\n')

    def check_container_running(self, protocol_type=None):
        name = self._container_name(protocol_type or self.protocol)
        out, _, _ = self.ssh.run_sudo_command(
            f"docker ps --filter name=^{name}$ --format '{{{{.Status}}}}'"
        )
        return 'Up' in out

    def get_logs(self, protocol_type=None, tail=200):
        """Return recent docker logs for the Hysteria container."""
        name = self._container_name(protocol_type or self.protocol)
        tail = max(20, min(int(tail or 200), 2000))
        out, err, code = self.ssh.run_sudo_command(
            f"docker logs --tail {tail} --timestamps {name} 2>&1",
            timeout=30,
        )
        text = (out or err or '').strip()
        if code != 0 and not text:
            text = f'(no logs: exit {code})'
        return text

    def get_container_diagnostics(self, protocol_type=None):
        """Inspect why the container is stopped / unhealthy."""
        name = self._container_name(protocol_type or self.protocol)
        fmt = (
            '{{.State.Status}}|{{.State.Running}}|{{.State.ExitCode}}|'
            '{{.State.OOMKilled}}|{{.State.Error}}|{{.State.FinishedAt}}|'
            '{{.State.StartedAt}}'
        )
        out, _, code = self.ssh.run_sudo_command(
            f"docker inspect -f '{fmt}' {name} 2>/dev/null"
        )
        diag = {
            'status': 'unknown',
            'running': False,
            'exit_code': None,
            'oom_killed': False,
            'error': '',
            'finished_at': '',
            'started_at': '',
            'recent_logs': '',
            'error_summary': '',
        }
        if code != 0 or not (out or '').strip():
            diag['status'] = 'missing'
            diag['error_summary'] = 'Container not found'
            return diag

        parts = (out or '').strip().split('|')
        while len(parts) < 7:
            parts.append('')
        status, running, exit_code, oom, err, finished, started = parts[:7]
        diag['status'] = status or 'unknown'
        diag['running'] = str(running).lower() == 'true'
        try:
            diag['exit_code'] = int(exit_code)
        except Exception:
            diag['exit_code'] = None
        diag['oom_killed'] = str(oom).lower() == 'true'
        diag['error'] = (err or '').strip()
        diag['finished_at'] = (finished or '').strip()
        diag['started_at'] = (started or '').strip()
        diag['recent_logs'] = self.get_logs(protocol_type, tail=40)

        # Build human-readable summary for the UI badge
        if diag['running']:
            diag['error_summary'] = ''
        elif diag['oom_killed']:
            diag['error_summary'] = 'OOM killed (out of memory)'
        elif diag['error']:
            diag['error_summary'] = diag['error']
        elif diag['exit_code'] not in (None, 0):
            # Prefer bind/port conflicts over generic FATAL lines
            bind_line = ''
            last = ''
            for raw in reversed((diag['recent_logs'] or '').splitlines()):
                line = self._strip_ansi(raw).strip()
                if not line:
                    continue
                # strip docker --timestamps prefix
                m_ts = re.match(r'^\d{4}-\d{2}-\d{2}T\S+\s+(.*)$', line)
                if m_ts:
                    line = m_ts.group(1).strip()
                low = line.lower()
                if 'address already in use' in low and not bind_line:
                    bind_line = line
                if ('FATAL' in line or 'failed to load' in low) and not last:
                    last = line
                if not last:
                    last = line
            pick = bind_line or last
            if pick and 'address already in use' in pick.lower():
                m = re.search(r'listen udp :(\d+)', pick, re.I) or re.search(r':(\d+):\s*bind', pick)
                p = m.group(1) if m else '?'
                if p == '?':
                    m2 = re.search(r'udp\s*:(\d+)', pick, re.I)
                    p = m2.group(1) if m2 else '?'
                diag['error_summary'] = (
                    f'UDP port {p} already in use — change port below (try 8998 or 8443)'
                )
                diag['port_busy'] = True
            elif pick:
                short = re.sub(r'\s+', ' ', pick)[:160]
                diag['error_summary'] = f"exit {diag['exit_code']}: {short}"
            else:
                diag['error_summary'] = f"exited with code {diag['exit_code']}"
        elif diag['status'] and diag['status'] != 'running':
            diag['error_summary'] = f"status: {diag['status']}"
        return diag

    def get_server_status(self, protocol_type=None):
        protocol_type = protocol_type or self.protocol
        exists = self.check_protocol_installed(protocol_type)
        running = self.check_container_running(protocol_type)
        meta = self._read_metadata() if exists else {}
        clients = self._read_clients() if exists else []
        diag = {}

        # Auto-migrate older installs (bridge NAT / userpass / missing BBR+obfs)
        if exists:
            try:
                name = self._container_name(protocol_type)
                mode, _, _ = self.ssh.run_sudo_command(
                    f"docker inspect -f '{{{{.HostConfig.NetworkMode}}}}' {name} 2>/dev/null"
                )
                mode = (mode or '').strip()
                cfg = self._read_file(self.config_path)
                needs_cfg = (
                    'type: userpass' in cfg
                    or 'type: salamander' not in cfg
                    or 'type: password' not in cfg
                )
                if (mode and mode != 'host') or needs_cfg:
                    port = int(meta.get('port') or self.DEFAULT_PORT)
                    self._write_config_from_clients(port)
                    self._start_container(port)
                    running = self.check_container_running(protocol_type)
                    meta = self._read_metadata()
            except Exception as e:
                logger.warning('Hysteria migrate failed: %s', e)
                diag = {'error_summary': f'migrate failed: {e}'}

        if exists:
            try:
                diag = self.get_container_diagnostics(protocol_type)
                running = bool(diag.get('running'))
            except Exception as e:
                logger.warning('Hysteria diagnostics failed: %s', e)
                diag = {'error_summary': str(e)}

        return {
            'container_exists': exists,
            'container_running': running,
            'port': int(meta.get('port') or self.DEFAULT_PORT),
            'domain': meta.get('domain'),
            'email': meta.get('email'),
            'clients_count': len(clients),
            'protocol': protocol_type,
            'base_protocol': self.PROTOCOL,
            'instance': self._instance_index(protocol_type),
            'container_name': self._container_name(protocol_type),
            'error': diag.get('error_summary') or '',
            'exit_code': diag.get('exit_code'),
            'container_status': diag.get('status') or '',
            'recent_logs': diag.get('recent_logs') or '',
            'port_busy': bool(diag.get('port_busy')),
        }

    # ===================== HELPERS =====================

    def _validate_domain(self, domain):
        domain = (domain or '').strip().lower()
        if not domain or len(domain) > 253:
            raise ValueError('Domain is required for Hysteria SSL')
        if not re.match(r'^(?!-)[a-z0-9.-]+(?<!-)$', domain) or '.' not in domain:
            raise ValueError('Invalid domain name')
        return domain

    def _validate_email(self, email):
        email = (email or '').strip()
        if not email or '@' not in email:
            raise ValueError("Valid Let's Encrypt email is required")
        return email

    def _read_file(self, path):
        out, _, code = self.ssh.run_sudo_command(f"cat {_q(path)} 2>/dev/null")
        return out if code == 0 else ''

    def _write_file(self, path, content):
        parent = path.rsplit('/', 1)[0]
        self.ssh.run_sudo_command(f"mkdir -p {_q(parent)}")
        self.ssh.upload_file_sudo(content, path)

    def _read_metadata(self):
        raw = self._read_file(self.meta_path)
        if not raw.strip():
            return {}
        try:
            return json.loads(raw)
        except Exception:
            return {}

    def _write_metadata(self, meta):
        self._write_file(self.meta_path, json.dumps(meta, indent=2, ensure_ascii=False))

    def _read_clients(self):
        raw = self._read_file(self.clients_path)
        if not raw.strip():
            return []
        try:
            data = json.loads(raw)
            return data if isinstance(data, list) else []
        except Exception:
            return []

    def _write_clients(self, clients):
        self._write_file(self.clients_path, json.dumps(clients, indent=2, ensure_ascii=False))

    def _ensure_secrets(self, meta):
        """Password auth (Happ/INCY-friendly) + salamander obfs secrets."""
        changed = False
        if not meta.get('password'):
            meta['password'] = _rand_token(24)
            changed = True
        if not meta.get('obfs_password'):
            meta['obfs_password'] = _rand_token(16)
            changed = True
        if changed:
            self._write_metadata(meta)
        return meta

    def _build_server_yaml(self, port, clients, meta=None):
        meta = self._ensure_secrets(meta if meta is not None else self._read_metadata())
        password = meta['password']
        obfs_password = meta['obfs_password']
        # password auth — Happ / sing-box / INCY expect a single auth string, not userpass
        lines = [
            f'listen: :{int(port)}',
            '',
            'tls:',
            '  cert: /etc/hysteria/cert.crt',
            '  key: /etc/hysteria/private.key',
            '',
            'auth:',
            '  type: password',
            f'  password: "{password}"',
            '',
            'obfs:',
            '  type: salamander',
            '  salamander:',
            f'    password: "{obfs_password}"',
            '',
            'quic:',
            '  initStreamReceiveWindow: 8388608',
            '  maxStreamReceiveWindow: 8388608',
            '  initConnReceiveWindow: 20971520',
            '  maxConnReceiveWindow: 20971520',
            '  maxIdleTimeout: 60s',
            '  maxIncomingStreams: 1024',
            '  disablePathMTUDiscovery: true',
            '',
            'ignoreClientBandwidth: true',
            '',
            'bandwidth:',
            '  up: 1 gbps',
            '  down: 1 gbps',
            '',
            'masquerade:',
            '  type: proxy',
            '  proxy:',
            '    url: https://www.bing.com',
            '    rewriteHost: true',
            '',
            'outbounds:',
            '  - name: direct',
            '    type: direct',
            '',
        ]
        return '\n'.join(lines)

    def _write_config_from_clients(self, port=None):
        meta = self._ensure_secrets(self._read_metadata())
        port = int(port or meta.get('port') or self.DEFAULT_PORT)
        # clients list is panel-side only (shared password); still rewrite yaml for port/obfs/secrets
        self._write_file(self.config_path, self._build_server_yaml(port, self._read_clients(), meta))
        return port

    def _tune_host_network(self):
        """UDP buffers + BBR — reduces quic-go EOF and improves throughput."""
        script = r"""
set +e
mkdir -p /etc/sysctl.d
printf '%s\n' \
  'net.core.rmem_max=16777216' \
  'net.core.wmem_max=16777216' \
  'net.core.rmem_default=16777216' \
  'net.core.wmem_default=16777216' \
  'net.core.default_qdisc=fq' \
  'net.ipv4.tcp_congestion_control=bbr' \
  'net.ipv4.ip_forward=1' \
  > /etc/sysctl.d/99-amnezia-hysteria.conf
modprobe tcp_bbr >/dev/null 2>&1 || true
sysctl -p /etc/sysctl.d/99-amnezia-hysteria.conf >/dev/null 2>&1 || true
sysctl -w net.core.rmem_max=16777216 >/dev/null 2>&1 || true
sysctl -w net.core.wmem_max=16777216 >/dev/null 2>&1 || true
sysctl -w net.core.rmem_default=16777216 >/dev/null 2>&1 || true
sysctl -w net.core.wmem_default=16777216 >/dev/null 2>&1 || true
sysctl -w net.core.default_qdisc=fq >/dev/null 2>&1 || true
sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1 || true
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
"""
        self.ssh.run_sudo_command(f"sh -c {_q(script)}", timeout=30)

    def _strip_ansi(self, text):
        return re.sub(r'\x1b\[[0-9;]*m', '', text or '')

    def _udp_port_busy(self, port):
        """Return (busy: bool, detail: str) for host UDP port (after our container is removed)."""
        port = int(port)
        out, _, _ = self.ssh.run_sudo_command(
            f"ss -ulnp 'sport = :{port}' 2>/dev/null || "
            f"ss -uln | grep -E ':{port}([[:space:]]|$)' || true"
        )
        detail = (out or '').strip()
        return bool(detail), detail[:240]

    def _open_udp_port(self, port):
        port = int(port)
        script = f"""
set +e
if command -v ufw >/dev/null 2>&1; then
  ufw allow {port}/udp >/dev/null 2>&1 || true
fi
if command -v firewall-cmd >/dev/null 2>&1; then
  firewall-cmd --permanent --add-port={port}/udp >/dev/null 2>&1 || true
  firewall-cmd --reload >/dev/null 2>&1 || true
fi
iptables -C INPUT -p udp --dport {port} -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport {port} -j ACCEPT 2>/dev/null || true
"""
        self.ssh.run_sudo_command(f"sh -c {_q(script)}", timeout=30)

    def _start_container(self, port):
        """Run with --network host so QUIC/UDP is not broken by Docker NAT (EOF)."""
        name = self.container_name
        port = int(port)
        if port == 80:
            raise RuntimeError('Port 80 is reserved for Let\'s Encrypt validation')
        self._tune_host_network()
        self._open_udp_port(port)
        self.ssh.run_sudo_command(
            f"chmod 644 {_q(self.cert_path)} {_q(self.key_path)} 2>/dev/null || true"
        )
        self.ssh.run_sudo_command(f"docker rm -fv {name} 2>/dev/null || true")
        busy, detail = self._udp_port_busy(port)
        if busy:
            raise RuntimeError(
                f'UDP port {port} is already in use — choose another port in Hysteria settings. '
                f'({self._strip_ansi(detail)})'
            )
        run_cmd = (
            f"docker run -d --restart always "
            f"--name {name} "
            f"--network host "
            f"--cap-add=NET_ADMIN "
            f"-v {_q(self.base_dir)}:/etc/hysteria "
            f"{self.IMAGE_NAME} "
            f"-c /etc/hysteria/server.yaml server"
        )
        _, err, code = self.ssh.run_sudo_command(run_cmd, timeout=60)
        if code != 0:
            raise RuntimeError(f'Failed to start Hysteria: {err}')
        # Confirm it stayed up (catch immediate bind failures)
        time.sleep(1.2)
        if not self.check_container_running(self.protocol):
            diag = self.get_container_diagnostics(self.protocol)
            raise RuntimeError(
                diag.get('error_summary')
                or 'Hysteria container exited immediately — check logs / port'
            )
        return True

    def get_settings(self):
        meta = self._ensure_secrets(self._read_metadata())
        port = int(meta.get('port') or self.DEFAULT_PORT)
        return {
            'port': port,
            'suggested_port': 8998 if port in (443, 80) else port,
            'domain': meta.get('domain') or '',
            'email': meta.get('email') or '',
            'protocol': self.protocol,
        }

    def update_settings(self, port=None, domain=None, email=None, renew_ssl=False):
        """Change listen UDP port and/or re-issue Let's Encrypt for domain."""
        meta = self._ensure_secrets(self._read_metadata())
        if port is None:
            port = meta.get('port') or self.DEFAULT_PORT
        port = int(port)
        if port < 1 or port > 65535:
            return {'status': 'error', 'message': 'Invalid port'}
        if port == 80:
            return {'status': 'error', 'message': 'Port 80 is reserved for Let\'s Encrypt validation'}

        old_domain = (meta.get('domain') or '').strip().lower()
        domain_changed = False
        try:
            if domain is not None and str(domain).strip():
                new_domain = self._validate_domain(domain)
                domain_changed = new_domain != old_domain
                meta['domain'] = new_domain
            if email is not None and str(email).strip():
                meta['email'] = self._validate_email(email)
        except ValueError as e:
            return {'status': 'error', 'message': str(e)}

        if renew_ssl or domain_changed:
            # Domain change or explicit renew → re-issue certificate (needs free TCP 80)
            try:
                d = meta.get('domain') or ''
                e = meta.get('email') or ''
                if not d or not e:
                    return {
                        'status': 'error',
                        'message': 'Domain and email are required to issue SSL',
                    }
                self._issue_certificate(d, e)
            except Exception as exc:
                return {'status': 'error', 'message': str(exc)}

        meta['port'] = port
        self._write_metadata(meta)
        self._write_config_from_clients(port)
        try:
            self._start_container(port)
        except Exception as e:
            return {
                'status': 'error',
                'message': str(e),
                'port': str(port),
                'domain': meta.get('domain'),
                'email': meta.get('email'),
            }
        msg = 'Hysteria settings updated'
        if renew_ssl or domain_changed:
            msg = 'SSL certificate issued and Hysteria settings updated'
        return {
            'status': 'success',
            'port': str(port),
            'domain': meta.get('domain'),
            'email': meta.get('email'),
            'message': msg,
        }

    def _reload_container(self):
        meta = self._read_metadata()
        port = int(meta.get('port') or self.DEFAULT_PORT)
        try:
            self._start_container(port)
        except Exception as e:
            logger.warning('Hysteria container reload failed: %s', e)

    def _issue_certificate(self, domain, email):
        """Issue Let's Encrypt cert via certbot standalone (needs free TCP 80)."""
        self.ssh.run_sudo_command(f"mkdir -p {_q(self.letsencrypt_dir)}")
        self.ssh.run_sudo_command(f"docker pull {self.CERTBOT_IMAGE}", timeout=180)

        # Stop anything briefly occupying 80 if it's our leftover certbot
        self.ssh.run_sudo_command(
            "docker rm -fv amnezia-hysteria-certbot 2>/dev/null || true"
        )

        cmd = (
            f"docker run --rm --name amnezia-hysteria-certbot "
            f"-p 80:80 "
            f"-v {_q(self.letsencrypt_dir)}:/etc/letsencrypt "
            f"{self.CERTBOT_IMAGE} certonly --standalone "
            f"--non-interactive --agree-tos --no-eff-email "
            f"--email {_q(email)} -d {_q(domain)}"
        )
        out, err, code = self.ssh.run_sudo_command(cmd, timeout=300)
        if code != 0:
            raise RuntimeError(
                f"Let's Encrypt failed for {domain}. "
                f"Point A-record to this server and free TCP port 80. {err or out}"
            )

        # Copy live certs into paths expected by the server config
        copy_script = f"""
set -e
LIVE={_q(self.letsencrypt_dir)}/live/{_q(domain)}
test -s "$LIVE/fullchain.pem"
test -s "$LIVE/privkey.pem"
cp -f "$LIVE/fullchain.pem" {_q(self.cert_path)}
cp -f "$LIVE/privkey.pem" {_q(self.key_path)}
chmod 644 {_q(self.cert_path)} {_q(self.key_path)}
"""
        out, err, code = self.ssh.run_sudo_command(f"sh -c {_q(copy_script)}", timeout=30)
        if code != 0:
            raise RuntimeError(f'Failed to install certificate files: {err or out}')

    def _build_share_uri(self, host, port, domain, name, meta=None):
        """Happ/INCY-compatible hy2 link: password auth + salamander + IP host + SNI."""
        meta = self._ensure_secrets(meta if meta is not None else self._read_metadata())
        password = meta['password']
        obfs_password = meta['obfs_password']
        sni = domain or host
        # Prefer raw IP in URI — domain may be CDN/DNS filtered for UDP while ICMP still works
        conn_host = host or domain
        fragment = quote(name or 'hysteria', safe='')
        return (
            f"hy2://{quote(password, safe='')}@{conn_host}:{int(port)}/"
            f"?sni={quote(sni, safe='')}"
            f"&obfs=salamander"
            f"&obfs-password={quote(obfs_password, safe='')}"
            f"&insecure=0#{fragment}"
        )

    # ===================== INSTALL / REMOVE =====================

    def install_protocol(self, protocol_type=None, port=None, domain=None, email=None):
        protocol_type = protocol_type or self.protocol
        if not self.check_docker_installed():
            return {'status': 'error', 'message': 'Docker not installed'}

        domain = self._validate_domain(domain)
        email = self._validate_email(email)
        port = int(port or self.DEFAULT_PORT)
        if port == 80:
            return {'status': 'error', 'message': 'Port 80 is reserved for Let\'s Encrypt validation'}

        log = []
        self.ssh.run_sudo_command(f"docker pull {self.IMAGE_NAME}", timeout=180)
        log.append(f'Pulled {self.IMAGE_NAME}')

        if self.check_protocol_installed(protocol_type):
            name = self._container_name(protocol_type)
            self.ssh.run_sudo_command(f"docker rm -fv {name} 2>/dev/null || true")
            log.append('Removed previous container')

        self.ssh.run_sudo_command(f"mkdir -p {_q(self.base_dir)}")
        self._write_clients([])
        meta = {
            'domain': domain,
            'email': email,
            'port': port,
            'password': _rand_token(24),
            'obfs_password': _rand_token(16),
        }
        self._write_metadata(meta)
        self._write_config_from_clients(port)
        log.append('Prepared config directory (password auth + salamander + BBR)')

        try:
            self._issue_certificate(domain, email)
            log.append(f"Issued Let's Encrypt certificate for {domain}")
        except Exception as e:
            return {'status': 'error', 'message': str(e), 'log': log}

        try:
            self._start_container(port)
        except Exception as e:
            return {'status': 'error', 'message': str(e), 'log': log}

        log.append(f'Started {self.container_name} on UDP {port} (host network, BBR)')
        return {
            'status': 'success',
            'message': 'Hysteria installed',
            'log': log,
            'port': str(port),
            'domain': domain,
            'email': email,
        }

    def remove_container(self, protocol_type=None):
        protocol_type = protocol_type or self.protocol
        name = self._container_name(protocol_type)
        base = self._base_dir(protocol_type)
        self.ssh.run_sudo_command(f"docker rm -fv {name} 2>/dev/null || true")
        self.ssh.run_sudo_command(f"rm -rf {_q(base)}")
        return True

    def get_server_config(self, protocol_type=None):
        return self._read_file(self.config_path)

    def save_server_config(self, protocol_type=None, config_text=''):
        self._write_file(self.config_path, config_text or '')
        self._reload_container()
        return True

    # ===================== CLIENTS =====================

    def get_clients(self, protocol_type=None):
        clients = self._read_clients()
        result = []
        for c in clients:
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
        meta = self._ensure_secrets(self._read_metadata())
        domain = meta.get('domain') or host
        port = int(port or meta.get('port') or self.DEFAULT_PORT)
        client_id = secrets.token_hex(8)
        clients = self._read_clients()
        clients.append({
            'id': client_id,
            'name': name or f'client-{client_id[:6]}',
            'enabled': True,
        })
        self._write_clients(clients)
        # Shared password auth — refresh yaml only if secrets/port changed
        self._write_config_from_clients(port)
        self._reload_container()
        config = self._build_share_uri(host, port, domain, name or client_id, meta)
        return {'client_id': client_id, 'config': config}

    def get_client_config(self, protocol_type, client_id, host, port=None):
        meta = self._ensure_secrets(self._read_metadata())
        domain = meta.get('domain') or host
        port = int(port or meta.get('port') or self.DEFAULT_PORT)
        clients = self._read_clients()
        client = next((c for c in clients if c.get('id') == client_id), None)
        if not client:
            raise RuntimeError('Client not found')
        if client.get('enabled', True) is False:
            raise RuntimeError('Client is disabled')
        return self._build_share_uri(
            host, port, domain,
            client.get('name') or client_id,
            meta,
        )

    def remove_client(self, protocol_type, client_id):
        clients = [c for c in self._read_clients() if c.get('id') != client_id]
        self._write_clients(clients)
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
        return True
