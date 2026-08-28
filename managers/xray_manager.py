import json
import os
import re
import secrets
import uuid
import logging
import base64
import shlex
from datetime import datetime
import urllib.parse

logger = logging.getLogger(__name__)

CERTBOT_IMAGE = 'certbot/certbot:latest'
CERTBOT_CF_IMAGE = 'certbot/dns-cloudflare:latest'
XRAY_RELEASE = 'v26.3.27'


def _q(value):
    return shlex.quote(str(value))


class XrayManager:
    """Manages Xray VLESS + XHTTP + TLS (Let's Encrypt) for DPI-resistant installs."""

    PROTOCOL = 'xray'
    CONTAINER_NAME = 'amnezia-xray'
    IMAGE_NAME = 'amneziavpn/amnezia-xray'
    DEFAULT_PORT = 8443

    def __init__(self, ssh_manager, protocol='xray'):
        self.ssh = ssh_manager
        self.protocol = protocol or self.PROTOCOL
        self.base_protocol = str(self.protocol).split('__', 1)[0]
        self.instance = self._instance_index(self.protocol)
        self.container_name = self._container_name(self.protocol)
        self.image_name = self._image_name(self.protocol)

    def _instance_index(self, protocol):
        parts = str(protocol or '').split('__', 1)
        if len(parts) == 2:
            try:
                return max(1, int(parts[1]))
            except ValueError:
                return 1
        return 1

    def _container_name(self, protocol=None):
        idx = self._instance_index(protocol or self.protocol)
        base_name = self.CONTAINER_NAME
        return base_name if idx <= 1 else f'{base_name}-{idx}'

    def _image_name(self, protocol=None):
        idx = self._instance_index(protocol or self.protocol)
        base_name = self.IMAGE_NAME
        return base_name if idx <= 1 else f'{base_name}-{idx}'

    def _config_dir(self):
        return '/opt/amnezia/xray' if self.instance <= 1 else f'/opt/amnezia/xray-{self.instance}'

    def _config_path(self):
        return f'{self._config_dir()}/server.json'

    def _list_xray_files(self):
        """List filenames in the on-disk Xray config directory."""
        out, _, code = self.ssh.run_sudo_command(f"ls -1 {self._config_dir()} 2>/dev/null")
        if code != 0:
            return []
        return [f for f in out.strip().split('\n') if f]

    def _detect_layout(self):
        """Pick which on-disk layout this installation uses.

        'native' — official Amnezia client layout: xray_private.key,
        xray_public.key, xray_short_id.key, xray_uuid.key plus a clientsTable
        file without an extension.
        'panel'  — legacy web-panel layout: meta.json + clientsTable.json.

        On a fresh node with no Xray files yet, defaults to 'native' so new
        installs produce the same artifacts as the official client.
        """
        if hasattr(self, '_cached_layout'):
            return self._cached_layout
        files = set(self._list_xray_files())
        if {'xray_private.key', 'xray_public.key'} & files:
            layout = 'native'
        elif 'meta.json' in files:
            layout = 'panel'
        else:
            layout = 'native'
        self._cached_layout = layout
        return layout

    def _clients_table_filename(self):
        return 'clientsTable' if self._detect_layout() == 'native' else 'clientsTable.json'

    def _clients_table_path(self):
        return f'{self._config_dir()}/{self._clients_table_filename()}'

    def _read_remote_file(self, path):
        """Read a remote text file, preferring the running container's view."""
        out, _, code = self.ssh.run_sudo_command(
            f"docker exec {self.container_name} cat {path} 2>/dev/null"
        )
        if code != 0 or not out:
            out, _, code = self.ssh.run_sudo_command(f"cat {path} 2>/dev/null")
        if code != 0 or not out.strip():
            return None
        return out

    def _derive_pubkey_from_priv(self, priv_key):
        """Derive the Reality public key from a private key via the xray binary.
        Used as a fallback when xray_public.key is missing or unreadable.
        """
        if not priv_key:
            return ''
        out, _, code = self.ssh.run_sudo_command(
            f"docker exec {self.container_name} /usr/bin/xray x25519 -i {priv_key}"
        )
        if code != 0 or not out.strip():
            out, _, code = self.ssh.run_sudo_command(
                f"docker run --rm --entrypoint=\"\" {self.image_name} /usr/bin/xray x25519 -i {priv_key}"
            )
        if code != 0 or not out:
            return ''
        for line in out.split('\n'):
            if 'Public' in line and ':' in line:
                return line.split(':', 1)[1].strip()
        return ''

    def _get_default_xray_uuid(self):
        """UUID of the install-time default client (xray_uuid.key) — meaningful only
        for native-layout installs. Imports skip this UUID, mirroring the official
        Amnezia client behaviour (see usersController.cpp::getXrayClients).
        """
        if self._detect_layout() != 'native':
            return ''
        out = self._read_remote_file(f"{self._config_dir()}/xray_uuid.key")
        return (out or '').strip()

    # ===================== INSTALLATION =====================

    def check_docker_installed(self):
        out, err, code = self.ssh.run_command("docker --version 2>/dev/null")
        if code != 0: return False
        out2, _, code2 = self.ssh.run_command("systemctl is-active docker 2>/dev/null || service docker status 2>/dev/null")
        return 'active' in out2 or 'running' in out2.lower()

    def check_container_running(self):
        out, _, _ = self.ssh.run_sudo_command(
            f"docker ps --filter name=^{self.container_name}$ --format '{{{{.Status}}}}'"
        )
        return 'Up' in out

    def check_protocol_installed(self):
        out, _, _ = self.ssh.run_sudo_command(
            f"docker ps -a --filter name=^{self.container_name}$ --format '{{{{.Names}}}}'"
        )
        return self.container_name in out.strip().split('\n')

    def get_server_status(self, protocol):
        exists = self.check_protocol_installed()
        if exists:
            try:
                self._heal_xhttp_config()
            except Exception as e:
                logger.warning(f"Xray config heal skipped: {e}")
        running = self.check_container_running()
        clients = self.get_clients() if exists else []
        meta = self._get_meta_json() if exists else {}
        return {
            'container_exists': exists,
            'container_running': running,
            'clients_count': len(clients),
            'port': meta.get('port'),
            'domain': meta.get('domain') or meta.get('site_name'),
            'transport': meta.get('transport') or 'xhttp',
            'security': meta.get('security') or 'tls',
            'acme_method': meta.get('acme_method'),
            'path': meta.get('path'),
        }

    def _normalize_xhttp_headers_in_config(self, config):
        """Xray xhttp headers must be map[string]string — arrays crash the process."""
        changed = False
        for inbound in (config.get('inbounds') or []):
            stream = inbound.get('streamSettings') or {}
            for key in ('xhttpSettings', 'splithttpSettings'):
                xs = stream.get(key)
                if not isinstance(xs, dict):
                    continue
                headers = xs.get('headers')
                if headers is None:
                    continue
                if not isinstance(headers, dict):
                    xs.pop('headers', None)
                    changed = True
                    continue
                fixed = {}
                for hk, hv in headers.items():
                    if isinstance(hv, str):
                        fixed[hk] = hv
                        continue
                    changed = True
                    if isinstance(hv, list) and hv:
                        fixed[hk] = str(hv[0])
                    elif hv is not None and not isinstance(hv, (dict, list)):
                        fixed[hk] = str(hv)
                if fixed:
                    xs['headers'] = fixed
                else:
                    xs.pop('headers', None)
        return changed

    def _normalize_xhttp_stream_for_compat(self, config):
        """Make inbound XHTTP+TLS closer to known-working minimal configs."""
        changed = self._normalize_xhttp_headers_in_config(config)
        for inbound in (config.get('inbounds') or []):
            if inbound.get('protocol') != 'vless':
                continue
            stream = inbound.get('streamSettings') or {}
            network = str(stream.get('network') or '').lower()
            security = str(stream.get('security') or '').lower()
            if network not in ('xhttp', 'splithttp') or security != 'tls':
                continue

            # Prefer canonical network name
            if network == 'splithttp':
                stream['network'] = 'xhttp'
                changed = True

            xs_key = 'xhttpSettings' if 'xhttpSettings' in stream else (
                'splithttpSettings' if 'splithttpSettings' in stream else 'xhttpSettings'
            )
            xs = stream.get(xs_key)
            if not isinstance(xs, dict):
                xs = {}
                stream[xs_key] = xs
                changed = True

            # Migrate splithttpSettings → xhttpSettings
            if xs_key == 'splithttpSettings':
                stream['xhttpSettings'] = xs
                stream.pop('splithttpSettings', None)
                changed = True

            # Server-side host rejects mismatched Host headers on some clients
            if 'host' in xs:
                xs.pop('host', None)
                changed = True
            if 'headers' in xs:
                xs.pop('headers', None)
                changed = True
            if not xs.get('path'):
                xs['path'] = '/'
                changed = True
            if xs.get('mode') not in (None, '', 'auto', 'packet-up', 'stream-up', 'stream-one'):
                xs['mode'] = 'auto'
                changed = True
            elif not xs.get('mode'):
                xs['mode'] = 'auto'
                changed = True

            tls = stream.get('tlsSettings')
            if not isinstance(tls, dict):
                tls = {}
                stream['tlsSettings'] = tls
                changed = True
            # minVersion / serverName are optional and can hurt older clients
            if 'minVersion' in tls:
                tls.pop('minVersion', None)
                changed = True
            alpn = tls.get('alpn')
            if not isinstance(alpn, list) or not alpn:
                tls['alpn'] = ['h2', 'http/1.1']
                changed = True

            sockopt = stream.get('sockopt')
            if isinstance(sockopt, dict):
                # TCP Fast Open frequently breaks mobile/CGNAT paths
                if sockopt.pop('tcpFastOpen', None) is not None:
                    changed = True
                if not sockopt:
                    stream.pop('sockopt', None)
                    changed = True

            inbound['streamSettings'] = stream
        return changed

    def _heal_xhttp_config(self):
        """Fix crash/compat issues in existing XHTTP+TLS server.json."""
        config = self._get_server_json()
        if not config or not self._normalize_xhttp_stream_for_compat(config):
            return False
        path = self._config_path()
        self.ssh.upload_file_sudo(json.dumps(config, indent=2), path)
        self.ssh.run_sudo_command(
            f"docker cp {_q(path)} {self.container_name}:{path} 2>/dev/null || true"
        )
        self.ssh.run_sudo_command(
            f"docker restart {self.container_name} 2>/dev/null || docker start {self.container_name} 2>/dev/null || true"
        )
        logger.info("Healed Xray XHTTP+TLS stream settings for client compatibility")
        return True

    def _validate_domain(self, domain):
        domain = (domain or '').strip().lower().rstrip('.')
        if not domain or not re.match(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$', domain):
            raise ValueError('Valid domain is required for Xray XHTTP+TLS (e.g. vpn.example.com)')
        return domain

    def _validate_email(self, email):
        email = (email or '').strip()
        if not email or '@' not in email or '.' not in email.split('@')[-1]:
            raise ValueError('Valid email is required for Let\'s Encrypt')
        return email

    def _certs_dir(self):
        return f'{self._config_dir()}/certs'

    def _letsencrypt_dir(self):
        return f'{self._config_dir()}/letsencrypt'

    def _cert_path(self):
        return f'{self._certs_dir()}/fullchain.pem'

    def _key_path(self):
        return f'{self._certs_dir()}/privkey.pem'

    def _random_xhttp_path(self):
        # Short opaque path — better client compatibility than nested “asset” URLs.
        return f'/{secrets.token_hex(8)}'

    def _cf_creds_path(self):
        return f'{self._config_dir()}/cloudflare.ini'

    def _write_cloudflare_ini(self, token):
        token = (token or '').strip()
        if not token:
            raise ValueError('Cloudflare API token is required for DNS validation')
        # Restrictive file for certbot dns plugin
        content = f"dns_cloudflare_api_token = {token}\n"
        path = self._cf_creds_path()
        self.ssh.run_sudo_command(f"mkdir -p {_q(self._config_dir())}")
        self.ssh.upload_file_sudo(content, path)
        self.ssh.run_sudo_command(f"chmod 600 {_q(path)}")
        return path

    def _install_issued_certs(self, domain, le_dir):
        copy_script = f"""
set -e
LIVE={_q(le_dir)}/live/{_q(domain)}
test -s "$LIVE/fullchain.pem"
test -s "$LIVE/privkey.pem"
mkdir -p {_q(self._certs_dir())}
cp -f "$LIVE/fullchain.pem" {_q(self._cert_path())}
cp -f "$LIVE/privkey.pem" {_q(self._key_path())}
chmod 644 {_q(self._cert_path())} {_q(self._key_path())}
"""
        out, err, code = self.ssh.run_sudo_command(f"sh -c {_q(copy_script)}", timeout=30)
        if code != 0:
            raise RuntimeError(f'Failed to install certificate files: {err or out}')

    def _issue_certificate(self, domain, email, *, acme_method='cloudflare', cloudflare_token=None):
        """Issue Let's Encrypt cert via Cloudflare DNS-01 (preferred) or HTTP-01 standalone."""
        method = (acme_method or 'cloudflare').strip().lower()
        if method in ('cf', 'dns', 'dns-01', 'cloudflare_dns'):
            method = 'cloudflare'
        if method in ('http', 'http-01', 'standalone', 'port80'):
            method = 'http'

        le_dir = self._letsencrypt_dir()
        certs_dir = self._certs_dir()
        self.ssh.run_sudo_command(f"mkdir -p {_q(le_dir)} {_q(certs_dir)}")
        self.ssh.run_sudo_command("docker rm -fv amnezia-xray-certbot 2>/dev/null || true")

        if method == 'cloudflare':
            creds = self._write_cloudflare_ini(cloudflare_token)
            self.ssh.run_sudo_command(f"docker pull {CERTBOT_CF_IMAGE}", timeout=180)
            # DNS-01 — no TCP 80 needed. Token needs Zone:DNS:Edit on the domain zone.
            cmd = (
                f"docker run --rm --name amnezia-xray-certbot "
                f"-v {_q(le_dir)}:/etc/letsencrypt "
                f"-v {_q(creds)}:/cloudflare.ini:ro "
                f"{CERTBOT_CF_IMAGE} certonly "
                f"--dns-cloudflare "
                f"--dns-cloudflare-credentials /cloudflare.ini "
                f"--dns-cloudflare-propagation-seconds 30 "
                f"--non-interactive --agree-tos --no-eff-email "
                f"--email {_q(email)} -d {_q(domain)}"
            )
            out, err, code = self.ssh.run_sudo_command(cmd, timeout=420)
            if code != 0:
                raise RuntimeError(
                    f"Let's Encrypt (Cloudflare DNS) failed for {domain}. "
                    f"Check API token (Zone:DNS:Edit) and that the domain is on Cloudflare. {err or out}"
                )
            self._install_issued_certs(domain, le_dir)
            return 'cloudflare'

        # HTTP-01 standalone — needs free TCP 80
        self.ssh.run_sudo_command(f"docker pull {CERTBOT_IMAGE}", timeout=180)
        cmd = (
            f"docker run --rm --name amnezia-xray-certbot "
            f"-p 80:80 "
            f"-v {_q(le_dir)}:/etc/letsencrypt "
            f"{CERTBOT_IMAGE} certonly --standalone "
            f"--non-interactive --agree-tos --no-eff-email "
            f"--email {_q(email)} -d {_q(domain)}"
        )
        out, err, code = self.ssh.run_sudo_command(cmd, timeout=300)
        if code != 0:
            raise RuntimeError(
                f"Let's Encrypt (HTTP-01) failed for {domain}. "
                f"Point an A-record to this server and free TCP port 80. {err or out}"
            )
        self._install_issued_certs(domain, le_dir)
        return 'http'

    def _is_xhttp_tls_inbound(self, inbound):
        stream = (inbound or {}).get('streamSettings') or {}
        return (
            str(stream.get('network') or '').lower() in ('xhttp', 'splithttp')
            and str(stream.get('security') or '').lower() == 'tls'
        )

    def _is_reality_inbound(self, inbound):
        stream = (inbound or {}).get('streamSettings') or {}
        return str(stream.get('security') or '').lower() == 'reality'

    def install_protocol(self, port=8443, domain=None, email=None, site_name=None,
                         acme_method='cloudflare', cloudflare_token=None):
        """Install VLESS + XHTTP + TLS (Let's Encrypt via Cloudflare DNS or HTTP-01)."""
        results = []
        domain = self._validate_domain(domain or site_name)
        email = self._validate_email(email)
        port = int(port or self.DEFAULT_PORT)
        if port < 1 or port > 65535:
            raise ValueError('Port must be between 1 and 65535')
        method = (acme_method or 'cloudflare').strip().lower()
        if method in ('cf', 'dns', 'dns-01', 'cloudflare_dns'):
            method = 'cloudflare'
        if method in ('http', 'http-01', 'standalone', 'port80'):
            method = 'http'
        if method == 'http' and port == 80:
            raise RuntimeError('Port 80 is reserved for Let\'s Encrypt HTTP-01 validation')
        if method == 'cloudflare' and not (cloudflare_token or '').strip():
            raise ValueError('Cloudflare API token is required')

        if not self.check_docker_installed():
            results.append("Docker not detected — install may fail")

        results.append("Removing old container if exists...")
        if self.check_protocol_installed():
            self.remove_container()

        if method == 'cloudflare':
            results.append(f"Issuing Let's Encrypt cert via Cloudflare DNS for {domain}...")
        else:
            results.append(f"Issuing Let's Encrypt cert via HTTP-01 (port 80) for {domain}...")
        used = self._issue_certificate(
            domain, email, acme_method=method, cloudflare_token=cloudflare_token,
        )
        results.append(f"TLS certificate ready ({used})")

        results.append("Building Docker image...")
        config_dir = self._config_dir()
        dockerfile_folder = f"/opt/amnezia/{self.container_name}"
        dockerfile_content = f"""FROM alpine:3.15
RUN apk add --no-cache curl unzip bash openssl netcat-openbsd dumb-init rng-tools xz iptables ip6tables ca-certificates
RUN apk --update upgrade --no-cache
RUN mkdir -p {config_dir}
RUN curl -L -H "Cache-Control: no-cache" -o /root/xray.zip "https://github.com/XTLS/Xray-core/releases/download/{XRAY_RELEASE}/Xray-linux-64.zip" && \\
    unzip /root/xray.zip -d /usr/bin/ && \\
    chmod a+x /usr/bin/xray && \\
    rm /root/xray.zip

RUN echo "fs.file-max = 51200" >> /etc/sysctl.conf && \\
    echo "net.core.rmem_max = 67108864" >> /etc/sysctl.conf && \\
    echo "net.core.wmem_max = 67108864" >> /etc/sysctl.conf && \\
    echo "net.core.netdev_max_backlog = 250000" >> /etc/sysctl.conf && \\
    echo "net.core.somaxconn = 4096" >> /etc/sysctl.conf && \\
    echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf && \\
    echo "net.ipv4.tcp_tw_reuse = 1" >> /etc/sysctl.conf && \\
    echo "net.ipv4.tcp_fin_timeout = 30" >> /etc/sysctl.conf && \\
    echo "net.ipv4.tcp_keepalive_time = 1200" >> /etc/sysctl.conf && \\
    echo "net.ipv4.ip_local_port_range = 10000 65000" >> /etc/sysctl.conf && \\
    echo "net.ipv4.tcp_max_syn_backlog = 8192" >> /etc/sysctl.conf && \\
    echo "net.ipv4.tcp_fastopen = 3" >> /etc/sysctl.conf && \\
    echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf

RUN mkdir -p /etc/security && \\
    echo "* soft nofile 51200" >> /etc/security/limits.conf && \\
    echo "* hard nofile 51200" >> /etc/security/limits.conf

RUN echo '#!/bin/bash' > /opt/amnezia/start.sh && \\
    echo 'sysctl -p /etc/sysctl.conf 2>/dev/null' >> /opt/amnezia/start.sh && \\
    echo '/usr/bin/xray -config {config_dir}/server.json' >> /opt/amnezia/start.sh && \\
    chmod a+x /opt/amnezia/start.sh

ENTRYPOINT [ "dumb-init", "/opt/amnezia/start.sh" ]
"""
        self.ssh.run_sudo_command(f"mkdir -p {dockerfile_folder}")
        self.ssh.upload_file_sudo(dockerfile_content, f"{dockerfile_folder}/Dockerfile")

        _, err, code = self.ssh.run_sudo_command(
            f"docker build --no-cache -t {self.image_name} {dockerfile_folder}", timeout=300
        )
        if code != 0:
            raise RuntimeError(f"Failed to build container: {err}")

        results.append("Generating XHTTP+TLS config...")
        xhttp_path = self._random_xhttp_path()
        # auto → packet-up under TLS (CDN/middlebox friendly); works direct too.
        xhttp_mode = 'auto'

        server_json = {
            "log": {"loglevel": "warning"},
            "stats": {},
            "api": {
                "services": ["StatsService", "LoggerService", "HandlerService"],
                "tag": "api"
            },
            "policy": {
                "levels": {
                    "0": {"statsUserUplink": True, "statsUserDownlink": True}
                },
                "system": {
                    "statsInboundUplink": True, "statsInboundDownlink": True,
                    "statsOutboundUplink": True, "statsOutboundDownlink": True
                }
            },
            "inbounds": [
                {
                    "listen": "0.0.0.0",
                    "port": int(port),
                    "protocol": "vless",
                    "tag": "proxy",
                    "settings": {
                        "clients": [],
                        "decryption": "none"
                    },
                    "streamSettings": {
                        "network": "xhttp",
                        "security": "tls",
                        "tlsSettings": {
                            "alpn": ["h2", "http/1.1"],
                            "certificates": [{
                                "certificateFile": self._cert_path(),
                                "keyFile": self._key_path()
                            }]
                        },
                        "xhttpSettings": {
                            "path": xhttp_path,
                            "mode": xhttp_mode
                        }
                    },
                    "sniffing": {
                        "enabled": True,
                        "destOverride": ["http", "tls", "quic"],
                        "routeOnly": True
                    }
                },
                {
                    "listen": "127.0.0.1",
                    "port": 10085,
                    "protocol": "dokodemo-door",
                    "settings": {"address": "127.0.0.1"},
                    "tag": "api"
                }
            ],
            "outbounds": [
                {"protocol": "freedom", "tag": "direct"},
                {"protocol": "blackhole", "tag": "block"}
            ],
            "routing": {
                "domainStrategy": "AsIs",
                "rules": [
                    {
                        "type": "field",
                        "inboundTag": ["api"],
                        "outboundTag": "api"
                    },
                    {
                        "type": "field",
                        "protocol": ["bittorrent"],
                        "outboundTag": "block"
                    }
                ]
            }
        }

        self.ssh.run_sudo_command(f"mkdir -p {config_dir}")
        self.ssh.upload_file_sudo(json.dumps(server_json, indent=2), f"{config_dir}/server.json")

        meta = {
            'transport': 'xhttp',
            'security': 'tls',
            'domain': domain,
            'email': email,
            'path': xhttp_path,
            'mode': xhttp_mode,
            'port': int(port),
            'fingerprint': 'chrome',
            'alpn': 'h2,http/1.1',
            'site_name': domain,
            'acme_method': used,
        }
        self.ssh.upload_file_sudo(json.dumps(meta, indent=2), f"{config_dir}/meta.json")
        self.ssh.upload_file_sudo("[]", f"{config_dir}/clientsTable.json")
        # Clear cached layout so we pick panel (meta.json) next.
        if hasattr(self, '_cached_layout'):
            delattr(self, '_cached_layout')

        results.append("Starting container...")
        run_cmd = f"""docker run -d \\
--restart always \\
--privileged \\
--cap-add=NET_ADMIN \\
-p {port}:{port}/tcp \\
-v {config_dir}:{config_dir} \\
--name {self.container_name} \\
{self.image_name}"""

        _, err, code = self.ssh.run_sudo_command(run_cmd)
        if code != 0:
            raise RuntimeError(f"Failed to run container: {err}")

        self.ssh.run_sudo_command(f"docker network connect amnezia-dns-net {self.container_name} || true")

        results.append("Xray VLESS+XHTTP+TLS configured and running")
        return {
            'status': 'success',
            'protocol': self.protocol,
            'port': port,
            'domain': domain,
            'path': xhttp_path,
            'acme_method': used,
            'log': results,
        }

    def remove_container(self):
        self.ssh.run_sudo_command(f"docker stop {self.container_name}")
        self.ssh.run_sudo_command(f"docker rm -fv {self.container_name}")
        if self.instance <= 1:
            self.ssh.run_sudo_command(f"docker rmi {self.image_name}")
        return True

    # ===================== CLIENT MANAGEMENT =====================

    def _get_server_json(self):
        """Read server.json — tries inside container first, falls back to host path."""
        out, _, code = self.ssh.run_sudo_command(
            f"docker exec {self.container_name} cat {self._config_path()}"
        )
        if code != 0:
            out, _, code = self.ssh.run_sudo_command(f"cat {self._config_path()}")
        if code != 0 or not out.strip():
            return None
        return json.loads(out)

    def _save_server_json(self, data):
        return self._write_server_json(data, restart=True)

    def _write_server_json(self, data, restart=True):
        """Write server.json to host path and into container when possible."""
        if self._normalize_xhttp_stream_for_compat(data):
            logger.info("Normalized XHTTP+TLS stream settings before write")
        tmp_file = "/tmp/_xray_server.json"
        path = self._config_path()
        self.ssh.upload_file_sudo(json.dumps(data, indent=2), tmp_file)
        # Host path first — volume mount survives crash loops
        self.ssh.run_sudo_command(f"cp {tmp_file} {path}")
        self.ssh.run_sudo_command(
            f"docker cp {tmp_file} {self.container_name}:{path} 2>/dev/null || true"
        )
        if restart:
            self.ssh.run_sudo_command(
                f"docker restart {self.container_name} 2>/dev/null || docker start {self.container_name} 2>/dev/null || true"
            )

    def _get_vless_inbound(self, config):
        for inbound in config.get('inbounds', []):
            if inbound.get('protocol') == 'vless':
                return inbound
        return None

    def _get_vless_inbound_tag(self, config):
        inbound = self._get_vless_inbound(config)
        return inbound.get('tag') if inbound else None

    def _run_xray_api_json(self, subcommand, payload):
        tmp_name = f"/tmp/_xray_api_{uuid.uuid4().hex}.json"
        container_tmp = tmp_name
        try:
            self.ssh.upload_file_sudo(json.dumps(payload, indent=2), tmp_name)
            _, err, code = self.ssh.run_sudo_command(
                f"docker cp {tmp_name} {self.container_name}:{container_tmp}"
            )
            if code != 0:
                return False, err
            out, err, code = self.ssh.run_sudo_command(
                f"docker exec -i {self.container_name} /usr/bin/xray api {subcommand} "
                f"-server=127.0.0.1:10085 {container_tmp}"
            )
            return code == 0, err or out
        finally:
            self.ssh.run_sudo_command(f"rm -f {tmp_name}")
            self.ssh.run_sudo_command(f"docker exec -i {self.container_name} rm -f {container_tmp} 2>/dev/null || true")

    def _xray_api_add_user(self, config, client):
        tag = self._get_vless_inbound_tag(config)
        if not tag:
            return False
        payload = {
            "inbounds": [{
                "tag": tag,
                "protocol": "vless",
                "settings": {
                    "clients": [client],
                    "decryption": "none",
                }
            }]
        }
        ok, message = self._run_xray_api_json('adu', payload)
        if not ok:
            logger.warning(f"Xray API add user failed: {message}")
            return False
        return True

    def _xray_api_remove_user(self, config, client_id):
        tag = self._get_vless_inbound_tag(config)
        if not tag:
            return False
        cmd = (
            f"docker exec -i {self.container_name} /usr/bin/xray api rmu "
            f"-server=127.0.0.1:10085 "
            f"-tag={shlex.quote(tag)} {shlex.quote(client_id)}"
        )
        out, err, code = self.ssh.run_sudo_command(cmd)
        if code != 0:
            logger.warning(f"Xray API remove user failed: {err or out}")
            return False
        return True

    def _client_object(self, client_id, inbound=None):
        client = {'id': client_id, 'email': client_id}
        # Vision flow only for classic TCP/Reality; XHTTP must not set flow.
        if inbound and self._is_reality_inbound(inbound):
            network = str((inbound.get('streamSettings') or {}).get('network') or 'tcp').lower()
            if network in ('tcp', 'raw', ''):
                client['flow'] = 'xtls-rprx-vision'
        return client

    def _get_meta_json(self):
        """Read protocol metadata from meta.json and/or server.json (XHTTP+TLS or legacy Reality)."""
        config = self._get_server_json() or {}
        inbound = self._get_vless_inbound(config) or {}
        stream = inbound.get('streamSettings') or {}
        port = inbound.get('port')

        meta = {}
        out = self._read_remote_file(f"{self._config_dir()}/meta.json")
        if out:
            try:
                meta = json.loads(out)
            except Exception:
                meta = {}

        if port is not None:
            meta['port'] = port

        network = str(stream.get('network') or '').lower()
        security = str(stream.get('security') or '').lower()

        if network in ('xhttp', 'splithttp') and security == 'tls':
            xs = stream.get('xhttpSettings') or stream.get('splithttpSettings') or {}
            tls = stream.get('tlsSettings') or {}
            meta['transport'] = 'xhttp'
            meta['security'] = 'tls'
            meta['path'] = xs.get('path') or meta.get('path') or '/'
            meta['mode'] = xs.get('mode') or meta.get('mode') or 'auto'
            meta['domain'] = (
                meta.get('domain')
                or xs.get('host')
                or tls.get('serverName')
                or meta.get('site_name')
            )
            meta['site_name'] = meta.get('domain') or meta.get('site_name')
            meta['fingerprint'] = meta.get('fingerprint') or 'chrome'
            meta['alpn'] = meta.get('alpn') or 'h2,http/1.1'
            # Prefer TLS ALPN from live server config when present
            tls_alpn = tls.get('alpn')
            if isinstance(tls_alpn, list) and tls_alpn:
                meta['alpn'] = ','.join(str(x) for x in tls_alpn if x)
            return meta

        # Legacy Reality
        rs = stream.get('realitySettings') or {}
        names = rs.get('serverNames') or []
        site_name = names[0] if names else meta.get('site_name') or 'yahoo.com'
        meta['transport'] = 'tcp'
        meta['security'] = 'reality'
        meta['site_name'] = site_name

        if self._detect_layout() == 'native':
            priv = (self._read_remote_file(f"{self._config_dir()}/xray_private.key") or '').strip()
            pub = (self._read_remote_file(f"{self._config_dir()}/xray_public.key") or '').strip()
            sid = (self._read_remote_file(f"{self._config_dir()}/xray_short_id.key") or '').strip()
            if not priv:
                priv = rs.get('privateKey', '')
            if not sid:
                sids = rs.get('shortIds') or []
                sid = sids[0] if sids else ''
            if not pub:
                pub = self._derive_pubkey_from_priv(priv)
            meta.update({
                'private_key': priv,
                'public_key': pub,
                'short_id': sid,
                'port': port,
                'site_name': site_name,
            })
            return meta

        if not meta.get('private_key'):
            meta['private_key'] = rs.get('privateKey', '')
        if not meta.get('short_id'):
            sids = rs.get('shortIds') or []
            if sids:
                meta['short_id'] = sids[0]
        if not meta.get('public_key') and meta.get('private_key'):
            meta['public_key'] = self._derive_pubkey_from_priv(meta['private_key'])
        return meta

    def _get_clients_table(self):
        """Read clientsTable, trying both layout filenames."""
        layout = self._detect_layout()
        primary = 'clientsTable' if layout == 'native' else 'clientsTable.json'
        fallback = 'clientsTable.json' if layout == 'native' else 'clientsTable'
        for fname in (primary, fallback):
            out = self._read_remote_file(f"{self._config_dir()}/{fname}")
            if not out or not out.strip():
                continue
            try:
                return json.loads(out)
            except Exception:
                continue
        return []

    def _save_clients_table(self, data):
        """Write clientsTable to the file matching the current layout, in both
        the container and the host bind-mount.
        """
        path = self._clients_table_path()
        tmp_file = "/tmp/_xray_clients.json"
        self.ssh.upload_file_sudo(json.dumps(data, indent=2), tmp_file)
        self.ssh.run_sudo_command(
            f"docker cp {tmp_file} {self.container_name}:{path}"
        )
        self.ssh.run_sudo_command(
            f"cp {tmp_file} {path} 2>/dev/null || true"
        )

    def _upgrade_config_for_stats(self, config, restart=True):
        """Injects API and Stats blocks into older Xray configs transparently."""
        dirty = False
        if 'stats' not in config:
            config['stats'] = {}
            dirty = True
        if 'api' not in config:
            config['api'] = {"services": ["StatsService", "LoggerService", "HandlerService"], "tag": "api"}
            dirty = True
        else:
            services = config['api'].setdefault('services', [])
            if 'HandlerService' not in services:
                services.append('HandlerService')
                dirty = True
        if 'policy' not in config:
            config['policy'] = {
                "levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}},
                "system": {"statsInboundUplink": True, "statsInboundDownlink": True, "statsOutboundUplink": True, "statsOutboundDownlink": True}
            }
            dirty = True
        if 'routing' not in config:
            config['routing'] = {"rules": [{"inboundTag": ["api"], "outboundTag": "api", "type": "field"}]}
            dirty = True
            
        has_api_inbound = any(ib.get('tag') == 'api' for ib in config.get('inbounds', []))
        if not has_api_inbound:
            config.setdefault('inbounds', []).append({
                "listen": "127.0.0.1",
                "port": 10085,
                "protocol": "dokodemo-door",
                "settings": {"address": "127.0.0.1"},
                "tag": "api"
            })
            dirty = True
            
        for ib in config.get('inbounds', []):
            if ib.get('protocol') == 'vless':
                if not ib.get('tag'):
                    ib['tag'] = 'proxy'
                    dirty = True
                for c in ib.get('settings', {}).get('clients', []):
                    if 'email' not in c:
                        c['email'] = c['id']
                        dirty = True
            
        if dirty:
            self._write_server_json(config, restart=restart)
        return dirty

    def _query_xray_stats(self):
        """Query Xray API for traffic stats using xray api command."""
        out, _, code = self.ssh.run_sudo_command(
            f"docker exec -i {self.container_name} /usr/bin/xray api statsquery -server=127.0.0.1:10085"
        )
        if code != 0 or not out.strip():
            return {}
        
        try:
            stats_raw = json.loads(out)
        except Exception:
            return {}

        results = {}
        # Output format: {"stat": [{"name": "user>>>uid>>>traffic>>>downlink", "value": "123"}, ...]}
        for item in stats_raw.get('stat', []):
            name_parts = item.get('name', '').split('>>>')
            if len(name_parts) == 4 and name_parts[0] == 'user':
                uid = name_parts[1]
                t_type = name_parts[3] # uplink or downlink
                val = int(item.get('value', 0))
                
                if uid not in results:
                    results[uid] = {'rx': 0, 'tx': 0}
                
                if t_type == 'downlink':
                    results[uid]['rx'] = val
                elif t_type == 'uplink':
                    results[uid]['tx'] = val
                    
        return results

    def _format_bytes(self, size):
        # Format bytes to string like AWG (e.g., 1.50 MiB)
        power = 2**10
        n = 0
        powers = {0: 'B', 1: 'KiB', 2: 'MiB', 3: 'GiB', 4: 'TiB'}
        while size > power:
            size /= power
            n += 1
        v = round(size, 2)
        if v == int(v):
            v = int(v)
        return f"{v} {powers.get(n, 'B')}"

    def get_clients(self, protocol=None):
        config = self._get_server_json()
        if not config:
            return []

        self._upgrade_config_for_stats(config, restart=False)

        # Collect all client IDs currently registered in the Xray server config
        xray_clients = []
        for ib in config.get('inbounds', []):
            if ib.get('protocol') == 'vless':
                xray_clients.extend(ib.get('settings', {}).get('clients', []))

        clients_table = self._get_clients_table()
        table_ids = {c['clientId'] for c in clients_table}

        # Auto-import clients present in server.json but missing from clientsTable
        # (e.g. added via the native Amnezia phone/desktop app). Skip the install-time
        # default UUID for native-layout installs — the official client treats it as
        # the device of the user who installed the server, not a manageable client.
        default_uuid = self._get_default_xray_uuid()
        updated = False
        for xc in xray_clients:
            uid = xc.get('id')
            if not uid or uid in table_ids or uid == default_uuid:
                continue
            clients_table.append({
                'clientId': uid,
                'userData': {
                    'clientName': f'Imported_{uid[:8]}',
                    'creationDate': datetime.now().isoformat(),
                    'enabled': True
                }
            })
            table_ids.add(uid)
            updated = True
            logger.info(f"Auto-imported Xray client {uid[:8]} from server.json")

        if updated:
            self._save_clients_table(clients_table)

        stats = self._query_xray_stats()

        for c in clients_table:
            uid = c.get('clientId', '')
            if uid in stats:
                user_data = c.setdefault('userData', {})
                rx = stats[uid]['rx']
                tx = stats[uid]['tx']
                if rx > 0 or tx > 0:
                    user_data['dataReceived'] = self._format_bytes(rx)
                    user_data['dataSent'] = self._format_bytes(tx)
                    user_data['dataReceivedBytes'] = rx
                    user_data['dataSentBytes'] = tx

        return clients_table

    def get_client_config(self, protocol, client_id, server_host, port):
        clients = self._get_clients_table()
        client = next((c for c in clients if c['clientId'] == client_id), None)
        if not client:
            return None

        meta = self._get_meta_json() or {}
        config = self._get_server_json() or {}
        inbound = self._get_vless_inbound(config) or {}
        name = client.get('userData', {}).get('clientName', 'vpn')
        encoded_name = urllib.parse.quote(name)
        listen_port = meta.get('port', port)

        if self._is_xhttp_tls_inbound(inbound) or (meta.get('transport') == 'xhttp' and meta.get('security') == 'tls'):
            domain = (meta.get('domain') or meta.get('site_name') or server_host or '').strip()
            path = meta.get('path') or '/'
            if not str(path).startswith('/'):
                path = '/' + str(path)
            # TLS+XHTTP resolves auto → packet-up; pin it for older clients.
            mode = meta.get('mode') or 'auto'
            if str(mode).lower() in ('auto', ''):
                mode = 'packet-up'
            fp = meta.get('fingerprint') or 'chrome'
            alpn = meta.get('alpn') or 'h2,http/1.1'
            if isinstance(alpn, list):
                alpn = ','.join(str(x) for x in alpn if x)
            # Dial address: panel connect host (IP/domain). TLS identity: cert domain.
            dial_host = (server_host or domain).strip()
            path_q = urllib.parse.quote(str(path), safe='/')
            return (
                f"vless://{client_id}@{dial_host}:{listen_port}"
                f"?encryption=none&security=tls&type=xhttp"
                f"&path={path_q}"
                f"&mode={urllib.parse.quote(str(mode), safe='')}"
                f"&host={urllib.parse.quote(domain, safe='')}"
                f"&sni={urllib.parse.quote(domain, safe='')}"
                f"&fp={urllib.parse.quote(fp, safe='')}"
                f"&alpn={urllib.parse.quote(alpn, safe=',')}"
                f"#{encoded_name}"
            )

        # Legacy Reality share link
        sni = meta.get('site_name', 'yahoo.com')
        try:
            sni = inbound['streamSettings']['realitySettings']['serverNames'][0]
        except Exception:
            pass
        return (
            f"vless://{client_id}@{server_host}:{listen_port}"
            f"?type=tcp&security=reality&pbk={meta.get('public_key', '')}"
            f"&sni={sni}&fp=chrome&sid={meta.get('short_id', '')}"
            f"&spx=%2F&flow=xtls-rprx-vision#{encoded_name}"
        )

    def add_client(self, protocol, client_name, server_host, port):
        client_id = str(uuid.uuid4())

        config = self._get_server_json()
        if not config:
            raise RuntimeError("Xray server config not found.")

        self._upgrade_config_for_stats(config, restart=False)

        inbound = self._get_vless_inbound(config)
        if not inbound:
            raise RuntimeError("Xray VLESS inbound not found.")

        clients_node = inbound.setdefault('settings', {}).setdefault('clients', [])
        client = self._client_object(client_id, inbound)
        if not self._xray_api_add_user(config, client):
            raise RuntimeError(
                "Xray runtime API is not available for hot user updates. "
                "The server config was upgraded, but the container must be restarted once to enable HandlerService. "
                "Restart the Xray container manually and try again."
            )
        clients_node.append(client)
        self._write_server_json(config, restart=False)

        clients_table = self._get_clients_table()
        clients_table.append({
            'clientId': client_id,
            'userData': {
                'clientName': client_name,
                'creationDate': datetime.now().isoformat(),
                'enabled': True
            }
        })
        self._save_clients_table(clients_table)

        return {
            'client_id': client_id,
            'config': self.get_client_config(protocol, client_id, server_host, port)
        }

    def toggle_client(self, protocol, client_id, enable):
        config = self._get_server_json()
        self._upgrade_config_for_stats(config, restart=False)
        inbound = self._get_vless_inbound(config)
        if not inbound:
            raise RuntimeError("Xray VLESS inbound not found.")
        clients_node = inbound.setdefault('settings', {}).setdefault('clients', [])

        if enable:
            if not any(c['id'] == client_id for c in clients_node):
                client = self._client_object(client_id, inbound)
                if not self._xray_api_add_user(config, client):
                    raise RuntimeError("Xray runtime API failed to enable the client without restarting the container.")
                clients_node.append(client)
        else:
            if not self._xray_api_remove_user(config, client_id):
                raise RuntimeError("Xray runtime API failed to disable the client without restarting the container.")
            inbound['settings']['clients'] = [c for c in clients_node if c['id'] != client_id]

        self._write_server_json(config, restart=False)

        clients_table = self._get_clients_table()
        for c in clients_table:
            if c['clientId'] == client_id:
                c.setdefault('userData', {})['enabled'] = enable
        self._save_clients_table(clients_table)

    def remove_client(self, protocol, client_id):
        config = self._get_server_json()
        self._upgrade_config_for_stats(config, restart=False)
        inbound = self._get_vless_inbound(config)
        if not inbound:
            raise RuntimeError("Xray VLESS inbound not found.")
        clients_node = inbound.setdefault('settings', {}).setdefault('clients', [])
        if not self._xray_api_remove_user(config, client_id):
            raise RuntimeError("Xray runtime API failed to remove the client without restarting the container.")
        inbound['settings']['clients'] = [c for c in clients_node if c['id'] != client_id]
        self._write_server_json(config, restart=False)

        clients_table = self._get_clients_table()
        clients_table = [c for c in clients_table if c['clientId'] != client_id]
        self._save_clients_table(clients_table)
        return True
