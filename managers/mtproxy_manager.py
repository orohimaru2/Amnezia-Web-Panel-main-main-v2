import json
import logging
import uuid
import re
import os
import secrets
from datetime import datetime
from .ssh_manager import SSHManager

logger = logging.getLogger(__name__)

class MtproxyManager:
    CONTAINER_NAME = "mtproxy"
    API_URL = "http://127.0.0.1:9091"
    
    def __init__(self, ssh_manager: SSHManager, protocol='mtproxy'):
        self.ssh = ssh_manager
        self.protocol = protocol or 'mtproxy'
        self.instance = self._instance_index(self.protocol)
        self.container_name = self._container_name(self.protocol)
        self.remote_dir = self._remote_dir(self.protocol)

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

    def _remote_dir(self, protocol=None):
        idx = self._instance_index(protocol or self.protocol)
        return '/opt/amnezia/mtproxy' if idx <= 1 else f'/opt/amnezia/mtproxy-{idx}'

    def _config_path(self):
        return f'{self.remote_dir}/config.toml'

    def _api_host_ports(self):
        if self.instance <= 1:
            return 9090, 9091
        base = 9090 + (self.instance * 10)
        return base, base + 1

    def _api_request(self, method, path, data=None):
        cmd = f"docker exec {self.container_name} curl -s -X {method} {self.API_URL}{path}"
        if data:
            js_data = json.dumps(data).replace('"', '\\"')
            cmd += f" -H 'Content-Type: application/json' -d \"{js_data}\""
        
        out, err, code = self.ssh.run_sudo_command(cmd)
        if code != 0:
            return None
        
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            return None

    def check_docker_installed(self):
        out, _, _ = self.ssh.run_command("docker --version 2>/dev/null")
        return bool(out.strip())

    def check_protocol_installed(self):
        out, _, _ = self.ssh.run_command(f"docker ps -a --filter name=^{self.container_name}$ --format '{{{{.Names}}}}'")
        return out.strip() == self.container_name

    def get_server_status(self, protocol_type):
        exists = self.check_protocol_installed()
        out, _, _ = self.ssh.run_command(f"docker inspect -f '{{{{.State.Running}}}}' {self.container_name} 2>/dev/null")
        is_running = out.strip().lower() == 'true'
        
        status = {
            'container_exists': exists,
            'container_running': is_running,
        }
        
        if is_running:
            out, _, _ = self.ssh.run_command(f"docker port {self.container_name} 443 2>/dev/null")
            if out:
                port = out.split(':')[-1].strip()
                status['port'] = port
            else:
                status['port'] = None
                
            config = self._get_server_config()
            status['awg_params'] = self._parse_mtproxy_params(config)
            
            clients = self.get_clients(protocol_type)
            status['clients_count'] = len(clients)
            
        return status

    def _ensure_docker_compose(self):
        out, _, code = self.ssh.run_command("docker compose version 2>/dev/null")
        if code == 0 and out.strip():
            return

        script = r"""
if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y || true
    apt-get install -y ca-certificates curl gnupg || exit 1
    install -m 0755 -d /etc/apt/keyrings
    . /etc/os-release
    DOCKER_DISTRO="$ID"
    case "$ID" in
        linuxmint|pop|elementary|zorin) DOCKER_DISTRO="ubuntu" ;;
        kali|parrot) DOCKER_DISTRO="debian" ;;
    esac
    if [ ! -s /etc/apt/keyrings/docker.asc ]; then
        curl -fsSL "https://download.docker.com/linux/${DOCKER_DISTRO}/gpg" -o /etc/apt/keyrings/docker.asc || exit 1
        chmod a+r /etc/apt/keyrings/docker.asc
    fi
    CODENAME="${UBUNTU_CODENAME:-$VERSION_CODENAME}"
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${DOCKER_DISTRO} ${CODENAME} stable" > /etc/apt/sources.list.d/docker.list
    apt-get update -y || exit 1
    apt-get install -y docker-buildx-plugin docker-compose-plugin || exit 1
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y dnf-plugins-core || exit 1
    . /etc/os-release
    dnf config-manager --add-repo "https://download.docker.com/linux/${ID}/docker-ce.repo" || exit 1
    dnf makecache || true
    dnf install -y docker-buildx-plugin docker-compose-plugin || exit 1
else
    echo "Unsupported package manager" >&2
    exit 1
fi
docker compose version
"""
        out, err, code = self.ssh.run_sudo_script(script, timeout=300)
        if code != 0:
            raise RuntimeError(f"Failed to install docker compose plugin: {err or out}")

    def install_protocol(self, protocol_type='mtproxy', port='443', secret=None, ad_tag=None):
        results = []
        if not self.check_docker_installed():
            results.append("Installing Docker...")
            self.ssh.run_sudo_command("curl -fsSL https://get.docker.com | sh", timeout=300)

        if self.check_protocol_installed():
            self.ssh.run_sudo_command(f"docker rm -f {self.container_name}")

        results.append("Ensuring docker compose plugin...")
        self._ensure_docker_compose()
            
        results.append("Uploading MTProxy files...")
        local_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'protocol_mtproxy')
        remote_dir = self.remote_dir
        self.ssh.run_sudo_command(f"mkdir -p {remote_dir}")
        self.ssh.run_sudo_command(f"chmod 755 {remote_dir}")
        
        with open(os.path.join(local_dir, 'config.toml'), 'r', encoding='utf-8') as f:
            config_content = f.read()
        
        if "public_host =" in config_content or "# public_host =" in config_content:
            config_content = re.sub(r'#?\s*public_host\s*=\s*".*?"', f'public_host = "{self.ssh.host}"', config_content)
        else:
            config_content = config_content.replace('[general.links]', f'[general.links]\npublic_host = "{self.ssh.host}"')
            
        config_content = re.sub(r'public_port\s*=\s*\d+', f'public_port = {port}', config_content)
        config_content = re.sub(r'^hello\s*=\s*".*?"', '', config_content, flags=re.MULTILINE)
            
        self.ssh.upload_file_sudo(config_content, f"{remote_dir}/config.toml")
        
        with open(os.path.join(local_dir, 'docker-compose.yml'), 'r', encoding='utf-8') as f:
            compose_content = f.read()
            
        compose_content = re.sub(r'"443:443"', f'"{port}:443"', compose_content)
        compose_content = re.sub(r'container_name:\s*mtproxy', f'container_name: {self.container_name}', compose_content)
        if self.instance > 1:
            api_port_9090, api_port_9091 = self._api_host_ports()
            compose_content = re.sub(r'"127\.0\.0\.1:9090:9090"', f'"127.0.0.1:{api_port_9090}:9090"', compose_content)
            compose_content = re.sub(r'"127\.0\.0\.1:9091:9091"', f'"127.0.0.1:{api_port_9091}:9091"', compose_content)
        self.ssh.upload_file_sudo(compose_content, f"{remote_dir}/docker-compose.yml")
        
        with open(os.path.join(local_dir, 'Dockerfile'), 'r', encoding='utf-8') as f:
            dockerfile = f.read()
            self.ssh.upload_file_sudo(dockerfile, f"{remote_dir}/Dockerfile")
            
        results.append("Starting MTProxy container...")
        out, err, code = self.ssh.run_sudo_command(f"sh -c 'cd {remote_dir} && docker compose up -d --build'", timeout=600)
        if code != 0:
            self.ssh.run_sudo_command(f"sh -c 'cd {remote_dir} && docker-compose up -d --build'", timeout=600)
                
        return {
            "status": "success",
            "protocol": self.protocol,
            "host": "",
            "port": port,
            "log": results
        }

    def _get_server_config(self):
        out, _, code = self.ssh.run_sudo_command(f"cat {self._config_path()}")
        if code != 0: return ""
        return out

    def save_server_config(self, protocol_type, config_content):
        self.ssh.upload_file_sudo(config_content.replace('\r\n', '\n'), f"{self._config_path()}")
        self.ssh.run_sudo_command(f"docker kill -s HUP {self.container_name} || docker restart {self.container_name}")

    def _parse_mtproxy_params(self, config_text):
        params = {}
        m = re.search(r'tls_emulation\s*=\s*(true|false)', config_text, re.IGNORECASE)
        if m: params['tls_emulation'] = m.group(1).lower() == 'true'
        m = re.search(r'tls_domain\s*=\s*"([^"]+)"', config_text)
        if m: params['tls_domain'] = m.group(1)
        m = re.search(r'max_connections\s*=\s*(\d+)', config_text)
        if m: params['max_connections'] = int(m.group(1))
        return params

    def remove_container(self, protocol_type=None):
        self.ssh.run_sudo_command(f"docker rm -f {self.container_name}")
        self.ssh.run_sudo_command(f"rm -rf {self.remote_dir}")

    def get_clients(self, protocol_type):
        api_data = {}
        resp = self._api_request("GET", "/v1/users")
        if resp and resp.get('ok'):
            for u in resp.get('data', []):
                api_data[u.get('username')] = u

        config_text = self._get_server_config()
        users = self._parse_users_from_config(config_text)
        
        clients = []
        for username, secret in users.items():
            user_stats = api_data.get(username.lstrip('#').strip(), {})
            links = user_stats.get('links', {})
            tg_link = ""
            if links.get('tls'): tg_link = links['tls'][0]
            elif links.get('secure'): tg_link = links['secure'][0]
            elif links.get('classic'): tg_link = links['classic'][0]
            
            enabled = not username.startswith('#')
            clean_name = username.lstrip('#').strip()
            
            total_octets = user_stats.get('total_octets', 0)
            quota = user_stats.get('data_quota_bytes')
            
            clients.append({
                "clientId": clean_name,
                "clientName": clean_name,
                "enabled": enabled,
                "creationDate": "",
                "userData": { 
                    "clientName": clean_name,
                    "token": secret,
                    "tg_link": tg_link,
                    "total_octets": total_octets,
                    "current_connections": user_stats.get('current_connections', 0),
                    "active_ips": user_stats.get('active_unique_ips', 0),
                    "quota": quota,
                    "expiry": user_stats.get('expiration_rfc3339')
                }
            })

        return clients

    def _parse_users_from_config(self, config_text):
        users = {}
        lines = config_text.split('\n')
        in_section = False
        for line in lines:
            stripped = line.strip()
            if stripped == '[access.users]':
                in_section = True
                continue
            if in_section and stripped.startswith('['):
                break
            if in_section and stripped:
                commented = stripped.startswith('#')
                content = stripped.lstrip('#').strip()
                if '=' in content:
                    if content.lower().startswith('format:'): continue
                    name, secret = content.split('=', 1)
                    name = name.strip().strip('"').strip()
                    secret = secret.strip().strip('"').strip()
                    full_name = ("# " + name) if commented else name
                    users[full_name] = secret
        return users

    def add_client(self, protocol_type, name, host='', port='', **kwargs):
        username = re.sub(r'[^a-zA-Z0-9_.-]', '', name.replace(' ', '_'))
        if not username: username = "user_" + uuid.uuid4().hex[:8]
        
        config_text = self._get_server_config()
        current_users = self._parse_users_from_config(config_text)
        idx = 1
        base_username = username
        while any(u.lstrip('#').strip() == username for u in current_users):
            username = f"{base_username}_{idx}"
            idx += 1
            
        secret = kwargs.get('secret') or secrets.token_hex(16)
        
        config_text = self._insert_into_section(config_text, "access.users", f'{username} = "{secret}"')
        
        api_payload = {"username": username, "secret": secret}
        
        quota = kwargs.get('quota')
        if quota:
            try:
                api_payload["data_quota_bytes"] = int(quota)
            except (ValueError, TypeError):
                pass
        
        expiry = kwargs.get('expiry')
        if expiry:
            api_payload["expiration_rfc3339"] = expiry
            
        ad_tag = kwargs.get('ad_tag')
        if ad_tag:
            api_payload["ad_tag"] = ad_tag
        
        resp = self._api_request("POST", "/v1/users", api_payload)
        if not resp or not resp.get('ok'):
            logger.warning(f"API failed to add user {username}, but config was updated")
        
        self.ssh.upload_file_sudo(config_text, self._config_path())
        self.ssh.run_sudo_command(f"docker kill -s HUP {self.container_name}")
        
        return {
            "clientId": username,
            "clientName": username,
            "userData": {
                "clientName": username,
                "token": secret,
                "tg_link": "",
                "quota": quota,
                "expiry": expiry,
                "ad_tag": ad_tag
            }
        }

    def _insert_into_section(self, config_text, section_name, new_line):
        lines = config_text.split('\n')
        result = []
        inserted = False
        in_section = False
        
        for line in lines:
            stripped = line.strip()
            if stripped == f'[{section_name}]':
                in_section = True
                result.append(line)
            elif in_section and stripped.startswith('['):
                if not inserted:
                    result.append(new_line)
                    inserted = True
                in_section = False
                result.append(line)
            elif in_section and not stripped:
                result.append(line)
            elif in_section and stripped:
                result.append(line)
            else:
                result.append(line)
        
        if in_section and not inserted:
            result.append(new_line)
        
        return '\n'.join(result)

    def toggle_client(self, protocol_type, client_id, enable, restart=True):
        config_text = self._get_server_config()
        lines = config_text.split('\n')
        result = []
        in_section = False
        
        for line in lines:
            stripped = line.strip()
            if stripped == '[access.users]':
                in_section = True
                result.append(line)
                continue
            if in_section and stripped.startswith('['):
                in_section = False
                result.append(line)
                continue
            if in_section and '=' in stripped:
                content = stripped.lstrip('#').strip()
                name, secret = content.split('=', 1)
                name = name.strip().strip('"').strip()
                if name == client_id:
                    if enable:
                        result.append(f'{name} = {secret.strip()}')
                    else:
                        result.append(f'# {name} = {secret.strip()}')
                    continue
            result.append(line)
        
        new_config = '\n'.join(result)
        self.ssh.upload_file_sudo(new_config, self._config_path())
        
        if restart:
            self.ssh.run_sudo_command(f"docker restart {self.container_name}")

    def remove_client(self, protocol_type, client_id):
        config_text = self._get_server_config()
        lines = config_text.split('\n')
        result = []
        in_section = False
        skip_next_blank = False
        
        for line in lines:
            stripped = line.strip()
            if stripped == '[access.users]':
                in_section = True
                result.append(line)
                continue
            if in_section and stripped.startswith('['):
                in_section = False
                result.append(line)
                continue
            if in_section and '=' in stripped:
                content = stripped.lstrip('#').strip()
                if '=' in content:
                    name, _ = content.split('=', 1)
                    name = name.strip().strip('"').strip()
                    if name == client_id:
                        skip_next_blank = True
                        continue
            if skip_next_blank and not stripped:
                skip_next_blank = False
                continue
            result.append(line)
        
        new_config = '\n'.join(result)
        self.ssh.upload_file_sudo(new_config, self._config_path())
        self._api_request("DELETE", f"/v1/users/{client_id}")
        self.ssh.run_sudo_command(f"docker kill -s HUP {self.container_name} || docker restart {self.container_name}")

    def update_client(self, protocol_type, client_id, **kwargs):
        config_text = self._get_server_config()
        current_users = self._parse_users_from_config(config_text)
        
        found = False
        for username, secret in current_users.items():
            clean_name = username.lstrip('#').strip()
            if clean_name == client_id:
                found = True
                break
        
        if not found:
            return {"error": "Client not found"}
        
        api_payload = {}
        if 'quota' in kwargs:
            api_payload['data_quota_bytes'] = kwargs['quota']
        if 'expiry' in kwargs:
            api_payload['expiration_rfc3339'] = kwargs['expiry']
        if 'ad_tag' in kwargs:
            api_payload['ad_tag'] = kwargs['ad_tag']
        
        if api_payload:
            resp = self._api_request("PUT", f"/v1/users/{client_id}", api_payload)
            if not resp or not resp.get('ok'):
                logger.warning(f"API failed to update user {client_id}")
        
        return {"status": "success"}

    def get_traffic_stats(self, protocol_type, client_id=None):
        resp = self._api_request("GET", "/v1/users")
        if not resp or not resp.get('ok'):
            return {}
        
        stats = {}
        for user in resp.get('data', []):
            username = user.get('username')
            stats[username] = {
                'total_octets': user.get('total_octets', 0),
                'current_connections': user.get('current_connections', 0),
                'active_unique_ips': user.get('active_unique_ips', 0)
            }
        
        if client_id:
            return stats.get(client_id, {})
        return stats
