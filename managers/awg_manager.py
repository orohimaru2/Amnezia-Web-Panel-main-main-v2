"""
AWG Protocol Manager - handles AmneziaWG and AmneziaWG-Legacy protocol
installation, configuration, and client management on remote servers.

Replicates the logic from:
- client/server_scripts/awg/ and awg_legacy/
- client/configurators/wireguard_configurator.cpp
- client/ui/models/clientManagementModel.cpp
"""

import json
import os
import secrets
import struct
import hashlib
import logging
import re
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)

_SNAPSHOT_MARKERS = ('__AMNZ_TABLE__', '__AMNZ_SHOW__', '__AMNZ_CONF__')
_SNAPSHOT_SPLIT_RE = re.compile(r'(__AMNZ_TABLE__|__AMNZ_SHOW__|__AMNZ_CONF__)')


def _split_clients_snapshot(raw: str) -> dict:
    """Split one-shot docker output even if markers are glued to the previous line.

    clientsTable is often written without a trailing newline, so
    `cat file; echo __AMNZ_SHOW__` becomes `...]__AMNZ_SHOW__` and a
    line-based splitter leaves the table unparseable.
    """
    parts = {'table': '', 'show': '', 'conf': ''}
    current = None
    for token in _SNAPSHOT_SPLIT_RE.split(raw or ''):
        if token in _SNAPSHOT_MARKERS:
            current = {'__AMNZ_TABLE__': 'table', '__AMNZ_SHOW__': 'show', '__AMNZ_CONF__': 'conf'}[token]
            continue
        if current:
            parts[current] += token
    return parts

# Default AWG parameters (from protocols_defs.h)
AWG_DEFAULTS = {
    'port': '55424',
    'mtu': '1280',
    'subnet_address': '10.8.1.0',
    'subnet_cidr': '24',
    'subnet_ip': '10.8.1.1',
    'dns1': '1.1.1.1',
    'dns2': '1.0.0.1',
    # AWG obfuscation parameters
    'junk_packet_count': '3',
    'junk_packet_min_size': '10',
    'junk_packet_max_size': '30',
    'init_packet_junk_size': '15',
    'response_packet_junk_size': '18',
    'cookie_reply_packet_junk_size': '20',
    'transport_packet_junk_size': '23',
    'init_packet_magic_header': '1020325451',
    'response_packet_magic_header': '3288052141',
    'transport_packet_magic_header': '2528465083',
    'underload_packet_magic_header': '1766607858',
}


def generate_wg_keypair():
    """Generate a WireGuard X25519 keypair (private, public) as base64 strings."""
    private_key = X25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return b64encode(private_bytes).decode(), b64encode(public_bytes).decode()


def generate_psk():
    """Generate a WireGuard preshared key."""
    return b64encode(secrets.token_bytes(32)).decode()


def generate_awg_params(use_ranges=False, version='2.0'):
    """Generate random AWG obfuscation parameters.

    For AWG 2.0+ (use_ranges=True): generates H1-H4 as non-overlapping
    ranges (min-max) for dynamic packet signature.
    For legacy AWG (use_ranges=False): generates fixed single H values.

    version='3.1' adds HeaderProtectionKey + ContentPaddingAddition and
    enforces S1-S4 floors required by header protection.
    """
    import random

    is_v31 = str(version).startswith('3')

    if is_v31:
        # AWG 3.1: header protection needs S1-S4 >= 12; junk train a bit noisier.
        jc = random.randint(4, 10)
        jmin = random.randint(50, 100)
        jmax = random.randint(jmin + 20, min(jmin + 180, 400))
        s1 = random.randint(12, 64)
        s2 = random.randint(12, 64)
        s3 = random.randint(12, 64)
        s4 = random.randint(12, 32)
    else:
        jc = random.randint(1, 10)
        jmin = random.randint(5, 20)
        jmax = random.randint(jmin + 10, jmin + 50)
        s1 = random.randint(10, 50)
        s2 = random.randint(10, 50)
        s3 = random.randint(10, 50)
        s4 = random.randint(10, 50)

    if use_ranges:
        # AWG 2.0+: H1-H4 as non-overlapping ranges (min-max)
        def make_ranges(total_min=1000000000, total_max=4294967295):
            zone_size = (total_max - total_min) // 4
            result = []
            for i in range(4):
                z_start = total_min + i * zone_size
                z_end = z_start + zone_size - 1
                padding = min(100000, zone_size // 4)
                a = random.randint(z_start + padding, z_end - padding)
                b = random.randint(a + 1, z_end)
                result.append(f"{a}-{b}")
            return result

        h1, h2, h3, h4 = make_ranges()
    else:
        h1 = str(random.randint(100000000, 4294967295))
        h2 = str(random.randint(100000000, 4294967295))
        h3 = str(random.randint(100000000, 4294967295))
        h4 = str(random.randint(100000000, 4294967295))

    params = {
        'junk_packet_count': str(jc),
        'junk_packet_min_size': str(jmin),
        'junk_packet_max_size': str(jmax),
        'init_packet_junk_size': str(s1),
        'response_packet_junk_size': str(s2),
        'cookie_reply_packet_junk_size': str(s3),
        'transport_packet_junk_size': str(s4),
        'init_packet_magic_header': h1,
        'response_packet_magic_header': h2,
        'underload_packet_magic_header': h3,
        'transport_packet_magic_header': h4,
        'awg_version': '3.1' if is_v31 else ('2.0' if use_ranges else '1.0'),
    }

    if is_v31:
        # Same encoding as WireGuard private key — matches `awg genkey`
        hp_key, _ = generate_wg_keypair()
        cpad_lo = random.randint(8, 24)
        cpad_hi = random.randint(cpad_lo + 8, 64)
        params['header_protection_key'] = hp_key
        params['content_padding_addition'] = f'{cpad_lo}-{cpad_hi}'

    return params


class AWGManager:
    """Manages AmneziaWG protocol installation and client management."""

    # Protocol types
    AWG = 'awg'          # New AWG (awg-go based, uses awg/awg-quick)
    AWG_LEGACY = 'awg_legacy'  # Legacy AWG (uses wg/wg-quick)
    AWG2 = 'awg2'        # AmneziaWG 2.0 (separate container amnezia-awg2)
    AWG3 = 'awg3'        # AmneziaWG 3.1 (header protection + content padding)

    AWG_GO_BASES = frozenset({AWG, AWG2, AWG3})
    AWG3_DOCKER_IMAGE = 'amneziavpn/amneziawg-go:3.1.20260814'
    AWG_GO_DOCKER_IMAGE = 'amneziavpn/amneziawg-go:latest'
    AWG_LEGACY_DOCKER_IMAGE = 'amneziavpn/amnezia-wg:latest'

    def __init__(self, ssh_manager):
        self.ssh = ssh_manager

    def _base_protocol(self, protocol_type):
        """Return base protocol for instance keys like awg__2."""
        return str(protocol_type or self.AWG).split('__', 1)[0]

    def _is_awg_go(self, protocol_type):
        return self._base_protocol(protocol_type) in self.AWG_GO_BASES

    def _is_awg3(self, protocol_type):
        return self._base_protocol(protocol_type) == self.AWG3

    def _instance_index(self, protocol_type):
        parts = str(protocol_type or '').split('__', 1)
        if len(parts) == 2:
            try:
                return max(1, int(parts[1]))
            except ValueError:
                return 1
        return 1

    def _container_name(self, protocol_type):
        """Get Docker container name for protocol type/instance.
        First instances keep legacy names; additional instances get -N suffix.
        """
        base = self._base_protocol(protocol_type)
        idx = self._instance_index(protocol_type)
        if base == self.AWG_LEGACY:
            name = 'amnezia-awg-legacy'
        elif base == self.AWG3:
            name = 'amnezia-awg3'
        elif base == self.AWG2:
            name = 'amnezia-awg2'
        else:
            name = 'amnezia-awg'
        return name if idx <= 1 else f'{name}-{idx}'

    def _config_path(self, protocol_type):
        """Get server config path inside container."""
        if self._base_protocol(protocol_type) == self.AWG_LEGACY:
            return '/opt/amnezia/awg/wg0.conf'
        # AWG / AWG2 / AWG3 use awg0.conf
        return '/opt/amnezia/awg/awg0.conf'

    def _config_path_candidates(self, protocol_type):
        """Return possible config paths, ordered by the expected path first."""
        expected = self._config_path(protocol_type)
        fallback = '/opt/amnezia/awg/awg0.conf' if self._base_protocol(protocol_type) == self.AWG_LEGACY else '/opt/amnezia/awg/wg0.conf'
        return [expected, fallback]

    def _resolve_config_path(self, protocol_type):
        """Resolve the real config path in existing containers.

        AWG Legacy should use wg0.conf, but some older or manually modified
        installations may have a different file name. Resolve the existing file
        instead of requiring users to create symlinks inside the container.
        """
        container_name = self._container_name(protocol_type)
        candidates = self._config_path_candidates(protocol_type)
        paths = ' '.join(candidates)
        script = f'for p in {paths}; do if [ -f "$p" ]; then echo "$p"; exit 0; fi; done; exit 1'
        out, _, code = self.ssh.run_sudo_command(
            f"docker exec -i {container_name} sh -c '{script}'"
        )
        if code == 0 and out.strip():
            return out.strip().splitlines()[0]
        return self._config_path(protocol_type)

    def _wg_binary(self, protocol_type):
        """Get the wireguard binary name."""
        if self._base_protocol(protocol_type) == self.AWG_LEGACY:
            return 'wg'
        # AWG / AWG2 / AWG3 use 'awg' binary
        return 'awg'


    def _quick_binary(self, protocol_type):
        """Get the wireguard-quick binary name."""
        if self._base_protocol(protocol_type) == self.AWG_LEGACY:
            return 'wg-quick'
        # AWG / AWG2 / AWG3 use 'awg-quick'
        return 'awg-quick'


    def _interface_name(self, protocol_type, config_path=None):
        """Get the interface name."""
        if config_path:
            return os.path.splitext(os.path.basename(config_path))[0]
        if self._base_protocol(protocol_type) == self.AWG_LEGACY:
            return 'wg0'
        # AWG / AWG2 / AWG3 use 'awg0' interface
        return 'awg0'

    def _docker_image(self, protocol_type):
        """Get Docker image for protocol type."""
        base = self._base_protocol(protocol_type)
        if base == self.AWG3:
            return self.AWG3_DOCKER_IMAGE
        if base in self.AWG_GO_BASES:
            return self.AWG_GO_DOCKER_IMAGE
        return self.AWG_LEGACY_DOCKER_IMAGE

    def _clients_table_path(self):
        """Path to the clients table file inside container."""
        return '/opt/amnezia/awg/clientsTable'

    def _get_subnet_ip(self, protocol_type):
        """Get the subnet IP (gateway) from server config, or fallback to default."""
        try:
            config = self._get_server_config(protocol_type)
            for line in config.split('\n'):
                if line.startswith('Address'):
                    addr = line.split('=')[1].strip()
                    ip = addr.split('/')[0]
                    return ip
        except Exception:
            pass
        return AWG_DEFAULTS['subnet_ip']

    def _get_subnet_cidr(self, protocol_type):
        """Get the subnet CIDR from server config, or fallback to default."""
        try:
            config = self._get_server_config(protocol_type)
            for line in config.split('\n'):
                if line.startswith('Address'):
                    addr = line.split('=')[1].strip()
                    if '/' in addr:
                        return addr.split('/')[1]
        except Exception:
            pass
        return AWG_DEFAULTS['subnet_cidr']

    def _get_subnet_base(self, protocol_type):
        """Get the subnet network address (e.g. 172.16.21.0) from server config."""
        subnet_ip = self._get_subnet_ip(protocol_type)
        cidr = int(self._get_subnet_cidr(protocol_type))
        parts = list(map(int, subnet_ip.split('.')))
        mask = (0xFFFFFFFF << (32 - cidr)) & 0xFFFFFFFF
        network = struct.pack('!I', (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3])
        net_int = struct.unpack('!I', network)[0] & mask
        net_parts = [(net_int >> 24) & 0xFF, (net_int >> 16) & 0xFF, (net_int >> 8) & 0xFF, net_int & 0xFF]
        return '.'.join(map(str, net_parts))

    # ===================== INSTALLATION =====================

    def check_docker_installed(self):
        """Check if Docker is installed and running."""
        out, err, code = self.ssh.run_command("docker --version 2>/dev/null")
        if code != 0:
            return False
        out2, _, code2 = self.ssh.run_command("systemctl is-active docker 2>/dev/null || service docker status 2>/dev/null")
        return 'active' in out2 or 'running' in out2.lower()

    def install_docker(self):
        """Install Docker on the server (mirrors install_docker.sh)."""
        script = r"""
if which apt-get > /dev/null 2>&1; then pm=$(which apt-get); silent_inst="-yq install"; check_pkgs="-yq update"; docker_pkg="docker.io"; dist="debian";
elif which dnf > /dev/null 2>&1; then pm=$(which dnf); silent_inst="-yq install"; check_pkgs="-yq check-update"; docker_pkg="docker"; dist="fedora";
elif which yum > /dev/null 2>&1; then pm=$(which yum); silent_inst="-y -q install"; check_pkgs="-y -q check-update"; docker_pkg="docker"; dist="centos";
elif which zypper > /dev/null 2>&1; then pm=$(which zypper); silent_inst="-nq install"; check_pkgs="-nq refresh"; docker_pkg="docker"; dist="opensuse";
elif which pacman > /dev/null 2>&1; then pm=$(which pacman); silent_inst="-S --noconfirm --noprogressbar --quiet"; check_pkgs="-Sup"; docker_pkg="docker"; dist="archlinux";
else echo "Packet manager not found"; exit 1; fi;
echo "Dist: $dist, Packet manager: $pm";
if [ "$dist" = "debian" ]; then export DEBIAN_FRONTEND=noninteractive; fi;
if ! command -v docker > /dev/null 2>&1; then
  $pm $check_pkgs; $pm $silent_inst $docker_pkg;
  sleep 5; systemctl enable --now docker; sleep 5;
fi;
if [ "$(systemctl is-active docker)" != "active" ]; then
  $pm $check_pkgs; $pm $silent_inst $docker_pkg;
  sleep 5; systemctl start docker; sleep 5;
fi;
docker --version
"""
        out, err, code = self.ssh.run_sudo_script(script, timeout=180)
        if code != 0:
            raise RuntimeError(f"Failed to install Docker: {err}")
        return out

    def check_container_running(self, protocol_type):
        """Check if AWG container is running."""
        container_name = self._container_name(protocol_type)
        # Use ^name$ for exact match (Docker name filter does substring match)
        out, _, code = self.ssh.run_sudo_command(
            f"docker ps --filter name=^{container_name}$ --format '{{{{.Status}}}}'"
        )
        return 'Up' in out

    def check_protocol_installed(self, protocol_type):
        """Check if protocol is installed (container exists)."""
        container_name = self._container_name(protocol_type)
        out, _, code = self.ssh.run_sudo_command(
            f"docker ps -a --filter name=^{container_name}$ --format '{{{{.Names}}}}'"
        )
        # Exact match check
        return container_name in out.strip().split('\n')

    def prepare_host(self, protocol_type):
        """Prepare host for container (mirrors prepare_host.sh)."""
        container_name = self._container_name(protocol_type)
        dockerfile_folder = f"/opt/amnezia/{container_name}"
        script = f"""
mkdir -p {dockerfile_folder}
if ! docker network ls | grep -q amnezia-dns-net; then
  docker network create --driver bridge --subnet=172.29.172.0/24 --opt com.docker.network.bridge.name=amn0 amnezia-dns-net
fi
"""
        out, err, code = self.ssh.run_sudo_script(script)
        if code != 0:
            logger.warning(f"prepare_host warning: {err}")
        return True

    def setup_firewall(self):
        """Setup host firewall (mirrors setup_host_firewall.sh)."""
        script = """
sysctl -w net.ipv4.ip_forward=1
iptables -C INPUT -p icmp --icmp-type echo-request -j DROP 2>/dev/null || iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
iptables -C FORWARD -j DOCKER-USER 2>/dev/null || iptables -A FORWARD -j DOCKER-USER 2>/dev/null
"""
        self.ssh.run_sudo_script(script)
        return True

    def install_protocol(self, protocol_type, port=None, awg_params=None):
        """
        Full installation of AWG or AWG-Legacy protocol.
        Steps: install docker -> prepare host -> build container ->
               configure container -> run container -> setup firewall
        """
        if port is None:
            port = AWG_DEFAULTS['port']

        if awg_params is None:
            base = self._base_protocol(protocol_type)
            awg_params = generate_awg_params(
                use_ranges=(base in self.AWG_GO_BASES),
                version='3.1' if base == self.AWG3 else '2.0',
            )

        container_name = self._container_name(protocol_type)
        docker_image = self._docker_image(protocol_type)
        config_path = self._config_path(protocol_type)
        wg_bin = self._wg_binary(protocol_type)
        quick_bin = self._quick_binary(protocol_type)
        iface = self._interface_name(protocol_type)

        results = []

        # Step 1: Install Docker
        if not self.check_docker_installed():
            results.append("Installing Docker...")
            self.install_docker()
            results.append("Docker installed successfully")
        else:
            results.append("Docker already installed")

        # Step 2: Prepare host
        results.append("Preparing host...")
        self.prepare_host(protocol_type)
        results.append("Host prepared")

        # Step 3: Remove old container if exists
        if self.check_protocol_installed(protocol_type):
            results.append("Removing old container...")
            self.remove_container(protocol_type)
            results.append("Old container removed")

        # Step 4: Build/Pull container
        results.append("Pulling Docker image...")
        dockerfile_folder = f"/opt/amnezia/{container_name}"

        # Create Dockerfile - matches original from client/server_scripts/awg/
        dockerfile_content = (
            f"FROM {docker_image}\n"
            f"\n"
            f'LABEL maintainer="AmneziaVPN"\n'
            f"\n"
            f"RUN apk add --no-cache bash curl dumb-init iptables\n"
            f"RUN apk --update upgrade --no-cache\n"
            f"\n"
            f"RUN mkdir -p /opt/amnezia\n"
            f'RUN echo "#!/bin/bash" > /opt/amnezia/start.sh && '
            f'echo "tail -f /dev/null" >> /opt/amnezia/start.sh\n'
            f"RUN chmod a+x /opt/amnezia/start.sh\n"
            f"\n"
            f'ENTRYPOINT [ "dumb-init", "/opt/amnezia/start.sh" ]\n'
        )
        self.ssh.run_sudo_command(f"mkdir -p {dockerfile_folder}")
        self.ssh.upload_file_sudo(dockerfile_content, f"{dockerfile_folder}/Dockerfile")

        out, err, code = self.ssh.run_sudo_command(
            f"docker build --no-cache --pull -t {container_name} {dockerfile_folder}",
            timeout=300
        )
        if code != 0:
            raise RuntimeError(f"Failed to build container: {err}")
        results.append("Docker image built successfully")

        # Step 5: Run container
        results.append("Starting container...")
        run_cmd = f"""docker run -d \
--restart always \
--privileged \
--cap-add=NET_ADMIN \
--cap-add=SYS_MODULE \
-p {port}:{port}/udp \
-v /lib/modules:/lib/modules \
--sysctl="net.ipv4.conf.all.src_valid_mark=1" \
--name {container_name} \
{container_name}"""

        out, err, code = self.ssh.run_sudo_command(run_cmd)
        if code != 0:
            raise RuntimeError(f"Failed to run container: {err}")

        # Connect to DNS network
        self.ssh.run_sudo_command(f"docker network connect amnezia-dns-net {container_name}")

        # Wait for container to be fully running
        results.append("Waiting for container to start...")
        self._wait_container_running(container_name)
        results.append("Container started")

        # Step 6: Configure container (generate server keys and config)
        results.append("Configuring AWG...")
        self._configure_container(protocol_type, port, awg_params)
        results.append("AWG configured")

        # Step 7: Upload and run start script
        results.append("Starting AWG service...")
        self._upload_start_script(protocol_type, port, awg_params)
        results.append("AWG service started")

        # Step 8: Setup firewall
        results.append("Setting up firewall...")
        self.setup_firewall()
        results.append("Firewall configured")

        return {
            'status': 'success',
            'protocol': protocol_type,
            'port': port,
            'awg_params': awg_params,
            'log': results,
        }

    def _wait_container_running(self, container_name, timeout=30):
        """Wait for a container to be in 'running' state."""
        import time
        last_status = 'unknown'
        for i in range(timeout // 2):
            out, _, _ = self.ssh.run_sudo_command(
                f"docker inspect --format='{{{{.State.Status}}}}' {container_name}"
            )
            last_status = out.strip().strip("'\"")
            if last_status == 'running':
                logger.info(f"Container {container_name} is running")
                time.sleep(1)
                return True
            logger.info(f"Container {container_name} status: {last_status}, waiting...")
            time.sleep(2)

        # Container failed to start — fetch logs for diagnostics
        logs_out, _, _ = self.ssh.run_sudo_command(
            f"docker logs --tail 50 {container_name} 2>&1"
        )
        raise RuntimeError(
            f"Container {container_name} did not start within {timeout}s "
            f"(status: {last_status}). Logs:\n{logs_out}"
        )

    def _configure_container(self, protocol_type, port, awg_params):
        """Configure the AWG container (generate keys and server config)."""
        container_name = self._container_name(protocol_type)
        wg_bin = self._wg_binary(protocol_type)
        config_path = self._config_path(protocol_type)

        subnet_ip = self._get_subnet_ip(protocol_type)
        subnet_cidr = self._get_subnet_cidr(protocol_type)

        # Build the server config generation script
        if self._is_awg_go(protocol_type):
            v31_lines = ''
            if self._is_awg3(protocol_type):
                hp = awg_params.get('header_protection_key') or ''
                cpad = awg_params.get('content_padding_addition') or ''
                v31_lines = f"""
HeaderProtectionKey = {hp}
ContentPaddingAddition = {cpad}
"""
            config_script = f"""
mkdir -p /opt/amnezia/awg
cd /opt/amnezia/awg
WIREGUARD_SERVER_PRIVATE_KEY=$({wg_bin} genkey)
echo $WIREGUARD_SERVER_PRIVATE_KEY > /opt/amnezia/awg/wireguard_server_private_key.key

WIREGUARD_SERVER_PUBLIC_KEY=$(echo $WIREGUARD_SERVER_PRIVATE_KEY | {wg_bin} pubkey)
echo $WIREGUARD_SERVER_PUBLIC_KEY > /opt/amnezia/awg/wireguard_server_public_key.key

WIREGUARD_PSK=$({wg_bin} genpsk)
echo $WIREGUARD_PSK > /opt/amnezia/awg/wireguard_psk.key

cat > {config_path} <<EOF
[Interface]
PrivateKey = $WIREGUARD_SERVER_PRIVATE_KEY
Address = {subnet_ip}/{subnet_cidr}
ListenPort = {port}
Jc = {awg_params['junk_packet_count']}
Jmin = {awg_params['junk_packet_min_size']}
Jmax = {awg_params['junk_packet_max_size']}
S1 = {awg_params['init_packet_junk_size']}
S2 = {awg_params['response_packet_junk_size']}
S3 = {awg_params['cookie_reply_packet_junk_size']}
S4 = {awg_params['transport_packet_junk_size']}
H1 = {awg_params['init_packet_magic_header']}
H2 = {awg_params['response_packet_magic_header']}
H3 = {awg_params['underload_packet_magic_header']}
H4 = {awg_params['transport_packet_magic_header']}
{v31_lines.rstrip()}
EOF
"""
        else:
            # AWG Legacy uses wg commands
            config_script = f"""
mkdir -p /opt/amnezia/awg
cd /opt/amnezia/awg
WIREGUARD_SERVER_PRIVATE_KEY=$({wg_bin} genkey)
echo $WIREGUARD_SERVER_PRIVATE_KEY > /opt/amnezia/awg/wireguard_server_private_key.key

WIREGUARD_SERVER_PUBLIC_KEY=$(echo $WIREGUARD_SERVER_PRIVATE_KEY | {wg_bin} pubkey)
echo $WIREGUARD_SERVER_PUBLIC_KEY > /opt/amnezia/awg/wireguard_server_public_key.key

WIREGUARD_PSK=$({wg_bin} genpsk)
echo $WIREGUARD_PSK > /opt/amnezia/awg/wireguard_psk.key

cat > {config_path} <<EOF
[Interface]
PrivateKey = $WIREGUARD_SERVER_PRIVATE_KEY
Address = {subnet_ip}/{subnet_cidr}
ListenPort = {port}
Jc = {awg_params['junk_packet_count']}
Jmin = {awg_params['junk_packet_min_size']}
Jmax = {awg_params['junk_packet_max_size']}
S1 = {awg_params['init_packet_junk_size']}
S2 = {awg_params['response_packet_junk_size']}
H1 = {awg_params['init_packet_magic_header']}
H2 = {awg_params['response_packet_magic_header']}
H3 = {awg_params['underload_packet_magic_header']}
H4 = {awg_params['transport_packet_magic_header']}
EOF
"""

        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {container_name} bash -c '{config_script}'"
        )
        if code != 0:
            raise RuntimeError(f"Failed to configure container: {err}")

    def _upload_start_script(self, protocol_type, port, awg_params):
        """Upload and execute the start script inside the container."""
        container_name = self._container_name(protocol_type)
        quick_bin = self._quick_binary(protocol_type)
        config_path = self._config_path(protocol_type)

        start_script = f"""#!/bin/bash
echo "Container startup"

# Read subnet from server config dynamically
SUBNET=$(grep '^Address' {config_path} | head -1 | cut -d'=' -f2 | tr -d ' ')
if [ -z "$SUBNET" ]; then
  SUBNET={AWG_DEFAULTS['subnet_ip']}/{AWG_DEFAULTS['subnet_cidr']}
fi

# kill daemons in case of restart
{quick_bin} down {config_path} 2>/dev/null

# start daemons if configured
if [ -f {config_path} ]; then {quick_bin} up {config_path}; fi

# Allow traffic on the TUN interface
IFACE=$(basename {config_path} .conf)
iptables -A INPUT -i $IFACE -j ACCEPT
iptables -A FORWARD -i $IFACE -j ACCEPT
iptables -A OUTPUT -o $IFACE -j ACCEPT

# Allow forwarding traffic only from the VPN
iptables -A FORWARD -i $IFACE -o eth0 -s $SUBNET -j ACCEPT
iptables -A FORWARD -i $IFACE -o eth1 -s $SUBNET -j ACCEPT

iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

iptables -t nat -A POSTROUTING -s $SUBNET -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s $SUBNET -o eth1 -j MASQUERADE

tail -f /dev/null
"""

        # Upload start script to container via SFTP + docker cp
        self.ssh.upload_file(start_script, "/tmp/_amnz_start.sh")
        self.ssh.run_sudo_command(f"docker cp /tmp/_amnz_start.sh {container_name}:/opt/amnezia/start.sh")
        self.ssh.run_sudo_command(f"docker exec {container_name} chmod +x /opt/amnezia/start.sh")
        self.ssh.run_command("rm -f /tmp/_amnz_start.sh")

        # Restart to apply the start script
        self.ssh.run_sudo_command(f"docker restart {container_name}")
        import time
        time.sleep(5)

    def remove_container(self, protocol_type):
        """Remove AWG container (mirrors remove_container.sh)."""
        container_name = self._container_name(protocol_type)
        self.ssh.run_sudo_command(f"docker stop {container_name}")
        self.ssh.run_sudo_command(f"docker rm -fv {container_name}")
        self.ssh.run_sudo_command(f"docker rmi {container_name}")
        return True

    # ===================== CLIENT MANAGEMENT =====================

    def _get_clients_table(self, protocol_type):
        """Get the clients table from the server."""
        container_name = self._container_name(protocol_type)
        clients_table_path = self._clients_table_path()

        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {container_name} cat {clients_table_path} 2>/dev/null"
        )
        if code != 0 or not out.strip():
            return []

        try:
            data = json.loads(out)
            if isinstance(data, list):
                return data
            elif isinstance(data, dict):
                # Migration from old format
                result = []
                for client_id, info in data.items():
                    result.append({
                        'clientId': client_id,
                        'userData': {
                            'clientName': info.get('clientName', 'Unknown'),
                        }
                    })
                return result
        except json.JSONDecodeError:
            return []

    def _save_clients_table(self, protocol_type, clients_table):
        """Save the clients table to the server."""
        container_name = self._container_name(protocol_type)
        clients_table_path = self._clients_table_path()
        content = json.dumps(clients_table, indent=2)

        # Write to /tmp via SFTP, then docker cp into container
        self.ssh.upload_file(content, "/tmp/_amnz_clients.json")
        self.ssh.run_sudo_command(
            f"docker cp /tmp/_amnz_clients.json {container_name}:{clients_table_path}"
        )
        self.ssh.run_command("rm -f /tmp/_amnz_clients.json")

    def _get_server_config(self, protocol_type):
        """Get the server WireGuard config."""
        container_name = self._container_name(protocol_type)
        config_path = self._resolve_config_path(protocol_type)

        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {container_name} cat {config_path}"
        )
        if code != 0:
            raise RuntimeError(f"Failed to get server config: {err}")
        return out

    def save_server_config(self, protocol_type, config_content):
        """Save the server WireGuard config and restart container."""
        container_name = self._container_name(protocol_type)
        config_path = self._resolve_config_path(protocol_type)

        # Upload new config into container via SFTP + docker cp
        self.ssh.upload_file(config_content.replace('\r\n', '\n'), "/tmp/_amnz_edit_config.conf")
        self.ssh.run_sudo_command(f"docker cp /tmp/_amnz_edit_config.conf {container_name}:{config_path}")
        self.ssh.run_command("rm -f /tmp/_amnz_edit_config.conf")

        # Regenerate start script so iptables rules pick up the (possibly changed) subnet
        quick_bin = self._quick_binary(protocol_type)
        start_script = f"""#!/bin/bash
echo "Container startup"

# Read subnet from server config dynamically
SUBNET=$(grep '^Address' {config_path} | head -1 | cut -d'=' -f2 | tr -d ' ')
if [ -z "$SUBNET" ]; then
  SUBNET={AWG_DEFAULTS['subnet_ip']}/{AWG_DEFAULTS['subnet_cidr']}
fi

# kill daemons in case of restart
{quick_bin} down {config_path} 2>/dev/null

# start daemons if configured
if [ -f {config_path} ]; then {quick_bin} up {config_path}; fi

# Allow traffic on the TUN interface
IFACE=$(basename {config_path} .conf)
iptables -A INPUT -i $IFACE -j ACCEPT
iptables -A FORWARD -i $IFACE -j ACCEPT
iptables -A OUTPUT -o $IFACE -j ACCEPT

# Allow forwarding traffic only from the VPN
iptables -A FORWARD -i $IFACE -o eth0 -s $SUBNET -j ACCEPT
iptables -A FORWARD -i $IFACE -o eth1 -s $SUBNET -j ACCEPT

iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

iptables -t nat -A POSTROUTING -s $SUBNET -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s $SUBNET -o eth1 -j MASQUERADE

tail -f /dev/null
"""
        self.ssh.upload_file(start_script, "/tmp/_amnz_start.sh")
        self.ssh.run_sudo_command(f"docker cp /tmp/_amnz_start.sh {container_name}:/opt/amnezia/start.sh")
        self.ssh.run_sudo_command(f"docker exec {container_name} chmod +x /opt/amnezia/start.sh")
        self.ssh.run_command("rm -f /tmp/_amnz_start.sh")

        # Restart container to apply all changes (including port and interface changes)
        self.ssh.run_sudo_command(f"docker restart {container_name}")

    def _get_server_public_key(self, protocol_type):
        """Get server public key."""
        container_name = self._container_name(protocol_type)
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {container_name} cat /opt/amnezia/awg/wireguard_server_public_key.key"
        )
        if code != 0:
            raise RuntimeError(f"Failed to get server public key: {err}")
        return out.strip()

    def _get_server_psk(self, protocol_type):
        """Get server preshared key."""
        container_name = self._container_name(protocol_type)
        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {container_name} cat /opt/amnezia/awg/wireguard_psk.key"
        )
        if code != 0:
            raise RuntimeError(f"Failed to get PSK: {err}")
        return out.strip()

    def _get_awg_params_from_config(self, protocol_type):
        """Extract AWG obfuscation params from server config."""
        config = self._get_server_config(protocol_type)
        params = {}
        # Mapping from server config keys to our param dictionary keys
        param_map = {
            'ListenPort': 'port',
            'Jc': 'junk_packet_count',
            'Jmin': 'junk_packet_min_size',
            'Jmax': 'junk_packet_max_size',
            'S1': 'init_packet_junk_size',
            'S2': 'response_packet_junk_size',
            'S3': 'cookie_reply_packet_junk_size',
            'S4': 'transport_packet_junk_size',
            'H1': 'init_packet_magic_header',
            'H2': 'response_packet_magic_header',
            'H3': 'underload_packet_magic_header',
            'H4': 'transport_packet_magic_header',
            'I1': 'i1',
            'I2': 'i2',
            'I3': 'i3',
            'I4': 'i4',
            'I5': 'i5',
            'CPS': 'cps',
            'HeaderProtectionKey': 'header_protection_key',
            'ContentPaddingAddition': 'content_padding_addition',
        }

        for line in config.split('\n'):
            line = line.strip()
            # Support both 'key=value' and 'key = value'
            if '=' in line and not line.startswith('#') and not line.startswith('['):
                parts = line.split('=', 1)
                key = parts[0].strip()
                val = parts[1].strip()
                if key in param_map:
                    params[param_map[key]] = val

        return params

    def _append_obfuscation_lines(self, config_lines, awg_params, protocol_type):
        """Append Jc/S/H/(3.1) fields appropriate for the protocol generation."""
        mapping = [
            ('junk_packet_count', 'Jc'),
            ('junk_packet_min_size', 'Jmin'),
            ('junk_packet_max_size', 'Jmax'),
            ('init_packet_junk_size', 'S1'),
            ('response_packet_junk_size', 'S2'),
            ('cookie_reply_packet_junk_size', 'S3'),
            ('transport_packet_junk_size', 'S4'),
            ('init_packet_magic_header', 'H1'),
            ('response_packet_magic_header', 'H2'),
            ('underload_packet_magic_header', 'H3'),
            ('transport_packet_magic_header', 'H4'),
            ('i1', 'I1'),
            ('i2', 'I2'),
            ('i3', 'I3'),
            ('i4', 'I4'),
            ('i5', 'I5'),
            ('cps', 'CPS'),
            ('header_protection_key', 'HeaderProtectionKey'),
            ('content_padding_addition', 'ContentPaddingAddition'),
        ]
        legacy_skip = {
            'S3', 'S4', 'I1', 'I2', 'I3', 'I4', 'I5', 'CPS',
            'HeaderProtectionKey', 'ContentPaddingAddition',
        }
        v2_skip = {'HeaderProtectionKey', 'ContentPaddingAddition'}
        base = self._base_protocol(protocol_type)
        for param_key, config_key in mapping:
            val = awg_params.get(param_key)
            if not val:
                continue
            if base == self.AWG_LEGACY and config_key in legacy_skip:
                continue
            if base in (self.AWG, self.AWG2) and config_key in v2_skip:
                continue
            config_lines.append(f"{config_key} = {val}")

    def _get_used_ips(self, protocol_type):
        """Get list of IPs already assigned in the config."""
        config = self._get_server_config(protocol_type)
        ips = []
        for line in config.split('\n'):
            line = line.strip()
            if line.startswith('AllowedIPs'):
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    ips.append(match.group(1))
            elif line.startswith('Address'):
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    ips.append(match.group(1))
        return ips

    def _get_next_ip(self, protocol_type):
        """Calculate the next available IP for a new client."""
        used_ips = self._get_used_ips(protocol_type)
        if not used_ips:
            base = self._get_subnet_base(protocol_type)
            parts = base.split('.')
            parts[3] = '2'
            return '.'.join(parts)

        # Get the last used IP and increment
        last_ip = used_ips[-1]
        parts = last_ip.split('.')
        last_octet = int(parts[3])

        if last_octet == 254:
            next_octet = last_octet + 3
        elif last_octet == 255:
            next_octet = last_octet + 2
        else:
            next_octet = last_octet + 1

        parts[3] = str(next_octet)
        return '.'.join(parts)

    def _extract_ipv4(self, value):
        """Extract the first IPv4 address from AllowedIPs/clientIp-like values."""
        if not value:
            return ''
        match = re.search(r'(\d+\.\d+\.\d+\.\d+)', str(value))
        return match.group(1) if match else ''

    def _client_ip_from_userdata(self, user_data):
        """Return a valid client IP from stored userData, tolerating native Amnezia records."""
        return (
            self._extract_ipv4(user_data.get('clientIp'))
            or self._extract_ipv4(user_data.get('allowedIps'))
            or self._extract_ipv4(user_data.get('allowed_ip'))
        )

    def _parse_peers_from_config(self, protocol_type, config=None):
        """Parse [Peer] sections from WireGuard server config and return dict of pubkey -> {allowedIps}."""
        if config is None:
            try:
                config = self._get_server_config(protocol_type)
            except Exception:
                return {}

        peers = {}
        current_key = None
        pending_name = ''
        for line in config.split('\n'):
            line = line.strip()
            if line.startswith('#'):
                comment = line[1:].strip()
                if comment:
                    pending_name = comment
                continue
            if line.startswith('[') and line != '[Peer]':
                pending_name = ''
                current_key = None
                continue
            if line == '[Peer]':
                current_key = None
            elif current_key is None and line.startswith('PublicKey'):
                current_key = line.split('=', 1)[1].strip()
                peers[current_key] = {'allowedIps': '', 'clientName': pending_name}
                pending_name = ''
            elif current_key and line.startswith('AllowedIPs'):
                peers[current_key]['allowedIps'] = line.split('=', 1)[1].strip()
        return peers

    def _clients_snapshot(self, protocol_type):
        """Fetch clients table, wg show and server conf in one SSH/docker exec."""
        container_name = self._container_name(protocol_type)
        clients_table_path = self._clients_table_path()
        wg_bin = self._wg_binary(protocol_type)
        paths = ' '.join(self._config_path_candidates(protocol_type))
        script = (
            f'printf "%s\\n" __AMNZ_TABLE__; cat {clients_table_path} 2>/dev/null || true; printf "\\n%s\\n" __AMNZ_SHOW__; '
            f'{wg_bin} show all 2>/dev/null || true; printf "\\n%s\\n" __AMNZ_CONF__; '
            f'for p in {paths}; do if [ -f "$p" ]; then cat "$p"; break; fi; done'
        )
        out, _, _ = self.ssh.run_sudo_command(
            f"docker exec -i {container_name} sh -c '{script}'",
            timeout=20,
        )
        return _split_clients_snapshot(out)

    def _parse_clients_table_text(self, raw):
        if not raw or not raw.strip():
            return []
        text = raw.strip()
        for marker in _SNAPSHOT_MARKERS:
            if marker in text:
                text = text.split(marker, 1)[0]
        start_arr = text.find('[')
        start_obj = text.find('{')
        if start_arr == -1 and start_obj == -1:
            return []
        if start_arr == -1 or (start_obj != -1 and start_obj < start_arr):
            text = text[start_obj:]
            end = text.rfind('}')
        else:
            text = text[start_arr:]
            end = text.rfind(']')
        if end != -1:
            text = text[:end + 1]
        try:
            data = json.loads(text)
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                result = []
                for client_id, info in data.items():
                    if not isinstance(info, dict):
                        continue
                    result.append({
                        'clientId': client_id,
                        'userData': {
                            'clientName': info.get('clientName') or info.get('name') or 'Unknown',
                        },
                    })
                return result
        except json.JSONDecodeError:
            return []
        return []

    def _parse_wg_show_text(self, raw):
        result = {}
        current_peer = None
        for line in (raw or '').split('\n'):
            line = line.strip()
            if line.startswith('peer:'):
                current_peer = line.split(':', 1)[1].strip()
                result[current_peer] = {}
            elif current_peer and ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()
                if key == 'latest handshake':
                    result[current_peer]['latestHandshake'] = value
                elif key == 'transfer':
                    parts = value.split(',')
                    if len(parts) == 2:
                        received = parts[0].strip().replace(' received', '')
                        sent = parts[1].strip().replace(' sent', '')
                        result[current_peer]['dataReceived'] = received
                        result[current_peer]['dataSent'] = sent
                        result[current_peer]['dataReceivedBytes'] = self._parse_bytes(received)
                        result[current_peer]['dataSentBytes'] = self._parse_bytes(sent)
                elif key == 'allowed ips':
                    result[current_peer]['allowedIps'] = value
        return result

    def get_clients(self, protocol_type):
        """Get list of all clients."""
        try:
            snap = self._clients_snapshot(protocol_type)
            clients_table = self._parse_clients_table_text(snap.get('table'))
            wg_show_data = self._parse_wg_show_text(snap.get('show'))
            conf_text = snap.get('conf') or ''
            if not clients_table:
                clients_table = self._get_clients_table(protocol_type)
        except Exception:
            clients_table = self._get_clients_table(protocol_type)
            try:
                wg_show_data = self._wg_show(protocol_type)
            except Exception:
                wg_show_data = {}
            conf_text = None

        # Enrich clients table with wg show data
        known_ids = set()
        for client in clients_table:
            client_id = client.get('clientId', '')
            known_ids.add(client_id)
            user_data = client.get('userData') or {}
            if not isinstance(user_data, dict):
                user_data = {}
            if not (user_data.get('clientName') or '').strip():
                user_data['clientName'] = (
                    user_data.get('name')
                    or client.get('clientName')
                    or client.get('name')
                    or ''
                )
            if client_id in wg_show_data:
                show_data = wg_show_data[client_id]
                user_data['latestHandshake'] = show_data.get('latestHandshake', '')
                user_data['dataReceived'] = show_data.get('dataReceived', '')
                user_data['dataSent'] = show_data.get('dataSent', '')
                user_data['dataReceivedBytes'] = show_data.get('dataReceivedBytes', 0)
                user_data['dataSentBytes'] = show_data.get('dataSentBytes', 0)
                user_data['allowedIps'] = show_data.get('allowedIps', '') or user_data.get('allowedIps', '')
            client['userData'] = user_data

        # Pick up peers from conf that are NOT in clientsTable (created via native Amnezia app)
        try:
            conf_peers = self._parse_peers_from_config(protocol_type, conf_text)
            for pub_key, peer_info in conf_peers.items():
                if pub_key in known_ids:
                    continue  # already in table
                show_data = wg_show_data.get(pub_key, {})
                allowed_ip = peer_info.get('allowedIps', '') or show_data.get('allowedIps', '')
                ip_part = self._extract_ipv4(allowed_ip)
                display_name = (
                    (peer_info.get('clientName') or '').strip()
                    or (f'External ({ip_part})' if ip_part else 'External (native app)')
                )
                clients_table.append({
                    'clientId': pub_key,
                    'userData': {
                        'clientName': display_name,
                        'clientPrivateKey': '',   # not available
                        'externalClient': True,
                        'clientIp': ip_part,
                        'latestHandshake': show_data.get('latestHandshake', ''),
                        'dataReceived': show_data.get('dataReceived', ''),
                        'dataSent': show_data.get('dataSent', ''),
                        'dataReceivedBytes': show_data.get('dataReceivedBytes', 0),
                        'dataSentBytes': show_data.get('dataSentBytes', 0),
                        'allowedIps': allowed_ip,
                    }
                })
        except Exception as e:
            logger.warning(f'get_clients: failed to parse conf peers: {e}')

        return clients_table

    def _parse_bytes(self, size_str):
        """Parse human readable size string like '1.50 MiB' into bytes."""
        try:
            parts = size_str.strip().split()
            if len(parts) != 2: return 0
            val, unit = float(parts[0]), parts[1]
            units = {'B': 1, 'KiB': 1024, 'MiB': 1024**2, 'GiB': 1024**3, 'TiB': 1024**4}
            return int(val * units.get(unit, 1))
        except Exception:
            return 0

    def _wg_show(self, protocol_type):
        """Run 'wg show all' and parse output."""
        container_name = self._container_name(protocol_type)
        wg_bin = self._wg_binary(protocol_type)

        out, err, code = self.ssh.run_sudo_command(
            f"docker exec -i {container_name} bash -c '{wg_bin} show all'"
        )
        if code != 0 or not out.strip():
            return {}

        result = {}
        current_peer = None

        for line in out.split('\n'):
            line = line.strip()
            if line.startswith('peer:'):
                current_peer = line.split(':', 1)[1].strip()
                result[current_peer] = {}
            elif current_peer and ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()
                if key == 'latest handshake':
                    result[current_peer]['latestHandshake'] = value
                elif key == 'transfer':
                    parts = value.split(',')
                    if len(parts) == 2:
                        received = parts[0].strip().replace(' received', '')
                        sent = parts[1].strip().replace(' sent', '')
                        result[current_peer]['dataReceived'] = received
                        result[current_peer]['dataSent'] = sent
                        result[current_peer]['dataReceivedBytes'] = self._parse_bytes(received)
                        result[current_peer]['dataSentBytes'] = self._parse_bytes(sent)
                elif key == 'allowed ips':
                    result[current_peer]['allowedIps'] = value

        return result

    def add_client(self, protocol_type, client_name, server_host, port):
        """
        Add a new client/peer to the AWG config.
        Returns the client config as a string for the .conf file.
        """
        container_name = self._container_name(protocol_type)
        wg_bin = self._wg_binary(protocol_type)
        config_path = self._resolve_config_path(protocol_type)
        iface = self._interface_name(protocol_type, config_path)

        # Generate client keys
        client_priv_key, client_pub_key = generate_wg_keypair()

        # Get server info
        server_pub_key = self._get_server_public_key(protocol_type)
        psk = self._get_server_psk(protocol_type)

        # Get next available IP
        client_ip = self._get_next_ip(protocol_type)

        # Get AWG params from server config
        awg_params = self._get_awg_params_from_config(protocol_type)

        # Add peer to server config
        safe_name = (client_name or '').replace('\n', ' ').replace('"', '')[:80]
        peer_section = f"""
# {safe_name}
[Peer]
PublicKey = {client_pub_key}
PresharedKey = {psk}
AllowedIPs = {client_ip}/32

"""
        # Append peer to server config
        escaped_peer = peer_section.replace("'", "'\\''")
        self.ssh.run_sudo_command(
            f"docker exec -i {container_name} bash -c 'echo \"{escaped_peer}\" >> {config_path}'"
        )

        # Sync config without restart
        self.ssh.run_sudo_command(
            f"docker exec -i {container_name} bash -c '{wg_bin} syncconf {iface} <({wg_bin}-quick strip {config_path})'"
        )

        # Update clients table — store keys for config reconstruction
        clients_table = self._get_clients_table(protocol_type)
        new_client = {
            'clientId': client_pub_key,
            'userData': {
                'clientName': client_name,
                'creationDate': __import__('datetime').datetime.now().isoformat(),
                'clientPrivateKey': client_priv_key,
                'clientIp': client_ip,
                'psk': psk,
                'enabled': True,
            }
        }
        clients_table.append(new_client)
        self._save_clients_table(protocol_type, clients_table)

        # Build client config
        awg_params = self._get_awg_params_from_config(protocol_type)
        if awg_params.get('port'):
            port = awg_params['port']

        dns1 = AWG_DEFAULTS['dns1']
        dns2 = AWG_DEFAULTS['dns2']
        
        # Check if AmneziaDNS is installed
        out, _, _ = self.ssh.run_sudo_command("docker ps -a --filter name=^amnezia-dns$ --format '{{.Names}}'")
        if 'amnezia-dns' in out:
            dns1 = '172.29.172.254'
            
        mtu = AWG_DEFAULTS['mtu']

        # Standard fields
        config_lines = [
            f"Address = {client_ip}/32",
            f"DNS = {dns1}, {dns2}",
            f"PrivateKey = {client_priv_key}",
            f"MTU = {mtu}"
        ]

        # Conditional obfuscation fields
        self._append_obfuscation_lines(config_lines, awg_params, protocol_type)

        client_config = "[Interface]\n" + "\n".join(config_lines) + f"""

[Peer]
PublicKey = {server_pub_key}
PresharedKey = {psk}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {server_host}:{port}
PersistentKeepalive = 25
"""

        return {
            'client_name': client_name,
            'client_id': client_pub_key,
            'client_ip': client_ip,
            'config': client_config,
        }

    def get_client_config(self, protocol_type, client_id, server_host, port):
        """Reconstruct client config from stored data."""
        clients_table = self._get_clients_table(protocol_type)
        client = None
        for c in clients_table:
            if c.get('clientId') == client_id:
                client = c
                break

        if not client:
            raise RuntimeError(f"Client {client_id} not found")

        ud = client.get('userData', {})
        client_priv_key = ud.get('clientPrivateKey', '')
        client_ip = ud.get('clientIp', '')
        psk = ud.get('psk', '')

        if not client_priv_key:
            raise RuntimeError("Client private key not stored. Config cannot be reconstructed.")

        server_pub_key = self._get_server_public_key(protocol_type)
        if not psk:
            psk = self._get_server_psk(protocol_type)

        awg_params = self._get_awg_params_from_config(protocol_type)
        if awg_params.get('port'):
            port = awg_params['port']

        dns1 = AWG_DEFAULTS['dns1']
        dns2 = AWG_DEFAULTS['dns2']
        
        # Check if AmneziaDNS is installed
        out, _, _ = self.ssh.run_sudo_command("docker ps -a --filter name=^amnezia-dns$ --format '{{.Names}}'")
        if 'amnezia-dns' in out:
            dns1 = '172.29.172.254'
            
        mtu = AWG_DEFAULTS['mtu']

        # Standard fields
        config_lines = [
            f"Address = {client_ip}/32",
            f"DNS = {dns1}, {dns2}",
            f"PrivateKey = {client_priv_key}",
            f"MTU = {mtu}"
        ]

        # Conditional obfuscation fields
        self._append_obfuscation_lines(config_lines, awg_params, protocol_type)

        config = "[Interface]\n" + "\n".join(config_lines) + f"""

[Peer]
PublicKey = {server_pub_key}
PresharedKey = {psk}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {server_host}:{port}
PersistentKeepalive = 25
"""
        return config

    def toggle_client(self, protocol_type, client_id, enable):
        """Enable or disable a client by adding/removing their [Peer] from server config."""
        container_name = self._container_name(protocol_type)
        wg_bin = self._wg_binary(protocol_type)
        config_path = self._resolve_config_path(protocol_type)
        iface = self._interface_name(protocol_type, config_path)
        clients_table = self._get_clients_table(protocol_type)
        table_changed = False

        if enable:
            # Re-add peer to server config. Native Amnezia clients may not have
            # userData.clientIp in clientsTable, so recover it from allowedIps
            # before falling back to a new free address.
            client = None
            for c in clients_table:
                if c.get('clientId') == client_id:
                    client = c
                    break
            if not client:
                raise RuntimeError(f"Client {client_id} not found")

            ud = client.setdefault('userData', {})
            psk = ud.get('psk', '')
            client_ip = self._client_ip_from_userdata(ud)
            if not client_ip:
                client_ip = self._get_next_ip(protocol_type)
                logger.warning(
                    "Client %s had no saved AWG IP/AllowedIPs; assigning next free IP %s",
                    client_id,
                    client_ip,
                )

            ud['clientIp'] = client_ip
            ud['allowedIps'] = f'{client_ip}/32'
            table_changed = True

            if not psk:
                psk = self._get_server_psk(protocol_type)
                ud['psk'] = psk
                table_changed = True

            peer_section = f"""
[Peer]
PublicKey = {client_id}
PresharedKey = {psk}
AllowedIPs = {client_ip}/32

"""
            escaped_peer = peer_section.replace("'", "'\\''")
            self.ssh.run_sudo_command(
                f"docker exec -i {container_name} bash -c 'echo \"{escaped_peer}\" >> {config_path}'"
            )
        else:
            # Remove peer from server config, but first persist its current
            # AllowedIPs so native/external clients can be enabled later.
            config = self._get_server_config(protocol_type)
            conf_peers = self._parse_peers_from_config(protocol_type)
            allowed_ips = conf_peers.get(client_id, {}).get('allowedIps', '')
            client_ip = self._extract_ipv4(allowed_ips)
            client = None
            for c in clients_table:
                if c.get('clientId') == client_id:
                    client = c
                    break
            if client is None:
                client = {
                    'clientId': client_id,
                    'userData': {
                        'clientName': f'External ({client_ip})' if client_ip else 'External (native app)',
                        'externalClient': True,
                    }
                }
                clients_table.append(client)
                table_changed = True

            ud = client.setdefault('userData', {})
            if client_ip:
                ud['clientIp'] = client_ip
                ud['allowedIps'] = allowed_ips or f'{client_ip}/32'
                table_changed = True
            if not ud.get('psk'):
                ud['psk'] = self._get_server_psk(protocol_type)
                table_changed = True

            sections = config.split('[')
            new_sections = []
            for section in sections:
                if not section.strip():
                    continue
                if client_id in section:
                    continue
                new_sections.append(section)

            new_config = '[' + '['.join(new_sections)
            self.ssh.upload_file(new_config, "/tmp/_amnz_config.conf")
            self.ssh.run_sudo_command(
                f"docker cp /tmp/_amnz_config.conf {container_name}:{config_path}"
            )
            self.ssh.run_command("rm -f /tmp/_amnz_config.conf")

        # Sync config
        self.ssh.run_sudo_command(
            f"docker exec -i {container_name} bash -c '{wg_bin} syncconf {iface} <({wg_bin}-quick strip {config_path})'"
        )

        # Update enabled status in clients table
        for c in clients_table:
            if c.get('clientId') == client_id:
                c.setdefault('userData', {})['enabled'] = enable
                table_changed = True
                break
        if table_changed:
            self._save_clients_table(protocol_type, clients_table)

    def remove_client(self, protocol_type, client_id):
        """Remove a client from AWG config (mirrors revokeWireGuard)."""
        container_name = self._container_name(protocol_type)
        wg_bin = self._wg_binary(protocol_type)
        config_path = self._resolve_config_path(protocol_type)
        iface = self._interface_name(protocol_type, config_path)

        # Get current config
        config = self._get_server_config(protocol_type)

        # Split by [Peer] sections and remove the matching one
        sections = config.split('[')
        new_sections = []
        for section in sections:
            if not section.strip():
                continue
            if client_id in section:
                continue
            new_sections.append(section)

        new_config = '[' + '['.join(new_sections)

        # Upload new config into container via SFTP + docker cp
        self.ssh.upload_file(new_config, "/tmp/_amnz_config.conf")
        self.ssh.run_sudo_command(
            f"docker cp /tmp/_amnz_config.conf {container_name}:{config_path}"
        )
        self.ssh.run_command("rm -f /tmp/_amnz_config.conf")

        # Sync config
        self.ssh.run_sudo_command(
            f"docker exec -i {container_name} bash -c '{wg_bin} syncconf {iface} <({wg_bin}-quick strip {config_path})'"
        )

        # Update clients table
        clients_table = self._get_clients_table(protocol_type)
        clients_table = [c for c in clients_table if c.get('clientId') != client_id]
        self._save_clients_table(protocol_type, clients_table)

        return True

    def get_server_status(self, protocol_type):
        """Get detailed status of the AWG server."""
        container_name = self._container_name(protocol_type)

        info = {
            'container_exists': self.check_protocol_installed(protocol_type),
            'container_running': False,
            'protocol': protocol_type,
        }

        if info['container_exists']:
            info['container_running'] = self.check_container_running(protocol_type)

            if info['container_running']:
                try:
                    config = self._get_server_config(protocol_type)
                    # Extract port
                    for line in config.split('\n'):
                        if 'ListenPort' in line:
                            info['port'] = line.split('=')[1].strip()
                            break
                    info['awg_params'] = self._get_awg_params_from_config(protocol_type)
                    info['clients_count'] = len(self._get_clients_table(protocol_type))
                except Exception as e:
                    info['error'] = str(e)

        return info