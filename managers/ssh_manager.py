"""
SSH Manager - manages SSH connections to VPN servers.
Replicates the ServerController logic from the AmneziaVPN client.

Concurrency notes
-----------------
Remote sshd MaxSessions is often ~10. Parallel UI polls + background traffic
sync used to open many Paramiko sessions to the same host and then fail with
"Timeout opening channel", stalling worker threads until the panel looked
"dead" and got restarted by the orchestrator.

We serialize *all* SSH work per (host, port, user) with a Lock, and keep a
small global cap on concurrent SSH hosts. Nested calls on the same thread
are tracked explicitly so they do not lock twice.

The lock must be a plain Lock, not an RLock: connect() and disconnect()
often run on different asyncio thread-pool workers. An RLock can only be
released by the thread that acquired it, which surfaced as
"cannot release un-acquired lock" when fetching a client config.
"""

import io
import logging
import threading
import time

import paramiko

logger = logging.getLogger(__name__)

# Per-host serialization. Plain Lock so another thread can release it
# (connect/disconnect are separate asyncio.to_thread calls).
_HOST_LOCKS = {}
_HOST_LOCKS_GUARD = threading.Lock()
# Cap how many different hosts can run SSH work at once.
_GLOBAL_SSH_SEM = threading.Semaphore(6)
_POOL = {}
_POOL_GUARD = threading.Lock()
_POOL_TTL = 60
_SWEEPER_STARTED = False

# Which thread owns each host key. Re-entry is per owner thread, not RLock.
_SCOPE_GUARD = threading.Lock()
_HELD = {}   # thread ident -> set of host keys
_OWNER = {}  # host key -> thread ident


def host_key(host, port, username):
    return (str(host or ''), int(port or 22), str(username or ''))


def host_ssh_lock(host, port, username):
    key = host_key(host, port, username)
    with _HOST_LOCKS_GUARD:
        lock = _HOST_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _HOST_LOCKS[key] = lock
        return lock


def _holds_host_key(key):
    with _SCOPE_GUARD:
        held = _HELD.get(threading.get_ident())
        return bool(held and key in held)


def _mark_held(key):
    ident = threading.get_ident()
    held = _HELD.get(ident)
    if held is None:
        held = set()
        _HELD[ident] = held
    held.add(key)
    _OWNER[key] = ident


def _unmark_held(key):
    """Drop ownership even if release runs on a different thread than acquire."""
    owner = _OWNER.pop(key, None)
    if owner is None:
        owner = threading.get_ident()
    held = _HELD.get(owner)
    if not held:
        return
    held.discard(key)
    if not held:
        _HELD.pop(owner, None)


def _acquire_host_scope(host, port, username, timeout=60):
    """Acquire per-host Lock (+ global sem on first acquire). Returns (lock, acquired_new)."""
    key = host_key(host, port, username)
    lock = host_ssh_lock(host, port, username)
    if _holds_host_key(key):
        return lock, False
    if not lock.acquire(timeout=timeout):
        raise TimeoutError(f"SSH host busy (lock timeout): {host}")
    if not _GLOBAL_SSH_SEM.acquire(timeout=timeout):
        lock.release()
        raise TimeoutError(f"SSH global limit timeout: {host}")
    with _SCOPE_GUARD:
        _mark_held(key)
    return lock, True


def _release_host_scope(host, port, username, acquired_new):
    if not acquired_new:
        return
    key = host_key(host, port, username)
    with _SCOPE_GUARD:
        _unmark_held(key)
    _GLOBAL_SSH_SEM.release()
    host_ssh_lock(host, port, username).release()


def _start_pool_sweeper():
    global _SWEEPER_STARTED
    with _POOL_GUARD:
        if _SWEEPER_STARTED:
            return
        _SWEEPER_STARTED = True

    def _sweep():
        while True:
            time.sleep(20)
            now = time.monotonic()
            stale = []
            with _POOL_GUARD:
                for key, entry in list(_POOL.items()):
                    if now - entry['last_used'] > _POOL_TTL or not entry['ssh'].is_alive():
                        stale.append(key)
                for key in stale:
                    entry = _POOL.pop(key, None)
                    if entry:
                        try:
                            entry['ssh'].disconnect(release_session=False)
                        except Exception:
                            pass

    threading.Thread(target=_sweep, name='ssh-pool-sweeper', daemon=True).start()


def borrow_pooled_ssh(host, port, username, password=None, private_key=None):
    """Reuse a live SSH session instead of a full handshake on every API call.

    Caller MUST already hold the host scope lock (see run_pooled).
    """
    _start_pool_sweeper()
    key = host_key(host, port, username)
    with _POOL_GUARD:
        entry = _POOL.get(key)
        if entry and entry['ssh'].is_alive():
            entry['last_used'] = time.monotonic()
            return entry['ssh']
        if entry:
            try:
                entry['ssh'].disconnect(release_session=False)
            except Exception:
                pass
            _POOL.pop(key, None)
        ssh = SSHManager(host, port, username, password, private_key)
        ssh.connect(take_host_lock=False)
        _POOL[key] = {'ssh': ssh, 'last_used': time.monotonic()}
        return ssh


def evict_pooled_ssh(host, port, username):
    key = host_key(host, port, username)
    with _POOL_GUARD:
        entry = _POOL.pop(key, None)
    if entry:
        try:
            entry['ssh'].disconnect(release_session=False)
        except Exception:
            pass


def run_pooled(host, port, username, password, private_key, fn):
    _, acquired = _acquire_host_scope(host, port, username)
    try:
        ssh = borrow_pooled_ssh(host, port, username, password, private_key)
        try:
            return fn(ssh)
        except Exception as e:
            if (not ssh.is_alive()) or SSHManager._should_reconnect(e):
                evict_pooled_ssh(host, port, username)
            raise
    except Exception as e:
        if SSHManager._should_reconnect(e):
            evict_pooled_ssh(host, port, username)
        raise
    finally:
        _release_host_scope(host, port, username, acquired)


class SSHManager:
    """Manages SSH connections and command execution on remote servers."""

    def __init__(self, host, port, username, password=None, private_key=None):
        self.host = host
        self.port = int(port)
        self.username = username
        self.password = password
        self.private_key = private_key
        self.client = None
        self._is_root = (username == 'root')
        self._lock = threading.RLock()
        self._host_lock = host_ssh_lock(host, port, username)
        # True when this instance acquired the host scope via connect(take_host_lock=True)
        self._session_owned = False
        self._session_acquired_new = False

    def is_alive(self):
        if not self.client:
            return False
        transport = self.client.get_transport()
        return bool(transport and transport.is_active() and transport.is_authenticated())

    def connect(self, take_host_lock=True):
        """Establish SSH connection to the server.

        take_host_lock=True (default for get_ssh paths) serializes this host so
        we do not open parallel sessions and hit sshd MaxSessions.
        take_host_lock=False when the caller already holds the host scope
        (run_pooled / pool borrow).
        """
        if take_host_lock and not self._session_owned:
            _, acquired = _acquire_host_scope(self.host, self.port, self.username)
            self._session_owned = True
            self._session_acquired_new = acquired

        with self._lock:
            try:
                if self.is_alive():
                    return True
                self._close_client_only()

                self.client = paramiko.SSHClient()
                self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                kwargs = {
                    'hostname': self.host,
                    'port': self.port,
                    'username': self.username,
                    'timeout': 15,
                    'banner_timeout': 15,
                    'auth_timeout': 15,
                    'allow_agent': False,
                    'look_for_keys': False,
                }

                if self.private_key:
                    key_file = io.StringIO(self.private_key)
                    try:
                        pkey = paramiko.RSAKey.from_private_key(key_file)
                    except paramiko.ssh_exception.SSHException:
                        key_file.seek(0)
                        try:
                            pkey = paramiko.Ed25519Key.from_private_key(key_file)
                        except paramiko.ssh_exception.SSHException:
                            key_file.seek(0)
                            pkey = paramiko.ECDSAKey.from_private_key(key_file)
                    kwargs['pkey'] = pkey
                elif self.password:
                    kwargs['password'] = self.password

                self.client.connect(**kwargs)
                transport = self.client.get_transport()
                if transport:
                    transport.set_keepalive(15)
                    # Keep channel window healthy under bursty short commands
                    try:
                        transport.use_compression(True)
                    except Exception:
                        pass
                return True
            except Exception:
                self._close_client_only()
                if take_host_lock and self._session_owned:
                    self._release_owned_session()
                raise

    def _release_owned_session(self):
        if not self._session_owned:
            return
        acquired = self._session_acquired_new
        self._session_owned = False
        self._session_acquired_new = False
        _release_host_scope(self.host, self.port, self.username, acquired)

    def _close_client_only(self):
        client = self.client
        self.client = None
        if not client:
            return
        try:
            transport = client.get_transport()
            if transport:
                transport.close()
        except Exception:
            pass
        try:
            client.close()
        except Exception:
            pass

    def disconnect(self, release_session=True):
        """Close SSH connection. release_session=False keeps host scope (pool)."""
        with self._lock:
            self._close_client_only()
        if release_session:
            self._release_owned_session()

    def _ensure_connected(self):
        if not self.is_alive():
            # If we already own a session lock, reconnect without re-acquiring.
            self.connect(take_host_lock=not self._session_owned)

    def run_command(self, command, timeout=60):
        """Execute command on remote server."""
        # Ensure host is serialized even if caller forgot connect() session lock
        # (e.g. leftover client). Prefer existing session ownership.
        need_scope = not self._session_owned and not _holds_host_key(host_key(self.host, self.port, self.username))
        acquired = False
        if need_scope:
            _, acquired = _acquire_host_scope(self.host, self.port, self.username)
        try:
            with self._lock:
                return self._run_command_locked(command, timeout, retry=True)
        finally:
            if need_scope:
                _release_host_scope(self.host, self.port, self.username, acquired)

    def _run_command_locked(self, command, timeout, retry):
        self._ensure_connected()
        if not self.client:
            raise ConnectionError("Not connected to server")

        logger.debug(f"Running command: {command[:100]}...")
        # Channel open timeout: keep short so a wedged sshd fails fast
        channel_timeout = min(max(int(timeout or 60), 5), 20)
        stdin = stdout = stderr = None
        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=channel_timeout)
            stdout.channel.settimeout(timeout)
            stderr.channel.settimeout(timeout)
            exit_code = stdout.channel.recv_exit_status()
            out = stdout.read().decode('utf-8', errors='replace').strip()
            err = stderr.read().decode('utf-8', errors='replace').strip()
        except Exception as e:
            logger.error("Command timed out or failed to read on %s: %s", self.host, e)
            self._close_client_only()
            evict_pooled_ssh(self.host, self.port, self.username)
            if retry and self._should_reconnect(e):
                time.sleep(0.5)
                try:
                    return self._run_command_locked(command, timeout, retry=False)
                except Exception as retry_err:
                    logger.error("SSH retry failed on %s: %s", self.host, retry_err)
                    return "", str(retry_err), -1
            return "", str(e), -1
        finally:
            self._close_exec(stdin, stdout, stderr)

        if exit_code != 0:
            logger.warning(f"Command exited with code {exit_code}: {err}")

        return out, err, exit_code

    @staticmethod
    def _should_reconnect(exc):
        text = str(exc).lower()
        return any(token in text for token in (
            'timeout opening channel',
            'not active',
            'eof',
            'no existing session',
            'administratively prohibited',
            'channel is not open',
            'socket is closed',
            'connection reset',
            'session not active',
        ))

    @staticmethod
    def _close_exec(stdin, stdout, stderr):
        for stream in (stdin, stdout, stderr):
            if stream is None:
                continue
            try:
                stream.channel.close()
            except Exception:
                pass
            try:
                stream.close()
            except Exception:
                pass

    def _sudo_prefix(self):
        """Get the sudo command prefix with password handling."""
        if self._is_root:
            return ''
        if self.password:
            escaped_pass = self.password.replace("'", "'\\''")
            return f"echo '{escaped_pass}' | sudo -S "
        return 'sudo '

    def run_sudo_command(self, command, timeout=60):
        """
        Execute command with sudo, automatically handling password.
        Strips 'sudo ' from the beginning of command if present,
        and re-adds it with password piping.
        """
        clean_cmd = command
        if clean_cmd.strip().startswith('sudo '):
            clean_cmd = clean_cmd.strip()[5:]

        if self._is_root:
            return self.run_command(clean_cmd, timeout=timeout)

        if self.password:
            escaped_pass = self.password.replace("'", "'\\''")
            full_cmd = f"echo '{escaped_pass}' | sudo -S -p '' {clean_cmd}"
        else:
            full_cmd = f"sudo {clean_cmd}"

        return self.run_command(full_cmd, timeout=timeout)

    def run_sudo_script(self, script, timeout=120):
        """
        Execute a multi-line script with sudo/root privileges.
        Writes script to /tmp via SFTP, then runs with sudo bash.
        """
        if self._is_root:
            return self.run_script(script, timeout=timeout)

        import hashlib
        script_hash = hashlib.md5(script.encode()).hexdigest()[:8]
        tmp_script = f"/tmp/_amnz_script_{script_hash}.sh"
        self.upload_file(script, tmp_script)

        if self.password:
            escaped_pass = self.password.replace("'", "'\\''")
            full_cmd = f"echo '{escaped_pass}' | sudo -S -p '' bash {tmp_script}; rm -f {tmp_script}"
        else:
            full_cmd = f"sudo bash {tmp_script}; rm -f {tmp_script}"

        return self.run_command(full_cmd, timeout=timeout)

    def run_script(self, script, timeout=120):
        """Execute a multi-line script on remote server."""
        return self.run_command(script, timeout=timeout)

    def upload_file(self, content, remote_path):
        """Upload text content to a remote file via SFTP."""
        need_scope = not self._session_owned and not _holds_host_key(host_key(self.host, self.port, self.username))
        acquired = False
        if need_scope:
            _, acquired = _acquire_host_scope(self.host, self.port, self.username)
        try:
            with self._lock:
                self._ensure_connected()
                if not self.client:
                    raise ConnectionError("Not connected to server")
                content = content.replace('\r\n', '\n')
                sftp = self.client.open_sftp()
                try:
                    with sftp.file(remote_path, 'w') as f:
                        f.write(content)
                finally:
                    sftp.close()
        finally:
            if need_scope:
                _release_host_scope(self.host, self.port, self.username, acquired)

    def upload_file_sudo(self, content, remote_path):
        """
        Upload text content to a remote file that requires root access.
        Uses SFTP to write to /tmp, then sudo mv to the target path.
        Also normalizes line endings to Unix-style (LF).
        """
        content = content.replace('\r\n', '\n')
        import hashlib
        tmp_name = f"/tmp/_amnz_{hashlib.md5(remote_path.encode()).hexdigest()[:8]}"
        self.upload_file(content, tmp_name)
        self.run_sudo_command(f"mv {tmp_name} {remote_path}")
        self.run_sudo_command(f"chmod 644 {remote_path}")
        return True

    def download_file(self, remote_path):
        """Download text content from a remote file."""
        need_scope = not self._session_owned and not _holds_host_key(host_key(self.host, self.port, self.username))
        acquired = False
        if need_scope:
            _, acquired = _acquire_host_scope(self.host, self.port, self.username)
        try:
            with self._lock:
                self._ensure_connected()
                if not self.client:
                    raise ConnectionError("Not connected to server")
                sftp = self.client.open_sftp()
                try:
                    with sftp.file(remote_path, 'r') as f:
                        return f.read().decode('utf-8', errors='replace')
                finally:
                    sftp.close()
        finally:
            if need_scope:
                _release_host_scope(self.host, self.port, self.username, acquired)

    def file_exists(self, remote_path):
        """Check if a remote file exists."""
        need_scope = not self._session_owned and not _holds_host_key(host_key(self.host, self.port, self.username))
        acquired = False
        if need_scope:
            _, acquired = _acquire_host_scope(self.host, self.port, self.username)
        try:
            with self._lock:
                self._ensure_connected()
                if not self.client:
                    raise ConnectionError("Not connected to server")
                sftp = self.client.open_sftp()
                try:
                    sftp.stat(remote_path)
                    return True
                except FileNotFoundError:
                    return False
                finally:
                    sftp.close()
        finally:
            if need_scope:
                _release_host_scope(self.host, self.port, self.username, acquired)

    def test_connection(self):
        """Test SSH connection and return server info."""
        out, err, code = self.run_command("uname -sr && cat /etc/os-release 2>/dev/null | head -2")
        return out

    def write_file(self, remote_path, content):
        """Write content to a remote file with sudo."""
        return self.upload_file_sudo(content, remote_path)

    def __enter__(self):
        self.connect(take_host_lock=True)
        return self

    def __exit__(self, *args):
        self.disconnect(release_session=True)

    def __del__(self):
        # Best-effort unlock if caller forgot disconnect() after an exception.
        try:
            if self._session_owned:
                self.disconnect(release_session=True)
        except Exception:
            pass
