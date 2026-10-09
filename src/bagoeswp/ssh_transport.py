from __future__ import annotations

import base64
import contextlib
import hashlib
import os
import re
import secrets
import shlex
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .models import AuthMethod, ServerConfig


LogCallback = Callable[[str], None]


@dataclass(slots=True)
class CommandResult:
    exit_code: int
    stdout: str
    stderr: str


class SSHError(RuntimeError):
    pass


class RemoteCommandError(SSHError):
    def __init__(self, command: str, result: CommandResult):
        self.command = command
        self.result = result
        message = result.stderr.strip() or result.stdout.strip() or "Perintah remote gagal"
        super().__init__(f"exit={result.exit_code}: {message}")


def _puttygen_candidates(configured: str = "") -> list[str]:
    candidates = [
        configured,
        shutil.which("puttygen") or "",
        shutil.which("puttygen.exe") or "",
        os.path.expandvars(r"%ProgramFiles%\PuTTY\puttygen.exe"),
        os.path.expandvars(r"%ProgramFiles(x86)%\PuTTY\puttygen.exe"),
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\PuTTY\puttygen.exe"),
    ]
    executable_dir = Path(getattr(__import__("sys"), "executable", "")).resolve().parent
    candidates.extend(
        [
            str(executable_dir / "puttygen.exe"),
            str(Path.cwd() / "puttygen.exe"),
            str(Path.cwd() / "tools" / "puttygen.exe"),
        ]
    )
    # Keep order but remove duplicates/empty values.
    return list(dict.fromkeys(value for value in candidates if value))


def find_puttygen(configured: str = "") -> str:
    for candidate in _puttygen_candidates(configured):
        if Path(candidate).is_file():
            return str(Path(candidate))
    raise SSHError(
        "PPK membutuhkan PuTTYgen untuk dikonversi. Instal PuTTY atau pilih puttygen.exe. "
        "Aplikasi sudah mencoba lokasi standar Program Files, LOCALAPPDATA, PATH, folder aplikasi, "
        "dan folder tools."
    )


def ppk_encryption(path: str | Path) -> str:
    """Return the PPK encryption name without exposing private material."""
    try:
        with Path(path).open("r", encoding="utf-8-sig", errors="strict") as handle:
            header = handle.readline().strip()
            lines = [handle.readline().strip() for _ in range(8)]
    except (OSError, UnicodeError) as exc:
        raise SSHError(f"File PPK tidak dapat dibaca: {exc}") from exc
    if not re.fullmatch(r"PuTTY-User-Key-File-[23]:\s*.+", header):
        raise SSHError("File yang dipilih bukan private key PPK versi 2 atau 3 yang valid")
    for line in lines:
        if line.lower().startswith("encryption:"):
            return line.split(":", 1)[1].strip().lower()
    raise SSHError("PPK tidak memiliki informasi Encryption yang valid")


def detect_key_method(path: str | Path) -> AuthMethod:
    key_path = Path(path)
    try:
        with key_path.open("r", encoding="utf-8-sig", errors="ignore") as handle:
            first = handle.readline().strip()
    except OSError:
        return AuthMethod.OPENSSH_KEY
    if first.startswith("PuTTY-User-Key-File-"):
        return AuthMethod.PPK
    if first.startswith("-----BEGIN ") and "PRIVATE KEY-----" in first:
        return AuthMethod.OPENSSH_KEY
    if key_path.suffix.lower() == ".ppk":
        return AuthMethod.PPK
    return AuthMethod.OPENSSH_KEY


class TemporaryKey:
    """Validate and convert a PPK in-process, retaining only an ephemeral file.

    PuTTYgen's Windows GUI does not implement the Unix conversion CLI. Native
    parsing avoids platform-specific commands and verifies the PPK MAC first.
    The original key is never modified; converted output is cleaned on failure.
    """

    def __init__(
        self,
        original: str,
        method: AuthMethod,
        puttygen: str = "",
        passphrase: str = "",
    ) -> None:
        self.original = original
        self.method = method
        self.puttygen = puttygen  # Accepted for compatibility with saved settings.
        self.passphrase = passphrase
        self.path = original
        self._temp_dir: tempfile.TemporaryDirectory[str] | None = None

    def __enter__(self) -> str:
        if self.method is not AuthMethod.PPK:
            return self.path
        from .ppk_keys import PPKError, ppk_to_openssh

        try:
            converted = ppk_to_openssh(self.original, self.passphrase)
            self._temp_dir = tempfile.TemporaryDirectory(prefix="bagoeswp-key-")
            output = Path(self._temp_dir.name) / "converted-openssh.key"
            # Create with restrictive permissions before writing secret material.
            fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(converted)
            self.path = str(output)
            return self.path
        except PPKError as exc:
            self.__exit__()
            raise SSHError(str(exc)) from exc
        except Exception:
            self.__exit__()
            raise

    def __exit__(self, *_: object) -> None:
        if self._temp_dir:
            self._temp_dir.cleanup()
            self._temp_dir = None


class SSHTransport:
    """One SSH connection. Create one instance per worker thread."""

    def __init__(self, config: ServerConfig, log: LogCallback | None = None) -> None:
        self.config = config
        self.log = log or (lambda _message: None)
        self._client = None
        self._key_context: TemporaryKey | None = None
        self.auth_used = ""

    def _new_client(self, paramiko):
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            known_hosts = Path(local_app_data) / "BagoesWP" / "known_hosts"
        else:
            known_hosts = Path.home() / ".bagoeswp" / "known_hosts"
        known_hosts.parent.mkdir(parents=True, exist_ok=True)
        known_hosts.touch(exist_ok=True)
        client.load_host_keys(str(known_hosts))
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        return client

    def _base_kwargs(self) -> dict[str, object]:
        return {
            "hostname": self.config.host,
            "port": int(self.config.port),
            "username": self.config.username,
            "timeout": 20,
            "banner_timeout": 30,
            "auth_timeout": 30,
            "look_for_keys": False,
        }

    def _key_method_for_attempt(self, preferred: AuthMethod) -> AuthMethod:
        if self.config.key_path and Path(self.config.key_path).is_file():
            detected = detect_key_method(self.config.key_path)
            if preferred in {AuthMethod.PPK, AuthMethod.OPENSSH_KEY} and detected is not preferred:
                self.log(
                    f"Tipe key terdeteksi {detected.value}; pilihan {preferred.value} disesuaikan otomatis."
                )
            return detected
        return preferred

    def _attempt_plan(self) -> list[AuthMethod]:
        preferred = self.config.auth_method
        plan: list[AuthMethod] = []

        def add(method: AuthMethod) -> None:
            if method not in plan:
                plan.append(method)

        has_key = bool(self.config.key_path and Path(self.config.key_path).is_file())
        has_password = bool(self.config.password)

        if preferred is AuthMethod.AUTO:
            if has_key:
                add(detect_key_method(self.config.key_path))
            if has_password:
                add(AuthMethod.PASSWORD)
            add(AuthMethod.SSH_AGENT)
        elif preferred is AuthMethod.PASSWORD:
            add(AuthMethod.PASSWORD)
            if has_key:
                add(detect_key_method(self.config.key_path))
            add(AuthMethod.SSH_AGENT)
        elif preferred in {AuthMethod.PPK, AuthMethod.OPENSSH_KEY}:
            add(self._key_method_for_attempt(preferred))
            if has_password:
                add(AuthMethod.PASSWORD)
            add(AuthMethod.SSH_AGENT)
        elif preferred is AuthMethod.SSH_AGENT:
            add(AuthMethod.SSH_AGENT)
            if has_key:
                add(detect_key_method(self.config.key_path))
            if has_password:
                add(AuthMethod.PASSWORD)
        return plan

    @staticmethod
    def _method_label(method: AuthMethod) -> str:
        return {
            AuthMethod.PASSWORD: "Password SSH",
            AuthMethod.OPENSSH_KEY: "OpenSSH key",
            AuthMethod.PPK: "PPK",
            AuthMethod.SSH_AGENT: "SSH Agent/Pageant",
            AuthMethod.AUTO: "Otomatis",
        }[method]

    def _connect_once(self, paramiko, method: AuthMethod) -> None:
        self.close()
        client = self._new_client(paramiko)
        self._client = client
        kwargs = self._base_kwargs()
        kwargs["allow_agent"] = method is AuthMethod.SSH_AGENT

        if method is AuthMethod.PASSWORD:
            if not self.config.password:
                raise SSHError("Password SSH kosong")
            kwargs["password"] = self.config.password
        elif method in {AuthMethod.OPENSSH_KEY, AuthMethod.PPK}:
            if not self.config.key_path or not Path(self.config.key_path).is_file():
                raise SSHError("Private key tidak ditemukan")
            real_method = detect_key_method(self.config.key_path)
            self._key_context = TemporaryKey(
                self.config.key_path,
                real_method,
                self.config.puttygen_path,
                self.config.key_passphrase,
            )
            try:
                key_path = self._key_context.__enter__()
                # Converted PPK output is intentionally unencrypted. Native OpenSSH keys may use
                # the supplied passphrase.
                key_password = (
                    self.config.key_passphrase or None
                    if real_method is AuthMethod.OPENSSH_KEY
                    else None
                )
                kwargs["pkey"] = paramiko.PKey.from_path(Path(key_path), password=key_password)
            except paramiko.PasswordRequiredException as exc:
                raise SSHError("Private key terenkripsi. Isi kolom Key passphrase.") from exc
            except paramiko.SSHException as exc:
                raise SSHError(f"Private key tidak dapat dibaca: {exc}") from exc
            except (ValueError, TypeError, OSError) as exc:
                # PKey.from_path delegates to cryptography, which also raises
                # ValueError/TypeError for invalid keys and wrong passphrases.
                # Keep these inside the auth fallback and cleanup path.
                raise SSHError(
                    "Private key tidak dapat dibaca. Periksa format key dan Key passphrase."
                ) from exc
        elif method is AuthMethod.SSH_AGENT:
            # No password/key here: Paramiko asks Windows OpenSSH Agent or PuTTY Pageant.
            pass
        else:
            raise SSHError(f"Metode autentikasi tidak didukung: {method.value}")

        try:
            client.connect(**kwargs)
        except paramiko.BadHostKeyException as exc:
            raise SSHError(
                "SSH host key berubah/tidak cocok dengan known_hosts. Demi keamanan koneksi dihentikan: "
                f"{exc}"
            ) from exc
        except paramiko.BadAuthenticationType as exc:
            allowed = ", ".join(exc.allowed_types) if exc.allowed_types else "tidak diketahui"
            raise SSHError(f"Server tidak menerima {self._method_label(method)}; metode server: {allowed}") from exc
        except paramiko.AuthenticationException as exc:
            if method is AuthMethod.PASSWORD:
                raise SSHError(
                    "Password SSH ditolak. Periksa username/password dan pastikan PasswordAuthentication aktif."
                ) from exc
            if method is AuthMethod.SSH_AGENT:
                raise SSHError("SSH Agent/Pageant tidak memiliki key yang diterima server") from exc
            raise SSHError(
                "Private key ditolak server. Periksa username, pasangan key, authorized_keys, dan passphrase."
            ) from exc
        except Exception as exc:
            raise SSHError(f"Koneksi SSH gagal: {exc}") from exc

    def connect(self) -> None:
        try:
            import paramiko
        except ImportError as exc:
            raise SSHError("Dependency Paramiko belum terpasang. Jalankan run_windows.bat.") from exc

        plan = self._attempt_plan()
        if not plan:
            raise SSHError("Tidak ada metode autentikasi yang dapat dicoba")

        errors: list[str] = []
        for index, method in enumerate(plan, start=1):
            label = self._method_label(method)
            self.log(f"Autentikasi {index}/{len(plan)}: mencoba {label}...")
            try:
                self._connect_once(paramiko, method)
                self.auth_used = label
                transport = self._client.get_transport() if self._client is not None else None
                if transport is not None:
                    key = transport.get_remote_server_key()
                    fingerprint = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode("ascii")
                    self.log(f"SSH host key {key.get_name()} SHA256:{fingerprint}")
                self.log(f"Autentikasi berhasil menggunakan {label}.")
                return
            except SSHError as exc:
                detail = str(exc)
                errors.append(f"{label}: {detail}")
                self.log(f"{label} gagal: {detail}")
                self.close()
                # Host key mismatch must never be bypassed by trying another credential.
                if "host key berubah/tidak cocok" in detail.lower():
                    raise

        raise SSHError("Semua metode autentikasi gagal. " + " | ".join(errors))

    def close(self) -> None:
        if self._client is not None:
            with contextlib.suppress(Exception):
                self._client.close()
            self._client = None
        if self._key_context is not None:
            self._key_context.__exit__(None, None, None)
            self._key_context = None

    def __enter__(self) -> "SSHTransport":
        self.connect()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _require_client(self):
        if self._client is None:
            raise SSHError("SSH belum tersambung")
        return self._client

    def run(
        self,
        command: str,
        *,
        sudo: bool = False,
        timeout: int | None = None,
        check: bool = True,
        display_command: str | None = None,
        input_text: str | None = None,
    ) -> CommandResult:
        client = self._require_client()
        sudo_password = self.config.sudo_password or self.config.password
        wrapped = command
        password_input = ""
        if sudo and self.config.username != "root":
            if sudo_password:
                # sudo may consume the password, or leave it on stdin when
                # NOPASSWD/cached credentials apply. Frame the application input
                # so the child safely discards any remaining password line.
                marker = "__BAGOESWP_STDIN_" + secrets.token_hex(16) + "__"
                framed_command = (
                    "while IFS= read -r bagoeswp_stdin_line; do "
                    f'if [ "$bagoeswp_stdin_line" = {shlex.quote(marker)} ]; then '
                    "unset bagoeswp_stdin_line; {\n" + command + "\n}; exit $?; fi; "
                    "done; exit 64"
                )
                wrapped = "sudo -S -p '' -- bash -lc " + shlex.quote(framed_command)
                password_input = sudo_password + "\n" + marker + "\n"
            else:
                wrapped = "sudo -n -- bash -lc " + shlex.quote(command)
        self.log(f"$ {display_command if display_command is not None else command}")
        stdin, stdout, stderr = client.exec_command(wrapped, timeout=timeout, get_pty=False)
        stdin_data = password_input + (input_text or "")
        if stdin_data:
            stdin.write(stdin_data)
            stdin.flush()
        stdin.channel.shutdown_write()
        out_text = stdout.read().decode("utf-8", errors="replace")
        err_text = stderr.read().decode("utf-8", errors="replace")
        exit_code = stdout.channel.recv_exit_status()
        for line in out_text.splitlines():
            self.log(line)
        for line in err_text.splitlines():
            self.log("[stderr] " + line)
        result = CommandResult(exit_code, out_text, err_text)
        if check and exit_code != 0:
            raise RemoteCommandError(command, result)
        return result

    def upload(self, local_path: str | Path, remote_path: str) -> None:
        client = self._require_client()
        sftp = client.open_sftp()
        try:
            sftp.put(str(local_path), remote_path)
            sftp.chmod(remote_path, 0o700)
        except Exception as exc:
            raise SSHError(f"Upload agent gagal: {exc}") from exc
        finally:
            sftp.close()


def quote_remote(value: str) -> str:
    return shlex.quote(value)
