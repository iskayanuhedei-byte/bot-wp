from __future__ import annotations

import tempfile
import base64
import hashlib
import hmac
import os
import shutil
import struct
import shlex
import subprocess
import socket
import threading
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import paramiko
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from bagoeswp.models import AuthMethod, ServerConfig
from bagoeswp.ppk_keys import PPKError, ppk_to_openssh
from bagoeswp.ssh_transport import (
    SSHError,
    SSHTransport,
    TemporaryKey,
    detect_key_method,
    ppk_encryption,
)


def write_ppk(path: Path, encryption: str = "none") -> None:
    path.write_text(
        "PuTTY-User-Key-File-3: ssh-ed25519\n"
        f"Encryption: {encryption}\n"
        "Comment: test\n"
        "Public-Lines: 0\n"
        "Private-Lines: 0\n",
        encoding="utf-8",
    )


PUTTYGEN = os.environ.get("BAGOESWP_TEST_PUTTYGEN") or shutil.which("puttygen")


def public_blob(key) -> bytes:
    return base64.b64decode(key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).split()[1])


def make_valid_ppk(path: Path, key, version: int = 3, passphrase: str = "", public_override: bytes | None = None) -> None:
    """Small fixture writer; the PuTTYgen test separately verifies interoperability."""
    def string(value):
        return struct.pack(">I", len(value)) + value
    def mpint(value):
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if raw and raw[0] & 0x80:
            raw = b"\0" + raw
        return string(raw)
    public = public_override if public_override is not None else public_blob(key)
    algorithm = key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).split()[0]
    if isinstance(key, rsa.RSAPrivateKey):
        numbers = key.private_numbers()
        private = b"".join(mpint(value) for value in (numbers.d, numbers.p, numbers.q, numbers.iqmp))
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        private = mpint(key.private_numbers().private_value)
    else:
        private = string(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
    encryption = b"aes256-cbc" if passphrase else b"none"
    cipher_key, iv, mac_key = b"", b"", b""
    kdf = ""
    password = passphrase.encode("utf-8")
    if version == 2:
        mac_key = hashlib.sha1(b"putty-private-key-file-mac-key" + password).digest()
        cipher_key = b"".join(hashlib.sha1(struct.pack(">I", i) + password).digest() for i in (0, 1))[:32]
        iv = b"\0" * 16
    elif passphrase:
        from argon2.low_level import Type, hash_secret_raw
        salt = b"test-salt-for-ppk"
        material = hash_secret_raw(password, salt, 2, 1024, 1, 80, Type.ID)
        cipher_key, iv, mac_key = material[:32], material[32:48], material[48:]
        kdf = "Key-Derivation: Argon2id\nArgon2-Memory: 1024\nArgon2-Passes: 2\nArgon2-Parallelism: 1\nArgon2-Salt: " + salt.hex() + "\n"
    if passphrase:
        private += b"X" * (-len(private) % 16)
    mac = hmac.new(mac_key, b"".join(string(value) for value in (algorithm, encryption, b"test", public, private)),
                   hashlib.sha256 if version == 3 else hashlib.sha1).hexdigest()
    if passphrase:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        encryptor = Cipher(algorithms.AES(cipher_key), modes.CBC(iv)).encryptor()
        private = encryptor.update(private) + encryptor.finalize()
    path.write_text(
        f"PuTTY-User-Key-File-{version}: {algorithm.decode()}\nEncryption: {encryption.decode()}\nComment: test\n"
        f"Public-Lines: 1\n{base64.b64encode(public).decode()}\n{kdf}"
        f"Private-Lines: 1\n{base64.b64encode(private).decode()}\nPrivate-MAC: {mac}\n", encoding="utf-8",
    )


class SSHTransportTests(unittest.TestCase):
    def test_ppk_encryption_detects_encrypted_and_plain_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            encrypted = Path(directory) / "encrypted.ppk"
            plain = Path(directory) / "plain.ppk"
            write_ppk(encrypted, "aes256-cbc")
            write_ppk(plain)
            self.assertEqual(ppk_encryption(encrypted), "aes256-cbc")
            self.assertEqual(ppk_encryption(plain), "none")

    def test_detect_key_method_checks_extension_and_header(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ppk = Path(directory) / "key.any"
            pem = Path(directory) / "key.pem"
            write_ppk(ppk)
            pem.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n", encoding="utf-8")
            self.assertIs(detect_key_method(ppk), AuthMethod.PPK)
            self.assertIs(detect_key_method(pem), AuthMethod.OPENSSH_KEY)

    def test_encrypted_ppk_requires_key_passphrase(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "encrypted.ppk"
            write_ppk(key, "aes256-cbc")
            with self.assertRaisesRegex(SSHError, "Isi kolom Key passphrase"):
                TemporaryKey(str(key), AuthMethod.PPK, "puttygen.exe").__enter__()

    def test_ppk_conversion_is_native_and_temporary_output_is_cleaned(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "plain.ppk"
            expected = ed25519.Ed25519PrivateKey.generate()
            make_valid_ppk(key, expected)
            with patch("bagoeswp.ssh_transport.find_puttygen", side_effect=AssertionError("CLI called")):
                with TemporaryKey(str(key), AuthMethod.PPK, "nonexistent.exe") as converted:
                    output = Path(converted)
                    actual = paramiko.PKey.from_path(output)
                    self.assertEqual(actual.asbytes(), public_blob(expected))
                    if os.name != "nt":
                        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
                self.assertFalse(output.exists())

    def test_native_ppk_roundtrip_and_mac_for_versions_and_key_types(self) -> None:
        keys = [
            rsa.generate_private_key(public_exponent=65537, key_size=2048),
            ec.generate_private_key(ec.SECP256R1()),
            ec.generate_private_key(ec.SECP384R1()),
            ec.generate_private_key(ec.SECP521R1()),
            ed25519.Ed25519PrivateKey.generate(),
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test.ppk"
            for version in (2, 3):
                for encrypted in (False, True):
                    for expected in keys:
                        with self.subTest(version=version, encrypted=encrypted, key=type(expected).__name__):
                            make_valid_ppk(path, expected, version, "passphrase" if encrypted else "")
                            with TemporaryKey(str(path), AuthMethod.PPK, passphrase="passphrase") as converted:
                                self.assertEqual(paramiko.PKey.from_path(Path(converted)).asbytes(), public_blob(expected))
                            if encrypted:
                                with self.assertRaisesRegex(SSHError, "Passphrase PPK salah"):
                                    with TemporaryKey(str(path), AuthMethod.PPK, passphrase="wrong"):
                                        pass
                            path.write_bytes(path.read_bytes().replace(b"Comment: test", b"Comment: fake"))
                            with self.assertRaisesRegex(PPKError, "integritas|Integritas"):
                                ppk_to_openssh(path, "passphrase")

    def test_argon2_parameters_are_bounded_before_kdf(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test.ppk"
            make_valid_ppk(path, ed25519.Ed25519PrivateKey.generate(), 3, "passphrase")
            path.write_bytes(path.read_bytes().replace(b"Argon2-Memory: 1024", b"Argon2-Memory: 4294967295"))
            with patch("argon2.low_level.hash_secret_raw", side_effect=AssertionError("KDF called")):
                with self.assertRaisesRegex(PPKError, "batas aman"):
                    ppk_to_openssh(path, "passphrase")

    def test_valid_mac_cannot_hide_mismatched_public_and_private_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test.ppk"
            private = ed25519.Ed25519PrivateKey.generate()
            different_public = public_blob(ed25519.Ed25519PrivateKey.generate())
            make_valid_ppk(path, private, public_override=different_public)
            with self.assertRaisesRegex(PPKError, "tidak cocok"):
                ppk_to_openssh(path)

    @unittest.skipUnless(PUTTYGEN, "PuTTYgen needed for independent interoperability test")
    def test_interoperability_with_all_argon2_flavors(self) -> None:
        key = ed25519.Ed25519PrivateKey.generate()
        with tempfile.TemporaryDirectory() as directory:
            original = Path(directory) / "original.key"
            ppk = Path(directory) / "converted.ppk"
            password_file = Path(directory) / "passphrase"
            password_file.write_text("unicode-秘密", encoding="utf-8")
            original.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()))
            for flavor in ("argon2id", "argon2i", "argon2d"):
                with self.subTest(flavor=flavor):
                    subprocess.run(
                        [PUTTYGEN, str(original), "-O", "private", "--new-passphrase", str(password_file),
                         "--ppk-param", f"version=3,kdf={flavor},memory=1024,passes=2,parallelism=2",
                         "-C", "key-秘密", "-o", str(ppk)],
                        check=True, capture_output=True, timeout=30,
                    )
                    with TemporaryKey(str(ppk), AuthMethod.PPK, passphrase="unicode-秘密") as converted:
                        self.assertEqual(paramiko.PKey.from_path(Path(converted)).asbytes(), public_blob(key))

    def test_ppk_temporary_directory_is_removed_when_write_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "key.ppk"
            make_valid_ppk(path, ed25519.Ed25519PrivateKey.generate())
            key = TemporaryKey(str(path), AuthMethod.PPK)
            real_open = os.open
            def fail_output_open(target, *args, **kwargs):
                if str(target).endswith("converted-openssh.key"):
                    raise OSError("disk failure")
                return real_open(target, *args, **kwargs)
            with patch("bagoeswp.ssh_transport.os.open", side_effect=fail_output_open):
                with self.assertRaises(OSError):
                    key.__enter__()
            self.assertIsNone(key._temp_dir)

    @unittest.skipUnless(PUTTYGEN, "PuTTYgen needed for independent interoperability test")
    def test_interoperability_with_real_puttygen(self) -> None:
        keys = [
            rsa.generate_private_key(public_exponent=65537, key_size=2048),
            ec.generate_private_key(ec.SECP256R1()),
            ec.generate_private_key(ec.SECP384R1()),
            ec.generate_private_key(ec.SECP521R1()),
            ed25519.Ed25519PrivateKey.generate(),
        ]
        with tempfile.TemporaryDirectory() as directory:
            original = Path(directory) / "original.key"
            ppk = Path(directory) / "converted.ppk"
            password_file = Path(directory) / "passphrase"
            for version in (2, 3):
                for password in ("", "phrase with spaces"):
                    password_file.write_text(password, encoding="utf-8")
                    for key in keys:
                        with self.subTest(version=version, encrypted=bool(password), key=type(key).__name__):
                            original.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()))
                            subprocess.run(
                                [PUTTYGEN, str(original), "-O", "private", "--new-passphrase", str(password_file),
                                 "--ppk-param", f"version={version},memory=1024,passes=2,parallelism=1", "-o", str(ppk)],
                                check=True, capture_output=True, timeout=30,
                            )
                            with TemporaryKey(str(ppk), AuthMethod.PPK, passphrase=password) as converted:
                                self.assertEqual(paramiko.PKey.from_path(Path(converted)).asbytes(), public_blob(key))

    def test_invalid_native_key_falls_back_and_releases_client(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broken.key"
            path.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\ninvalid\n", encoding="utf-8")
            logs = []
            transport = SSHTransport(ServerConfig(host="192.0.2.1", username="ubuntu", key_path=str(path),
                                                   auth_method=AuthMethod.OPENSSH_KEY, password="fallback"), logs.append)
            clients = [MagicMock(), MagicMock()]
            clients[1].get_transport.return_value = None
            with patch.object(transport, "_new_client", side_effect=clients):
                transport.connect()
            self.assertEqual(transport.auth_used, "Password SSH")
            clients[0].close.assert_called_once()
            self.assertIsNone(transport._key_context)
            transport.close()

    def test_sudo_and_stdin_payload_do_not_enter_command_or_logs(self) -> None:
        for password in ("", "sudo-secret"):
            with self.subTest(password=bool(password)):
                logs = []
                config = ServerConfig(host="192.0.2.1", username="ubuntu", sudo_password=password)
                transport = SSHTransport(config, logs.append)
                stdin, stdout, stderr = MagicMock(), MagicMock(), MagicMock()
                stdout.read.return_value = b"done\n"
                stderr.read.return_value = b""
                stdout.channel.recv_exit_status.return_value = 0
                transport._client = MagicMock()
                transport._client.exec_command.return_value = (stdin, stdout, stderr)
                transport.run("python3 agent.py --payload-stdin", sudo=True, input_text="private-payload")
                wrapped = transport._client.exec_command.call_args.args[0]
                self.assertIn("sudo -S" if password else "sudo -n", wrapped)
                self.assertNotIn("private-payload", wrapped)
                self.assertNotIn("sudo-secret", wrapped)
                stdin.write.assert_called_once()
                delivered = stdin.write.call_args.args[0]
                if password:
                    first, marker, payload = delivered.split("\n", 2)
                    self.assertEqual(first, password)
                    self.assertIn(marker, wrapped)
                    self.assertEqual(payload, "private-payload")
                else:
                    self.assertEqual(delivered, "private-payload")
                self.assertFalse(any("private-payload" in line or "sudo-secret" in line for line in logs))
                stdin.channel.shutdown_write.assert_called_once()

    def test_host_key_mismatch_stops_auth_fallback(self) -> None:
        config = ServerConfig(host="192.0.2.1", username="ubuntu", auth_method=AuthMethod.PASSWORD, password="secret")
        transport = SSHTransport(config)
        client = MagicMock()
        client.connect.side_effect = paramiko.BadHostKeyException(config.host, paramiko.RSAKey.generate(1024),
                                                                 paramiko.RSAKey.generate(1024))
        with patch.object(transport, "_new_client", return_value=client) as new_client:
            with self.assertRaisesRegex(SSHError, "host key berubah/tidak cocok"):
                transport.connect()
        new_client.assert_called_once()
        self.assertIsNone(transport._client)

    def test_real_local_ssh_auth_accepts_native_ppk(self) -> None:
        for key in (ed25519.Ed25519PrivateKey.generate(),
                    rsa.generate_private_key(public_exponent=65537, key_size=2048)):
            for version in (2, 3):
                with self.subTest(key=type(key).__name__, version=version):
                    self._assert_local_ssh_auth(key, version)

    def _assert_local_ssh_auth(self, key, version) -> None:
        expected_public = public_blob(key)
        class Server(paramiko.ServerInterface):
            def check_auth_publickey(self, username, offered):
                if username == "ubuntu" and offered.asbytes() == expected_public:
                    return paramiko.AUTH_SUCCESSFUL
                return paramiko.AUTH_FAILED
            def get_allowed_auths(self, _username):
                return "publickey"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "login.ppk"
            if PUTTYGEN:
                original = Path(directory) / "original.key"
                password_file = Path(directory) / "passphrase"
                original.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()))
                password_file.write_text("key-phrase", encoding="utf-8")
                subprocess.run(
                    [PUTTYGEN, str(original), "-O", "private", "--new-passphrase", str(password_file),
                     "--ppk-param", f"version={version},memory=1024,passes=2,parallelism=1", "-o", str(path)],
                    check=True, capture_output=True, timeout=30,
                )
            else:
                make_valid_ppk(path, key, version, "key-phrase")
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(15)
            errors = []
            complete = threading.Event()
            host_key = paramiko.RSAKey.generate(2048)
            def serve():
                remote = None
                try:
                    connection, _address = listener.accept()
                    remote = paramiko.Transport(connection)
                    remote.add_server_key(host_key)
                    remote.start_server(server=Server())
                    complete.wait(15)
                except Exception as exc:
                    errors.append(exc)
                finally:
                    if remote:
                        remote.close()
                    listener.close()
            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
            host, port = listener.getsockname()
            config = ServerConfig(host=host, port=port, username="ubuntu", auth_method=AuthMethod.PPK,
                                  key_path=str(path), key_passphrase="key-phrase")
            transport = SSHTransport(config)
            try:
                with patch.dict(os.environ, {"LOCALAPPDATA": directory}):
                    transport.connect()
                self.assertEqual(transport.auth_used, "PPK")
                self.assertTrue(transport._client.get_transport().is_authenticated())
                self.assertTrue((Path(directory) / "BagoesWP" / "known_hosts").is_file())
            finally:
                transport.close()
                complete.set()
                worker.join(15)
            self.assertFalse(worker.is_alive())
            self.assertFalse(errors)

    def test_auto_auth_plan_uses_key_then_password_then_agent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "key.ppk"
            write_ppk(key)
            config = ServerConfig(
                host="192.0.2.1",
                username="ubuntu",
                auth_method=AuthMethod.AUTO,
                password="secret",
                key_path=str(key),
            )
            transport = SSHTransport(config)
            self.assertEqual(
                transport._attempt_plan(),
                [AuthMethod.PPK, AuthMethod.PASSWORD, AuthMethod.SSH_AGENT],
            )

    def test_key_auth_plan_keeps_password_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "id_ed25519"
            key.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n", encoding="utf-8")
            config = ServerConfig(
                host="192.0.2.1",
                username="ubuntu",
                auth_method=AuthMethod.OPENSSH_KEY,
                password="secret",
                key_path=str(key),
            )
            transport = SSHTransport(config)
            self.assertEqual(
                transport._attempt_plan(),
                [AuthMethod.OPENSSH_KEY, AuthMethod.PASSWORD, AuthMethod.SSH_AGENT],
            )

    def test_content_detection_overrides_misleading_ppk_extension(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "actually-openssh.ppk"
            path.write_bytes(ed25519.Ed25519PrivateKey.generate().private_bytes(
                Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption(),
            ))
            self.assertIs(detect_key_method(path), AuthMethod.OPENSSH_KEY)

    def test_sudo_stdin_framing_handles_consumed_and_unconsumed_password(self) -> None:
        transport = SSHTransport(ServerConfig(host="192.0.2.1", username="ubuntu", sudo_password="ssh-password"))
        stdin, stdout, stderr = MagicMock(), MagicMock(), MagicMock()
        stdout.read.return_value = b""
        stderr.read.return_value = b""
        stdout.channel.recv_exit_status.return_value = 0
        transport._client = MagicMock()
        transport._client.exec_command.return_value = (stdin, stdout, stderr)
        transport.run("cat", sudo=True, input_text="application-secret\n")
        wrapped = transport._client.exec_command.call_args.args[0]
        script = shlex.split(wrapped)[-1]
        delivered = stdin.write.call_args.args[0]
        for sudo_consumed_password in (False, True):
            with self.subTest(sudo_consumed_password=sudo_consumed_password):
                source = delivered.split("\n", 1)[1] if sudo_consumed_password else delivered
                result = subprocess.run(["bash", "-c", script], input=source, capture_output=True, text=True,
                                        check=True, timeout=10)
                self.assertEqual(result.stdout, "application-secret\n")
                self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
