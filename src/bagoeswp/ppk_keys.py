"""Read PuTTY PPK v2/v3 without relying on the Windows PuTTYgen GUI.

Format reference: PuTTY manual, Appendix C (PPK file format):
https://the.earth.li/~sgtatham/putty/latest/htmldoc/AppendixC.html
The MAC is verified before interpreting any decrypted private key material.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import struct
from pathlib import Path


class PPKError(ValueError):
    pass


MAX_FILE_BYTES = 1024 * 1024
# PuTTY normally uses 8 MiB and calibrates passes to about 100 ms. Bound both
# memory and total work before accepting parameters from an untrusted file.
MAX_ARGON2_MEMORY_KIB = 256 * 1024
MAX_ARGON2_PASSES = 100
MAX_ARGON2_PARALLELISM = 16
MAX_ARGON2_WORK = 1024 * 1024


def _string(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


class _Fields:
    def __init__(self, data: bytes) -> None:
        self.lines = data.removeprefix(b"\xef\xbb\xbf").splitlines()
        self.position = 0

    def field(self, name: bytes) -> bytes:
        if self.position >= len(self.lines):
            raise PPKError("File PPK terpotong atau memiliki urutan field yang tidak valid")
        line = self.lines[self.position]
        self.position += 1
        prefix = name + b": "
        if not line.startswith(prefix):
            raise PPKError("File PPK memiliki struktur field yang tidak valid")
        return line[len(prefix):]

    def integer(self, name: bytes) -> int:
        value = self.field(name)
        if not re.fullmatch(rb"[0-9]{1,10}", value):
            raise PPKError("File PPK memiliki parameter angka yang tidak valid")
        return int(value)

    def blob(self, name: bytes) -> bytes:
        count = self.integer(name)
        end = self.position + count
        if count < 1 or end > len(self.lines):
            raise PPKError("Data key PPK terpotong atau kosong")
        data = b"".join(self.lines[self.position:end])
        self.position = end
        try:
            return base64.b64decode(data, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise PPKError("Data base64 PPK tidak valid") from exc

    def finish(self) -> None:
        if any(self.lines[self.position:]):
            raise PPKError("File PPK memiliki field tambahan yang tidak valid")


class _Blob:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.position = 0

    def string(self) -> bytes:
        if self.position + 4 > len(self.data):
            raise PPKError("Data biner PPK terpotong")
        size = struct.unpack_from(">I", self.data, self.position)[0]
        start = self.position + 4
        end = start + size
        if end > len(self.data):
            raise PPKError("Data biner PPK terpotong")
        self.position = end
        return self.data[start:end]

    def integer(self) -> int:
        value = self.string()
        if not value or value[0] & 0x80 or len(value) > 2049:
            raise PPKError("Parameter key PPK tidak valid atau terlalu besar")
        return int.from_bytes(value, "big")

    def finish(self, padding: bool = False) -> None:
        remaining = len(self.data) - self.position
        if remaining != 0 and not (padding and remaining < 16):
            raise PPKError("Data key PPK memiliki panjang yang tidak valid")


def _hex(value: bytes, *, size: int | None = None) -> bytes:
    if not re.fullmatch(rb"[0-9a-fA-F]+", value) or len(value) % 2:
        raise PPKError("Data heksadesimal PPK tidak valid")
    decoded = bytes.fromhex(value.decode("ascii"))
    if size is not None and len(decoded) != size:
        raise PPKError("Panjang MAC PPK tidak valid")
    return decoded


def _argon2_keys(fields: _Fields, password: bytes) -> tuple[bytes, bytes, bytes]:
    flavor = fields.field(b"Key-Derivation")
    memory = fields.integer(b"Argon2-Memory")
    passes = fields.integer(b"Argon2-Passes")
    parallelism = fields.integer(b"Argon2-Parallelism")
    salt = _hex(fields.field(b"Argon2-Salt"))
    if (
        not 1 <= parallelism <= MAX_ARGON2_PARALLELISM
        or not 8 * parallelism <= memory <= MAX_ARGON2_MEMORY_KIB
        or not 1 <= passes <= MAX_ARGON2_PASSES
        or memory * passes > MAX_ARGON2_WORK
        or not 8 <= len(salt) <= 64
    ):
        raise PPKError(
            "Parameter Argon2 PPK melebihi batas aman aplikasi; "
            "ekspor ulang key dengan parameter standar PuTTY"
        )
    try:
        from argon2.low_level import Type, hash_secret_raw
    except ImportError as exc:
        raise PPKError("Dependency Argon2 belum terpasang. Jalankan run_windows.bat lagi") from exc
    flavors = {b"Argon2d": Type.D, b"Argon2i": Type.I, b"Argon2id": Type.ID}
    if flavor not in flavors:
        raise PPKError("Metode Key-Derivation PPK tidak didukung")
    try:
        material = hash_secret_raw(
            password, salt, time_cost=passes, memory_cost=memory,
            parallelism=parallelism, hash_len=80, type=flavors[flavor], version=19,
        )
    except (ValueError, RuntimeError) as exc:
        raise PPKError("Derivasi Argon2 PPK gagal; periksa format atau parameter key") from exc
    return material[:32], material[32:48], material[48:]


def _private_key(algorithm: bytes, public: bytes, private: bytes, encrypted: bool):
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    pub = _Blob(public)
    priv = _Blob(private)
    if pub.string() != algorithm:
        raise PPKError("Tipe public key PPK tidak sesuai header")
    if algorithm == b"ssh-rsa":
        e, n = pub.integer(), pub.integer()
        d, p, q, iqmp = (priv.integer() for _ in range(4))
        key = rsa.RSAPrivateNumbers(
            p, q, d, rsa.rsa_crt_dmp1(d, p), rsa.rsa_crt_dmq1(d, q), iqmp,
            rsa.RSAPublicNumbers(e, n),
        ).private_key()
    elif algorithm == b"ssh-ed25519":
        public_bytes = pub.string()
        seed = priv.string()
        if len(public_bytes) != 32 or len(seed) != 32:
            raise PPKError("Panjang key Ed25519 PPK tidak valid")
        key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    elif algorithm.startswith(b"ecdsa-sha2-"):
        curves = {b"nistp256": ec.SECP256R1, b"nistp384": ec.SECP384R1, b"nistp521": ec.SECP521R1}
        name = pub.string()
        if name not in curves or algorithm != b"ecdsa-sha2-" + name:
            raise PPKError("Kurva ECDSA PPK tidak didukung")
        pub.string()  # The complete public blob is compared to the derived key below.
        key = ec.derive_private_key(priv.integer(), curves[name]())
    elif algorithm == b"ssh-dss":
        raise PPKError("Key DSA lama tidak didukung; gunakan key Ed25519 atau RSA")
    else:
        raise PPKError("Tipe key PPK tidak didukung; gunakan RSA, ECDSA, atau Ed25519")
    pub.finish()
    priv.finish(padding=encrypted)
    derived = base64.b64decode(
        key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).split()[1],
        validate=True,
    )
    if not hmac.compare_digest(derived, public):
        raise PPKError("Public key dan private key PPK tidak cocok")
    return key


def ppk_to_openssh(path: str | Path, passphrase: str = "") -> bytes:
    """Validate a PPK and return an unencrypted OpenSSH private key in memory."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

    try:
        with Path(path).open("rb") as handle:
            data = handle.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise PPKError("File PPK tidak dapat dibaca") from exc
    if len(data) > MAX_FILE_BYTES:
        raise PPKError("File PPK terlalu besar")
    fields = _Fields(data)
    if not fields.lines:
        raise PPKError("File PPK kosong")
    header = re.fullmatch(rb"PuTTY-User-Key-File-([23]): ([a-zA-Z0-9@._-]+)", fields.lines[0])
    if not header:
        raise PPKError("File yang dipilih bukan private key PPK versi 2 atau 3 yang valid")
    version = int(header[1])
    algorithm = header[2]
    fields.position = 1
    encryption = fields.field(b"Encryption")
    if encryption not in {b"none", b"aes256-cbc"}:
        raise PPKError("Metode enkripsi PPK tidak didukung")
    encrypted = encryption != b"none"
    if encrypted and not passphrase:
        raise PPKError("PPK terenkripsi. Isi kolom Key passphrase dengan passphrase PPK")
    password = passphrase.encode("utf-8") if encrypted else b""
    comment = fields.field(b"Comment")
    public = fields.blob(b"Public-Lines")
    cipher_key, iv, mac_key = b"", b"", b""
    digest = hashlib.sha256 if version == 3 else hashlib.sha1
    if version == 3 and encrypted:
        cipher_key, iv, mac_key = _argon2_keys(fields, password)
    elif version == 2:
        mac_key = hashlib.sha1(b"putty-private-key-file-mac-key" + password).digest()
        if encrypted:
            cipher_key = b"".join(hashlib.sha1(struct.pack(">I", i) + password).digest() for i in (0, 1))[:32]
            iv = b"\0" * 16
    private = fields.blob(b"Private-Lines")
    expected_mac = _hex(fields.field(b"Private-MAC"), size=32 if version == 3 else 20)
    fields.finish()
    if encrypted:
        if len(private) % 16:
            raise PPKError("Panjang data PPK terenkripsi tidak valid")
        decryptor = Cipher(algorithms.AES(cipher_key), modes.CBC(iv)).decryptor()
        private = decryptor.update(private) + decryptor.finalize()
    payload = b"".join(_string(value) for value in (algorithm, encryption, comment, public, private))
    if not hmac.compare_digest(hmac.new(mac_key, payload, digest).digest(), expected_mac):
        if encrypted:
            raise PPKError("Passphrase PPK salah atau integritas file PPK gagal")
        raise PPKError("Integritas file PPK gagal; file berubah atau rusak")
    try:
        key = _private_key(algorithm, public, private, encrypted)
    except PPKError:
        raise
    except (ValueError, TypeError, ArithmeticError) as exc:
        raise PPKError("Parameter public/private key PPK tidak valid") from exc
    return key.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption())
