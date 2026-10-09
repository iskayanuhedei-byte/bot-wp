from __future__ import annotations

import csv
import ipaddress
import re
from pathlib import Path

from .models import AuthMethod, ServerConfig, SiteSpec, parse_bool


DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
USER_RE = re.compile(r"^[A-Za-z0-9_.@-]{3,60}$")
LOCALE_RE = re.compile(r"^[a-z]{2,3}(?:_[A-Z]{2})?$")


class ValidationError(ValueError):
    pass


def normalize_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix) :]
    domain = domain.split("/", 1)[0]
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def validate_domain(value: str) -> str:
    domain = normalize_domain(value)
    if not DOMAIN_RE.fullmatch(domain):
        raise ValidationError(f"Domain tidak valid: {value!r}")
    return domain


def validate_server(config: ServerConfig) -> None:
    if not config.host.strip():
        raise ValidationError("IP/host VPS wajib diisi")
    try:
        ipaddress.ip_address(config.host.strip())
    except ValueError:
        if not DOMAIN_RE.fullmatch(config.host.strip()):
            raise ValidationError("IP/host VPS tidak valid")
    if not 1 <= int(config.port) <= 65535:
        raise ValidationError("Port SSH harus 1-65535")
    if not config.username.strip():
        raise ValidationError("Username SSH wajib diisi")
    if not 1 <= int(config.concurrency) <= 10:
        raise ValidationError("Concurrency harus 1-10")
    if config.auth_method is AuthMethod.PASSWORD and not config.password:
        raise ValidationError("Password SSH wajib diisi")
    if config.auth_method is AuthMethod.AUTO and not (config.password or config.key_path):
        # SSH Agent/Pageant tetap akan dicoba, tetapi minta setidaknya satu kredensial eksplisit
        # agar kegagalan tidak membingungkan pada komputer tanpa agent aktif.
        raise ValidationError("Mode Otomatis memerlukan Password SSH atau private key")
    if config.auth_method in {AuthMethod.OPENSSH_KEY, AuthMethod.PPK}:
        if not config.key_path:
            raise ValidationError("Lokasi private key wajib dipilih")
        if not Path(config.key_path).is_file():
            raise ValidationError("Private key tidak ditemukan")


def validate_site(site: SiteSpec) -> SiteSpec:
    site.domain = validate_domain(site.domain)
    site.title = site.title.strip()
    site.admin_user = site.admin_user.strip()
    site.admin_email = site.admin_email.strip()
    site.locale = site.locale.strip()
    if not site.title.strip():
        raise ValidationError(f"Judul website {site.domain} kosong")
    if not USER_RE.fullmatch(site.admin_user.strip()):
        raise ValidationError(f"Username admin {site.domain} tidak valid")
    if not EMAIL_RE.fullmatch(site.admin_email.strip()):
        raise ValidationError(f"Email admin {site.domain} tidak valid")
    if len(site.admin_password) < 12:
        raise ValidationError(f"Password admin {site.domain} minimal 12 karakter")
    if not LOCALE_RE.fullmatch(site.locale.strip()):
        raise ValidationError(f"Locale {site.domain} tidak valid")
    return site


def validate_sites(sites: list[SiteSpec]) -> list[SiteSpec]:
    if not sites:
        raise ValidationError("Tambahkan minimal satu domain")
    normalized: list[SiteSpec] = []
    seen: set[str] = set()
    for site in sites:
        checked = validate_site(site)
        if checked.domain in seen:
            raise ValidationError(f"Domain duplikat: {checked.domain}")
        seen.add(checked.domain)
        normalized.append(checked)
    return normalized


def read_sites_csv(path: str | Path) -> list[SiteSpec]:
    required = {"domain", "title", "admin_user", "admin_email", "admin_password"}
    sites: list[SiteSpec] = []
    with Path(path).open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        headers = set(reader.fieldnames or [])
        missing = required - headers
        if missing:
            raise ValidationError("Kolom CSV kurang: " + ", ".join(sorted(missing)))
        for line_no, row in enumerate(reader, start=2):
            if not (row.get("domain") or "").strip():
                continue
            try:
                sites.append(
                    SiteSpec(
                        domain=row["domain"],
                        title=row["title"],
                        admin_user=row["admin_user"],
                        admin_email=row["admin_email"],
                        admin_password=row["admin_password"],
                        locale=(row.get("locale") or "en_US").strip(),
                        enable_ssl=parse_bool(row.get("ssl"), True),
                        include_www=parse_bool(row.get("www"), True),
                    )
                )
            except Exception as exc:
                raise ValidationError(f"CSV baris {line_no}: {exc}") from exc
    return validate_sites(sites)


def parse_bulk_text(value: str) -> list[SiteSpec]:
    """Parse domain|title|user|email|password|locale|ssl|www."""
    sites: list[SiteSpec] = []
    for line_no, raw in enumerate(value.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [part.strip() for part in line.split("|")]
        if len(parts) < 5:
            raise ValidationError(
                f"Baris {line_no}: gunakan domain|title|user|email|password|locale|ssl|www"
            )
        parts += [""] * (8 - len(parts))
        sites.append(
            SiteSpec(
                domain=parts[0],
                title=parts[1],
                admin_user=parts[2],
                admin_email=parts[3],
                admin_password=parts[4],
                locale=parts[5] or "en_US",
                enable_ssl=parse_bool(parts[6], True),
                include_www=parse_bool(parts[7], True),
            )
        )
    return validate_sites(sites)

