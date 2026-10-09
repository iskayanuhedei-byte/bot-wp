#!/usr/bin/env python3
"""Remote provisioning agent for BagoesWP OLS Manager.

Uploaded to an Ubuntu 24.04 VPS and executed as root. It intentionally uses
only the Python standard library so the remote host does not need pip.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import datetime as dt
import email.utils
import fcntl
import grp
import hashlib
import http.client
import json
import os
import pwd
import re
import secrets
import shlex
import shutil
import socket
import ssl
import string
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Iterable


VERSION = "0.2.7"
BASE = Path("/var/lib/bagoeswp")
STATE_DIR = BASE / "sites"
REPORT_DIR = BASE / "reports"
TUNING_PATH = BASE / "tuning.json"
LOCK_FILE = Path("/var/lock/bagoeswp.lock")
OLS_ROOT = Path("/usr/local/lsws")
OLS_MAIN = OLS_ROOT / "conf/httpd_config.conf"
OLS_DEFAULTS = OLS_ROOT / "conf/httpd-defaults.conf"
MANAGED_DIR = OLS_ROOT / "conf/bagoeswp"
MANAGED_CONF = MANAGED_DIR / "manager.conf"
MANAGED_INCLUDE = "include /usr/local/lsws/conf/bagoeswp/manager.conf"
PERSISTENT_AGENT = Path("/usr/local/lib/bagoeswp/remote_agent.py")
PHP_BIN = Path("/usr/local/lsws/lsphp83/bin/php")
WP_CLI = Path("/usr/local/bin/wp")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)
LOCALE_RE = re.compile(r"^[a-z]{2,3}(?:_[A-Z]{2})?$")
USER_RE = re.compile(r"^[A-Za-z0-9_.@-]{3,60}$")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
PERFORMANCE_POLICY: dict[str, float] = {
    "max_p95_ms": 800.0,
    "min_cache_hit_pct": 90.0,
    "max_error_pct": 0.0,
    "max_peak_cpu_pct": 90.0,
    "max_peak_memory_pct": 90.0,
    "max_swap_growth_mb": 0.0,
}


class AgentError(RuntimeError):
    def __init__(self, stage: str, message: str):
        self.stage = stage
        super().__init__(message)


def log(message: str) -> None:
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%H:%M:%S")
    print(f"[{stamp}] {message}", flush=True)


def run(
    args: list[str],
    *,
    input_text: str | None = None,
    check: bool = True,
    timeout: int | None = None,
    env: dict[str, str] | None = None,
    quiet: bool = False,
) -> subprocess.CompletedProcess[str]:
    safe = " ".join(shlex.quote(item) for item in args)
    if not quiet:
        log("Menjalankan: " + safe)
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    result = subprocess.run(
        args,
        input=input_text,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=merged_env,
        check=False,
    )
    if result.stdout and not quiet:
        for line in result.stdout.rstrip().splitlines():
            log(line)
    if result.stderr and not quiet:
        for line in result.stderr.rstrip().splitlines():
            log("stderr: " + line)
    if check and result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or safe
        raise AgentError("command", f"Perintah gagal ({result.returncode}): {detail}")
    return result


def atomic_write(path: Path, content: str, mode: int = 0o640) -> None:
    previous = path.stat() if path.exists() else None
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, mode)
        if previous is not None:
            os.chown(temp_name, previous.st_uid, previous.st_gid)
        os.replace(temp_name, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temp_name)


def backup_file(path: Path) -> Path | None:
    if not path.exists():
        return None
    backup_dir = BASE / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    destination = backup_dir / f"{path.name}.{stamp}.{secrets.token_hex(3)}.bak"
    shutil.copy2(path, destination)
    return destination


@contextlib.contextmanager
def global_lock() -> Iterable[None]:
    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOCK_FILE.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def read_os_release() -> dict[str, str]:
    data: dict[str, str] = {}
    path = Path("/etc/os-release")
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                data[key] = value.strip().strip('"')
    return data


def parse_meminfo(text: str) -> dict[str, int]:
    """Parse /proc/meminfo values into MiB without trusting field order."""
    values: dict[str, int] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, raw = line.split(":", 1)
        parts = raw.split()
        if not parts or not parts[0].isdigit():
            continue
        kib = int(parts[0])
        values[key] = kib // 1024
    return values


def memory_snapshot() -> dict[str, int]:
    parsed = parse_meminfo(Path("/proc/meminfo").read_text(encoding="utf-8"))
    total = max(1, parsed.get("MemTotal", 1024))
    available = max(0, min(total, parsed.get("MemAvailable", parsed.get("MemFree", 0))))
    swap_total = max(0, parsed.get("SwapTotal", 0))
    swap_free = max(0, min(swap_total, parsed.get("SwapFree", 0)))
    return {
        "memory_total_mb": total,
        "memory_available_mb": available,
        "memory_used_mb": total - available,
        "swap_total_mb": swap_total,
        "swap_free_mb": swap_free,
        "swap_used_mb": swap_total - swap_free,
    }


def memory_mb() -> int:
    return memory_snapshot()["memory_total_mb"]


def system_snapshot() -> dict[str, Any]:
    memory = memory_snapshot()
    disk = shutil.disk_usage("/")
    load = os.getloadavg() if hasattr(os, "getloadavg") else (0.0, 0.0, 0.0)
    return {
        **memory,
        "vcpu": os.cpu_count() or 1,
        "load_1m": round(load[0], 3),
        "load_5m": round(load[1], 3),
        "load_15m": round(load[2], 3),
        "disk_total_gib": round(disk.total / 1024**3, 2),
        "disk_free_gib": round(disk.free / 1024**3, 2),
        "disk_used_pct": round(disk.used / disk.total * 100, 2),
    }


def percentile(values: list[float], percent: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(0.0, min(1.0, percent)) * (len(ordered) - 1)
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = rank - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def resource_plan(mem_mb: int, vcpu: int, site_count: int) -> dict[str, int]:
    """Return a conservative initial plan; audit can retune after real use."""
    mem_mb = max(512, int(mem_mb))
    vcpu = max(1, int(vcpu))
    site_count = max(1, int(site_count))
    ols_workers = 1 if vcpu <= 8 else 2
    os_reserve = max(512, int(mem_mb * 0.18))
    usable = max(320, mem_mb - os_reserve)
    mariadb_mb = max(256, min(4096, int(usable * 0.30)))
    redis_mb = max(64, min(1024, int(usable * 0.08)))
    ols_budget = max(128, min(512, int(usable * 0.07)))
    php_budget = max(
        160,
        min(int(mem_mb * 0.38), usable - mariadb_mb - redis_mb - ols_budget),
    )
    # Each site's LSAPI process group owns OPcache shared memory. Count it
    # separately from PHP request memory instead of spending the same RAM twice.
    php_process_memory_mb = 256
    opcache_per_site = 64
    group_overhead = opcache_per_site + 16
    groups = site_count * ols_workers
    opcache_overhead = groups * group_overhead
    total_php_children = max(0, (php_budget - opcache_overhead) // php_process_memory_mb)
    per_site_children = max(1, min(10, total_php_children // site_count // ols_workers))
    php_estimated_mb = groups * (per_site_children * php_process_memory_mb + group_overhead)
    max_safe_sites = php_budget // (ols_workers * (php_process_memory_mb + group_overhead))
    return {
        "memory_mb": mem_mb,
        "vcpu": vcpu,
        "site_count": site_count,
        "ols_workers": ols_workers,
        "os_reserve_mb": os_reserve,
        "mariadb_mb": mariadb_mb,
        "redis_mb": redis_mb,
        "ols_budget_mb": ols_budget,
        "php_budget_mb": php_budget,
        "headroom_mb": max(0, mem_mb - os_reserve - mariadb_mb - redis_mb - ols_budget - php_budget),
        "php_children_per_site": per_site_children,
        "opcache_mb_per_site": opcache_per_site,
        "php_process_memory_mb": php_process_memory_mb,
        "opcache_overhead_mb": opcache_overhead,
        "php_estimated_mb": php_estimated_mb,
        "max_safe_sites": max_safe_sites,
        "capacity_ok": int(php_estimated_mb <= php_budget),
    }


def load_tuning() -> dict[str, int]:
    if not TUNING_PATH.exists():
        return {}
    try:
        raw = json.loads(TUNING_PATH.read_text(encoding="utf-8"))
        return {"php_children_per_site": int(raw["php_children_per_site"])}
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        log("Tuning override rusak; memakai perhitungan resource standar")
        return {}


def save_tuning(children: int | None) -> None:
    if children is None:
        with contextlib.suppress(FileNotFoundError):
            TUNING_PATH.unlink()
        return
    atomic_write(
        TUNING_PATH,
        json.dumps(
            {
                "php_children_per_site": max(1, int(children)),
                "updated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            },
            indent=2,
        ),
        0o600,
    )


def effective_resource_plan(mem_mb: int, vcpu: int, site_count: int) -> dict[str, int]:
    plan = resource_plan(mem_mb, vcpu, site_count)
    override = load_tuning().get("php_children_per_site")
    if override is not None:
        plan["php_children_per_site"] = max(
            1, min(int(override), int(plan["php_children_per_site"]))
        )
        plan["php_estimated_mb"] = (
            plan["site_count"] * plan["ols_workers"]
            * plan["php_children_per_site"] * plan["php_process_memory_mb"]
            + plan["opcache_overhead_mb"]
        )
        plan["capacity_ok"] = int(plan["php_estimated_mb"] <= plan["php_budget_mb"])
    return plan


def choose_php_children(
    current: int,
    baseline: int,
    site_results: dict[str, dict[str, Any]],
) -> tuple[int, str]:
    """Choose at most one bounded adjustment; never exceed the safe RAM plan."""
    benchmarks = [
        value.get("benchmark") or {}
        for value in site_results.values()
        if isinstance(value, dict)
    ]
    if not benchmarks:
        return current, "no_benchmark"
    peak_cpu = max(float(item.get("peak_cpu_pct", 0.0)) for item in benchmarks)
    peak_memory = max(float(item.get("peak_memory_pct", 0.0)) for item in benchmarks)
    swap_growth = max(float(item.get("swap_growth_mb", 0.0)) for item in benchmarks)
    error_rate = max(float(item.get("error_rate_pct", 0.0)) for item in benchmarks)
    if (peak_cpu > 90.0 or peak_memory > 90.0 or swap_growth > 0.0) and current > 1:
        return current - 1, "resource_pressure"
    if (
        current < baseline
        and peak_cpu < 70.0
        and peak_memory < 80.0
        and swap_growth <= 0.0
        and error_rate <= 0.0
    ):
        return min(baseline, current + 1), "headroom_recovery"
    return current, "stable"


def normalize_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    for prefix in ("http://", "https://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix) :]
    domain = domain.split("/", 1)[0]
    if domain.startswith("www."):
        domain = domain[4:]
    if not DOMAIN_RE.fullmatch(domain):
        raise AgentError("validation", f"Domain tidak valid: {value!r}")
    return domain


def validate_payload(data: dict[str, Any]) -> dict[str, Any]:
    required = ("domain", "title", "admin_user", "admin_email", "admin_password")
    missing = [key for key in required if not str(data.get(key, "")).strip()]
    if missing:
        raise AgentError("validation", "Kolom kosong: " + ", ".join(missing))
    data = dict(data)
    data["domain"] = normalize_domain(str(data["domain"]))
    if not USER_RE.fullmatch(str(data["admin_user"])):
        raise AgentError("validation", "Username admin tidak valid")
    if not EMAIL_RE.fullmatch(str(data["admin_email"])):
        raise AgentError("validation", "Email admin tidak valid")
    if len(str(data["admin_password"])) < 12:
        raise AgentError("validation", "Password admin minimal 12 karakter")
    locale = str(data.get("locale") or "en_US")
    if not LOCALE_RE.fullmatch(locale):
        raise AgentError("validation", "Locale WordPress tidak valid")
    data["locale"] = locale
    data["enable_ssl"] = bool(data.get("enable_ssl", True))
    data["include_www"] = bool(data.get("include_www", True))
    return data


def site_identity(domain: str) -> dict[str, str]:
    digest = hashlib.sha256(domain.encode("utf-8")).hexdigest()[:12]
    return {
        "site_key": "bw" + digest,
        "linux_user": "bw" + digest[:10],
        "db_name": "bw_" + digest,
        "db_user": "bw_" + digest,
        "socket": f"uds://tmp/lshttpd/bw-{digest}.sock",
    }


def random_password(length: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits + "_-"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def state_path(domain: str) -> Path:
    return STATE_DIR / f"{normalize_domain(domain)}.json"


def load_state(domain: str) -> dict[str, Any]:
    path = state_path(domain)
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def save_state(state: dict[str, Any]) -> None:
    state["updated_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
    atomic_write(state_path(str(state["domain"])), json.dumps(state, indent=2), 0o600)


def load_managed_states(*, configured_only: bool = False) -> list[dict[str, Any]]:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    states: list[dict[str, Any]] = []
    for path in sorted(STATE_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            domain = normalize_domain(str(data.get("domain", "")))
            identity = site_identity(domain)
            if path != state_path(domain):
                raise ValueError("nama file state tidak cocok dengan domain")
            for key, expected in identity.items():
                if data.get(key) != expected:
                    raise ValueError(f"identitas {key} tidak cocok")
            if not configured_only or data.get("configured"):
                states.append(data)
        except (OSError, json.JSONDecodeError):
            log(f"Mengabaikan state rusak: {path}")
        except (AgentError, ValueError) as exc:
            log(f"Mengabaikan state tidak aman {path}: {exc}")
    return states


def load_all_states() -> list[dict[str, Any]]:
    return load_managed_states(configured_only=True)


def render_manager_config(states: list[dict[str, Any]], register_cache: bool = True) -> str:
    lines = ["# Managed by BagoesWP OLS Manager. Do not edit manually.", ""]
    if register_cache:
        lines.extend(
            [
            "module cache {",
            "  internal                1",
            "  ls_enabled              1",
            "  storagePath             $SERVER_ROOT/cachedata",
            "  checkPrivateCache       1",
            "  checkPublicCache        1",
            "  maxCacheObjSize         10000000",
            "  enableCache             0",
            "  enablePrivateCache      0",
            "}",
            "",
            ]
        )
    lines.extend(
        [
            "listener BagoesHTTP {",
            "  address                 *:80",
            "  secure                  0",
        ]
    )
    for state in sorted(states, key=lambda item: item["domain"]):
        aliases = state["domain"]
        if state.get("include_www"):
            aliases += f", www.{state['domain']}"
        lines.append(f"  map                     {state['site_key']} {aliases}")
    lines.extend(["}", "", "listener BagoesHTTPS {", "  address                 *:443", "  secure                  1"])
    lines.extend(
        [
            "  keyFile                 /usr/local/lsws/conf/example.key",
            "  certFile                /usr/local/lsws/conf/example.crt",
            "  certChain               1",
        ]
    )
    for state in sorted(states, key=lambda item: item["domain"]):
        aliases = state["domain"]
        if state.get("include_www"):
            aliases += f", www.{state['domain']}"
        lines.append(f"  map                     {state['site_key']} {aliases}")
    lines.extend(["}", ""])
    for state in sorted(states, key=lambda item: item["domain"]):
        lines.extend(
            [
                f"virtualhost {state['site_key']} {{",
                f"  vhRoot                  /home/{state['linux_user']}/",
                f"  configFile              /usr/local/lsws/conf/vhosts/{state['site_key']}/vhost.conf",
                "  allowSymbolLink         1",
                "  enableScript            1",
                "  restrained              1",
                "  setUIDMode              2",
                "}",
                "",
            ]
        )
    return "\n".join(lines) + "\n"


def render_vhost_config(state: dict[str, Any], plan: dict[str, int]) -> str:
    domain = state["domain"]
    user = state["linux_user"]
    app = "lsphp83_" + state["site_key"]
    children = int(plan["php_children_per_site"])
    alias = f"www.{domain}" if state.get("include_www") else ""
    lines = [
        "# Managed by BagoesWP OLS Manager.",
        "docRoot                   $VH_ROOT/public_html/",
        f"vhDomain                  {domain}",
        f"adminEmails               {state.get('admin_email', 'root@localhost')}",
        "enableGzip                1",
        "",
        f"errorlog /home/{user}/logs/error.log {{",
        "  useServer               0",
        "  logLevel                WARN",
        "  rollingSize             10M",
        "  keepDays                14",
        "}",
        "",
        f"accesslog /home/{user}/logs/access.log {{",
        "  useServer               0",
        '  logFormat               "%v %h %l %u %t \\"%r\\" %>s %b"',
        "  rollingSize             10M",
        "  keepDays                14",
        "  compressArchive         1",
        "}",
        "",
        "index {",
        "  useServer               0",
        "  indexFiles              index.php, index.html",
        "}",
        "",
        "scripthandler {",
        f"  add                     lsapi:{app} php",
        "}",
        "",
        f"extprocessor {app} {{",
        "  type                    lsapi",
        f"  address                 {state['socket']}",
        f"  maxConns                {children}",
        f"  env                     PHP_LSAPI_CHILDREN={children}",
        "  env                     LSAPI_AVOID_FORK=200M",
        "  initTimeout             60",
        "  retryTimeout            0",
        "  persistConn             1",
        "  respBuffer              0",
        "  autoStart               1",
        "  path                    /usr/local/lsws/lsphp83/bin/lsphp",
        "  backlog                 100",
        "  instances               1",
        f"  extUser                 {user}",
        f"  extGroup                {user}",
        "  runOnStartUp            1",
        "  priority                0",
        "}",
        "",
        "module cache {",
        "  ls_enabled              1",
        "  storagePath             $VH_ROOT/lscache",
        "  checkPrivateCache       1",
        "  checkPublicCache        1",
        "}",
        "",
        "expires {",
        "  enableExpires           1",
        "  expiresByType           image/*=A15552000,text/css=A15552000,application/x-javascript=A15552000,application/javascript=A15552000,font/*=A15552000,application/x-font-ttf=A15552000",
        "}",
        "",
        "rewrite {",
        "  enable                  1",
        "  autoLoadHtaccess        1",
        "}",
    ]
    if alias:
        lines.insert(3, f"vhAliases                 {alias}")
    if state.get("ssl_active"):
        cert = f"/etc/letsencrypt/live/{domain}"
        lines.extend(
            [
                "",
                "vhssl {",
                f"  keyFile                 {cert}/privkey.pem",
                f"  certFile                {cert}/fullchain.pem",
                "  certChain               1",
                "}",
            ]
        )
    return "\n".join(lines) + "\n"


def ensure_managed_include() -> None:
    if not OLS_MAIN.exists():
        raise AgentError("ols_config", "httpd_config.conf OpenLiteSpeed tidak ditemukan")
    content = OLS_MAIN.read_text(encoding="utf-8")
    if MANAGED_INCLUDE in content:
        return
    if re.search(r"(?m)^\s*address\s+[^\n]*:(?:80|443)\s*$", content):
        raise AgentError(
            "ols_config",
            "Port 80/443 sudah dikelola konfigurasi OLS lain. Versi awal hanya untuk server baru.",
        )
    backup_file(OLS_MAIN)
    atomic_write(OLS_MAIN, content.rstrip() + "\n\n" + MANAGED_INCLUDE + "\n", 0o600)


def parse_ols_server_identity(content: str) -> tuple[str, str]:
    user_match = re.search(
        r"(?im)^\s*user\s+([A-Za-z_][A-Za-z0-9_-]*)\s*(?:#.*)?$", content
    )
    group_match = re.search(
        r"(?im)^\s*group\s+([A-Za-z_][A-Za-z0-9_-]*)\s*(?:#.*)?$", content
    )
    if not user_match:
        raise AgentError("ols_config", "User proses OpenLiteSpeed tidak ditemukan")
    user = user_match.group(1)
    group = group_match.group(1) if group_match else ""
    return user, group


def repair_packaged_example_ownership() -> dict[str, Any]:
    """Normalize only the document root shipped with the OLS example vhost."""
    example_base = OLS_ROOT / "Example"
    document_root = example_base / "html"
    if not document_root.exists():
        return {"present": False, "changed": False}
    if document_root.is_symlink() or not document_root.is_dir():
        raise AgentError("ols_config", f"Document root Example tidak aman: {document_root}")
    try:
        document_root.resolve().relative_to(example_base.resolve())
    except ValueError as exc:
        raise AgentError("ols_config", "Document root Example keluar dari allowlist") from exc
    content = OLS_MAIN.read_text(encoding="utf-8")
    user_name, group_name = parse_ols_server_identity(content)
    try:
        user_entry = pwd.getpwnam(user_name)
        group_id = grp.getgrnam(group_name).gr_gid if group_name else user_entry.pw_gid
    except KeyError as exc:
        raise AgentError("ols_config", f"User/group proses OLS tidak tersedia: {exc}") from exc
    if user_entry.pw_uid < 11 or group_id < 10:
        raise AgentError(
            "ols_config",
            f"User/group proses OLS tidak aman: uid={user_entry.pw_uid}, gid={group_id}",
        )
    before = document_root.stat()
    changed = before.st_uid != user_entry.pw_uid or before.st_gid != group_id
    if changed:
        os.chown(document_root, user_entry.pw_uid, group_id)
        after = document_root.stat()
        if after.st_uid != user_entry.pw_uid or after.st_gid != group_id:
            raise AgentError("ols_config", "Ownership document root Example gagal diperbaiki")
        log(
            "Memperbaiki ownership vhost Example bawaan OLS ke "
            f"{user_name}:{group_name or group_id}"
        )
    return {
        "present": True,
        "changed": changed,
        "user": user_name,
        "group": group_name or str(group_id),
    }


def only_known_example_ownership_warnings(output: str) -> bool:
    warning_lines = [line for line in output.splitlines() if "[WARN]" in line]
    if not warning_lines or re.search(r"\[(?:ERROR|FATAL)\]", output, re.IGNORECASE):
        return False
    pattern = re.compile(
        r"\[config:server:vhosts:vhost:Example\].*"
        r"(?:Uid|Gid) of /usr/local/lsws/Example/html/.*"
        r"use server (?:uid|gid)!",
        re.IGNORECASE,
    )
    return all(pattern.search(line) for line in warning_lines)


def config_test() -> None:
    binary = OLS_ROOT / "bin/openlitespeed"
    if not binary.exists():
        raise AgentError("ols_config", "Binary OpenLiteSpeed tidak ditemukan")
    repair_packaged_example_ownership()
    result = run([str(binary), "-t"], check=False, quiet=True)
    combined = (result.stdout + "\n" + result.stderr).strip()
    if result.returncode != 0:
        if only_known_example_ownership_warnings(combined):
            log("Config-test OLS hanya menghasilkan warning ownership vhost Example; dilanjutkan")
            return
        raise AgentError("ols_config", "Validasi konfigurasi OLS gagal: " + combined)


def tune_ols_workers(workers: int) -> None:
    if not OLS_DEFAULTS.exists():
        return
    content = OLS_DEFAULTS.read_text(encoding="utf-8")
    updated, count = re.subn(
        r"(?im)^\s*httpdworkers\s+\d+\s*$", f"httpdworkers {workers}", content
    )
    if count and updated != content:
        backup_file(OLS_DEFAULTS)
        atomic_write(OLS_DEFAULTS, updated, 0o600)


def apply_ols_config() -> dict[str, int]:
    if not OLS_MAIN.exists():
        raise AgentError("ols_config", "httpd_config.conf OpenLiteSpeed tidak ditemukan")
    states = load_all_states()
    plan = effective_resource_plan(memory_mb(), os.cpu_count() or 1, len(states))
    main_before = OLS_MAIN.read_text(encoding="utf-8")
    had_managed_include = MANAGED_INCLUDE in main_before
    MANAGED_DIR.mkdir(parents=True, exist_ok=True)
    manager_backup = backup_file(MANAGED_CONF)
    old_vhosts: dict[Path, str] = {}
    new_vhosts: list[Path] = []
    defaults_before = OLS_DEFAULTS.read_text(encoding="utf-8") if OLS_DEFAULTS.exists() else None
    try:
        ensure_managed_include()
        main_content = OLS_MAIN.read_text(encoding="utf-8")
        register_cache = not bool(re.search(r"(?im)^\s*module\s+cache\s*\{", main_content))
        atomic_write(MANAGED_CONF, render_manager_config(states, register_cache), 0o600)
        for state in states:
            vhost_path = OLS_ROOT / "conf/vhosts" / state["site_key"] / "vhost.conf"
            if vhost_path.exists():
                old_vhosts[vhost_path] = vhost_path.read_text(encoding="utf-8")
            else:
                new_vhosts.append(vhost_path)
            atomic_write(vhost_path, render_vhost_config(state, plan), 0o640)
            shutil.chown(vhost_path.parent, user="lsadm", group="lsadm")
            shutil.chown(vhost_path, user="lsadm", group="lsadm")
        tune_ols_workers(plan["ols_workers"])
        config_test()
        run([str(OLS_ROOT / "bin/lswsctrl"), "restart"], timeout=120)
        run(["systemctl", "is-active", "--quiet", "lsws"], timeout=30)
        return plan
    except Exception:
        if manager_backup and manager_backup.exists():
            shutil.copy2(manager_backup, MANAGED_CONF)
        else:
            register_cache = not bool(re.search(r"(?im)^\s*module\s+cache\s*\{", main_before))
            atomic_write(MANAGED_CONF, render_manager_config([], register_cache), 0o600)
        for path, content in old_vhosts.items():
            atomic_write(path, content, 0o640)
        for path in new_vhosts:
            with contextlib.suppress(FileNotFoundError):
                path.unlink()
        if defaults_before is not None:
            atomic_write(OLS_DEFAULTS, defaults_before, 0o600)
        if not had_managed_include:
            atomic_write(OLS_MAIN, main_before, 0o600)
        with contextlib.suppress(Exception):
            run([str(OLS_ROOT / "bin/lswsctrl"), "restart"], check=False, quiet=True)
        raise


def package_available(package: str) -> bool:
    result = run(["apt-cache", "show", package], check=False, quiet=True)
    return result.returncode == 0 and bool(result.stdout.strip())


def select_packages(
    required: list[str], optional: list[str], available: set[str]
) -> tuple[list[str], list[str]]:
    """Return installable packages and unavailable required packages.

    LiteSpeed periodically changes whether a PHP extension is bundled in
    ``lsphpXX-common`` or published as a separate package. Only the small core
    package set is therefore mandatory by package name; extensions are proven
    later from the actual PHP runtime.
    """
    missing = [package for package in required if package not in available]
    selected = [package for package in required if package in available]
    selected.extend(package for package in optional if package in available)
    return selected, missing


def install_packages(required: list[str], optional: list[str]) -> list[str]:
    candidates = list(dict.fromkeys([*required, *optional]))
    available = {package for package in candidates if package_available(package)}
    selected, missing = select_packages(required, optional, available)
    if missing:
        raise AgentError("packages", "Paket wajib tidak tersedia: " + ", ".join(missing))
    if not selected:
        return []
    run(
        ["apt-get", "install", "-y", "--no-install-recommends", *selected],
        timeout=1800,
        env={"DEBIAN_FRONTEND": "noninteractive"},
    )
    return selected


def ensure_litespeed_repository() -> None:
    """Install/refresh the official LiteSpeed repository idempotently.

    Checking only ``openlitespeed`` is insufficient: an existing OLS package
    can be visible while the LSPHP extension metadata is absent or stale.
    """
    repo_script = Path("/tmp/litespeed-repo.sh")
    try:
        run(
            ["curl", "-fsSL", "https://repo.litespeed.sh", "-o", str(repo_script)],
            timeout=300,
        )
        if not repo_script.exists() or repo_script.stat().st_size == 0:
            raise AgentError("repository", "Script repository LiteSpeed kosong")
        os.chmod(repo_script, 0o700)
        run(["bash", str(repo_script)], timeout=600)
        run(
            ["apt-get", "update"],
            timeout=1200,
            env={"DEBIAN_FRONTEND": "noninteractive"},
        )
    finally:
        with contextlib.suppress(FileNotFoundError):
            repo_script.unlink()


def install_litespeed_stack() -> list[str]:
    required = [
        "openlitespeed",
        "lsphp83",
        "lsphp83-common",
        "lsphp83-mysql",
        "lsphp83-curl",
        "lsphp83-opcache",
        "lsphp83-redis",
    ]
    optional = [
        "lsphp83-gd",
        "lsphp83-imagick",
        "lsphp83-intl",
        "lsphp83-mbstring",
        "lsphp83-xml",
        "lsphp83-zip",
    ]
    last_error: AgentError | None = None
    for attempt in range(2):
        ensure_litespeed_repository()
        try:
            return install_packages(required, optional)
        except AgentError as exc:
            last_error = exc
            if exc.stage != "packages" or attempt == 1:
                raise
            log("Metadata paket LiteSpeed belum lengkap; menyegarkan repository sekali lagi")
    assert last_error is not None
    raise last_error


def tune_mariadb(plan: dict[str, int]) -> None:
    path = Path("/etc/mysql/mariadb.conf.d/60-bagoeswp.cnf")
    php_connections = (
        plan["site_count"] * plan["php_children_per_site"] * plan["ols_workers"]
    )
    max_connections = max(50, min(300, php_connections * 2 + 20))
    temp_table_mb = max(16, min(64, plan["mariadb_mb"] // 16))
    content = f"""# Managed by BagoesWP OLS Manager
[mysqld]
innodb_buffer_pool_size={plan['mariadb_mb']}M
max_connections={max_connections}
thread_cache_size=32
table_open_cache=2000
tmp_table_size={temp_table_mb}M
max_heap_table_size={temp_table_mb}M
slow_query_log=1
long_query_time=2
slow_query_log_file=/var/log/mysql/bagoeswp-slow.log
skip_name_resolve=1
"""
    atomic_write(path, content, 0o644)
    run(["systemctl", "restart", "mariadb"], timeout=120)
    result = run(["mariadb", "--protocol=socket", "-Nse", "SELECT 1"], quiet=True)
    if result.stdout.strip() != "1":
        raise AgentError("mariadb", "MariaDB socket test gagal")


def tune_redis(plan: dict[str, int]) -> None:
    main = Path("/etc/redis/redis.conf")
    include = Path("/etc/redis/bagoeswp.conf")
    atomic_write(
        include,
        "\n".join(
            [
                "# Managed by BagoesWP OLS Manager",
                "bind 127.0.0.1 ::1",
                "protected-mode yes",
                f"maxmemory {plan['redis_mb']}mb",
                "maxmemory-policy allkeys-lru",
                'save ""',
                "appendonly no",
                "",
            ]
        ),
        0o640,
    )
    shutil.chown(include, user="redis", group="redis")
    if main.exists():
        content = main.read_text(encoding="utf-8")
        marker = "include /etc/redis/bagoeswp.conf"
        if marker not in content:
            backup_file(main)
            atomic_write(main, content.rstrip() + "\n" + marker + "\n", 0o640)
    run(["systemctl", "restart", "redis-server"], timeout=120)
    pong = run(["redis-cli", "ping"], quiet=True).stdout.strip()
    if pong != "PONG":
        raise AgentError("redis", "Redis tidak menjawab PONG")


def tune_php(plan: dict[str, int]) -> None:
    ini = run([str(PHP_BIN), "--ini"], timeout=60, quiet=True)
    match = re.search(r"Scan for additional \.ini files in:\s*(\S+)", ini.stdout)
    if not match or match.group(1).lower() == "(none)":
        raise AgentError("php_tuning", "Direktori conf.d LSPHP tidak ditemukan")
    directory = Path(match.group(1))
    if not directory.is_dir():
        raise AgentError("php_tuning", f"Direktori conf.d LSPHP tidak ada: {directory}")
    content = "\n".join(
        [
            "; Managed by BagoesWP OLS Manager",
            "opcache.enable=1",
            "opcache.enable_cli=0",
            f"opcache.memory_consumption={plan['opcache_mb_per_site']}",
            "opcache.interned_strings_buffer=16",
            "opcache.max_accelerated_files=30000",
            "opcache.validate_timestamps=1",
            "opcache.revalidate_freq=60",
            "opcache.save_comments=1",
            "opcache.jit=0",
            "realpath_cache_size=4096K",
            "realpath_cache_ttl=600",
            f"memory_limit={plan['php_process_memory_mb']}M",
            "expose_php=Off",
            "max_execution_time=120",
            "",
        ]
    )
    atomic_write(directory / "99-bagoeswp.ini", content, 0o644)


def install_wp_cli() -> None:
    if WP_CLI.exists():
        result = run([str(PHP_BIN), str(WP_CLI), "--info"], check=False, quiet=True)
        if result.returncode == 0:
            return
    temp = Path("/tmp/wp-cli.phar")
    run(
        [
            "curl",
            "-fsSL",
            "https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar",
            "-o",
            str(temp),
        ],
        timeout=300,
    )
    run([str(PHP_BIN), str(temp), "--info"], timeout=60)
    os.chmod(temp, 0o755)
    os.replace(temp, WP_CLI)


def php_runtime_checks(modules: set[str], opcache_enabled: bool) -> dict[str, bool]:
    normalized = {module.strip().lower() for module in modules}
    return {
        "mysqli": "mysqli" in normalized,
        "curl": "curl" in normalized,
        "mbstring": "mbstring" in normalized,
        "redis": "redis" in normalized,
        "xml": "xml" in normalized,
        "zip": "zip" in normalized,
        "image_processing": "gd" in normalized or "imagick" in normalized,
        "opcache": "zend opcache" in normalized,
        "opcache_enabled": opcache_enabled,
    }


def read_php_runtime_checks() -> dict[str, bool]:
    result = run([str(PHP_BIN), "-m"], timeout=60, quiet=True)
    modules = {line.strip().lower() for line in result.stdout.splitlines() if line.strip()}
    opcache_setting = run(
        [str(PHP_BIN), "-r", "echo (string) ini_get('opcache.enable');"],
        check=False,
        timeout=60,
        quiet=True,
    )
    return php_runtime_checks(
        modules,
        opcache_setting.returncode == 0 and opcache_setting.stdout.strip() == "1",
    )


def verify_php_runtime() -> dict[str, bool]:
    checks = read_php_runtime_checks()
    missing = [name for name, present in checks.items() if not present]
    extension_packages = {
        "mbstring": ["lsphp83-mbstring"],
        "xml": ["lsphp83-xml"],
        "zip": ["lsphp83-zip"],
        "image_processing": ["lsphp83-gd", "lsphp83-imagick"],
        "opcache": ["lsphp83-opcache"],
        "redis": ["lsphp83-redis"],
        "curl": ["lsphp83-curl"],
        "mysqli": ["lsphp83-mysql"],
    }
    repair_candidates = list(
        dict.fromkeys(
            package
            for name in missing
            for package in extension_packages.get(name, [])
        )
    )
    repair = [package for package in repair_candidates if package_available(package)]
    if repair:
        log("Memperbaiki ekstensi LSPHP runtime: " + ", ".join(repair))
        install_packages([], repair)
        checks = read_php_runtime_checks()
        missing = [name for name, present in checks.items() if not present]
    if missing:
        raise AgentError(
            "php_runtime",
            "Ekstensi LSPHP wajib tidak aktif setelah pemasangan repository resmi: "
            + ", ".join(missing),
        )
    return checks


def ensure_fallback_certificate() -> None:
    key = OLS_ROOT / "conf/example.key"
    cert = OLS_ROOT / "conf/example.crt"
    if key.exists() and cert.exists():
        return
    run(
        [
            "openssl",
            "req",
            "-x509",
            "-nodes",
            "-newkey",
            "rsa:2048",
            "-days",
            "30",
            "-subj",
            "/CN=localhost",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        timeout=120,
        quiet=True,
    )
    os.chmod(key, 0o600)
    os.chmod(cert, 0o644)


def install_certbot_hook() -> None:
    hook = Path("/etc/letsencrypt/renewal-hooks/deploy/bagoeswp-restart-ols")
    atomic_write(
        hook,
        "#!/bin/sh\nexec /usr/local/lsws/bin/lswsctrl restart\n",
        0o750,
    )


def install_service_units() -> None:
    PERSISTENT_AGENT.parent.mkdir(parents=True, exist_ok=True)
    source = Path(__file__).resolve()
    if source != PERSISTENT_AGENT:
        shutil.copy2(source, PERSISTENT_AGENT)
        os.chmod(PERSISTENT_AGENT, 0o700)
    units = {
        "/etc/systemd/system/bagoeswp-maintenance.service": """[Unit]
Description=BagoesWP safe WordPress maintenance
After=network.target mariadb.service redis-server.service lsws.service

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/local/lib/bagoeswp/remote_agent.py maintenance
Nice=10
IOSchedulingClass=idle
""",
        "/etc/systemd/system/bagoeswp-maintenance.timer": """[Unit]
Description=Run BagoesWP maintenance every 30 minutes

[Timer]
OnBootSec=15min
OnUnitActiveSec=30min
Persistent=true
RandomizedDelaySec=120

[Install]
WantedBy=timers.target
""",
        "/etc/systemd/system/bagoeswp-wpcron.service": """[Unit]
Description=Run due WordPress cron events for BagoesWP sites
After=mariadb.service redis-server.service

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/local/lib/bagoeswp/remote_agent.py wpcron
Nice=10
IOSchedulingClass=idle
""",
        "/etc/systemd/system/bagoeswp-wpcron.timer": """[Unit]
Description=Run BagoesWP WordPress cron every 5 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=5min
Persistent=true
RandomizedDelaySec=30

[Install]
WantedBy=timers.target
""",
        "/etc/systemd/system/bagoeswp-monitor.service": """[Unit]
Description=Run BagoesWP health monitor
After=network.target mariadb.service redis-server.service lsws.service

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/local/lib/bagoeswp/remote_agent.py monitor
Nice=10
IOSchedulingClass=idle
""",
        "/etc/systemd/system/bagoeswp-monitor.timer": """[Unit]
Description=Run BagoesWP health monitor hourly

[Timer]
OnBootSec=20min
OnUnitActiveSec=1h
Persistent=true
RandomizedDelaySec=180

[Install]
WantedBy=timers.target
""",
    }
    for name, content in units.items():
        atomic_write(Path(name), content, 0o644)
    run(["systemctl", "daemon-reload"])
    run(
        [
            "systemctl",
            "enable",
            "--now",
            "bagoeswp-maintenance.timer",
            "bagoeswp-wpcron.timer",
            "bagoeswp-monitor.timer",
        ]
    )


def canonical_systemd_unit(unit: str) -> str:
    result = run(
        ["systemctl", "show", "--property=Id", "--value", unit],
        check=False,
        timeout=30,
        quiet=True,
    )
    canonical = result.stdout.strip()
    if result.returncode == 0 and canonical and canonical != unit:
        return canonical
    fragment = run(
        ["systemctl", "show", "--property=FragmentPath", "--value", unit],
        check=False,
        timeout=30,
        quiet=True,
    )
    fragment_path = Path(fragment.stdout.strip()) if fragment.returncode == 0 else Path()
    if fragment_path.is_absolute() and fragment_path.exists():
        resolved_name = fragment_path.resolve().name
        if resolved_name.endswith(".service"):
            return resolved_name
    return canonical or unit


def enable_and_start_service(unit: str) -> str:
    """Enable a canonical unit but start/check through the requested alias."""
    canonical = canonical_systemd_unit(unit)
    run(["systemctl", "enable", canonical], timeout=120)
    run(["systemctl", "start", unit], timeout=120)
    active = run(
        ["systemctl", "is-active", "--quiet", unit],
        check=False,
        timeout=30,
        quiet=True,
    )
    if active.returncode != 0:
        raise AgentError("services", f"Service tidak aktif setelah dijalankan: {unit}")
    return canonical


def preflight() -> dict[str, Any]:
    release = read_os_release()
    warnings: list[str] = []
    if os.geteuid() != 0:
        raise AgentError("preflight", "Agent harus dijalankan sebagai root/sudo")
    if release.get("ID") != "ubuntu" or not release.get("VERSION_ID", "").startswith("24.04"):
        raise AgentError("preflight", "Versi awal hanya mendukung Ubuntu 24.04")
    resources = system_snapshot()
    mem = int(resources["memory_total_mb"])
    if mem < 2048:
        raise AgentError("preflight", "Minimal RAM 2 GB agar OLS, PHP, MariaDB, dan Redis tidak dipaksa oversubscribe")
    if float(resources["disk_free_gib"]) < 10.0:
        warnings.append("Disk kosong di bawah 10 GiB")
    if int(resources["swap_total_mb"]) == 0:
        warnings.append("Swap tidak tersedia; lonjakan PHP memiliki bantalan memori lebih kecil")
    return {
        "status": "ok",
        "agent_version": VERSION,
        "os": release.get("PRETTY_NAME", "Ubuntu 24.04"),
        "memory_mb": mem,
        **resources,
        "warnings": warnings,
    }


def bootstrap() -> dict[str, Any]:
    pre = preflight()
    with global_lock():
        BASE.mkdir(parents=True, exist_ok=True)
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        run(["apt-get", "update"], timeout=1200, env={"DEBIAN_FRONTEND": "noninteractive"})
        base_required = [
            "ca-certificates",
            "curl",
            "unzip",
            "openssl",
            "mariadb-server",
            "redis-server",
            "certbot",
        ]
        install_packages(base_required, ["fail2ban", "ufw"])
        installed_litespeed_packages = install_litespeed_stack()
        enabled_units = {
            service: enable_and_start_service(service)
            for service in ("lsws", "mariadb", "redis-server")
        }
        install_wp_cli()
        states = load_all_states()
        plan = effective_resource_plan(memory_mb(), os.cpu_count() or 1, len(states) or 1)
        tune_mariadb(plan)
        tune_redis(plan)
        tune_php(plan)
        verify_php_runtime()
        ensure_fallback_certificate()
        plan = apply_ols_config()
        install_certbot_hook()
        install_service_units()
    return {
        "status": "ok",
        "stage": "bootstrap",
        "preflight": pre,
        "plan": plan,
        "litespeed_packages": installed_litespeed_packages,
        "enabled_units": enabled_units,
    }


def ensure_linux_user(state: dict[str, Any]) -> None:
    user = state["linux_user"]
    result = run(["id", "-u", user], check=False, quiet=True)
    if result.returncode != 0:
        run(["useradd", "--create-home", "--home-dir", f"/home/{user}", "--shell", "/usr/sbin/nologin", user])
    uid = int(run(["id", "-u", user], quiet=True).stdout.strip())
    if uid == 0:
        raise AgentError("ownership", "Document root tidak boleh dimiliki UID 0/root")
    for name in ("public_html", "logs", "lscache", ".wp-cli/cache"):
        path = Path(f"/home/{user}") / name
        path.mkdir(parents=True, exist_ok=True)
        shutil.chown(path, user=user, group=user)
    os.chmod(f"/home/{user}", 0o711)
    os.chmod(f"/home/{user}/public_html", 0o755)


def ensure_database(state: dict[str, Any]) -> None:
    db_name = state["db_name"]
    db_user = state["db_user"]
    password = state["db_password"]
    sql = (
        f"CREATE DATABASE IF NOT EXISTS `{db_name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
        f"CREATE USER IF NOT EXISTS '{db_user}'@'localhost' IDENTIFIED BY '{password}';"
        f"ALTER USER '{db_user}'@'localhost' IDENTIFIED BY '{password}';"
        f"GRANT ALL PRIVILEGES ON `{db_name}`.* TO '{db_user}'@'localhost';"
        "FLUSH PRIVILEGES;"
    )
    run(["mariadb", "--protocol=socket"], input_text=sql, timeout=60, quiet=True)
    test = run(
        ["mariadb", "--protocol=socket", f"-u{db_user}", "-Nse", "SELECT 1", db_name],
        env={"MYSQL_PWD": password},
        quiet=True,
    )
    if test.stdout.strip() != "1":
        raise AgentError("database", "Database user tidak dapat mengakses database domain")


def wp_command(
    state: dict[str, Any],
    args: list[str],
    *,
    input_text: str | None = None,
    check: bool = True,
    quiet: bool = False,
) -> subprocess.CompletedProcess[str]:
    user = state["linux_user"]
    root = f"/home/{user}/public_html"
    env = {"WP_CLI_CACHE_DIR": f"/home/{user}/.wp-cli/cache", "HOME": f"/home/{user}"}
    command = [
        "runuser",
        "-u",
        user,
        "--",
        str(PHP_BIN),
        str(WP_CLI),
        *args,
        f"--path={root}",
        "--no-color",
    ]
    return run(command, input_text=input_text, check=check, timeout=600, env=env, quiet=quiet)


def ensure_wordpress(state: dict[str, Any], payload: dict[str, Any]) -> None:
    root = Path(f"/home/{state['linux_user']}/public_html")
    if not (root / "wp-load.php").exists():
        wp_command(state, ["core", "download", f"--locale={payload['locale']}"])
    if not (root / "wp-config.php").exists():
        wp_command(
            state,
            [
                "config",
                "create",
                f"--dbname={state['db_name']}",
                f"--dbuser={state['db_user']}",
                "--dbhost=localhost",
                "--dbcharset=utf8mb4",
                "--prompt=dbpass",
            ],
            input_text=state["db_password"] + "\n",
        )
        wp_command(state, ["config", "shuffle-salts"])
    installed = wp_command(state, ["core", "is-installed"], check=False, quiet=True).returncode == 0
    if not installed:
        wp_command(
            state,
            [
                "core",
                "install",
                f"--url=http://{state['domain']}",
                f"--title={payload['title']}",
                f"--admin_user={payload['admin_user']}",
                f"--admin_email={payload['admin_email']}",
                "--skip-email",
                "--prompt=admin_password",
            ],
            input_text=str(payload["admin_password"]) + "\n",
        )
    constants = [
        ("WP_CACHE", "true", True),
        ("WP_CACHE_KEY_SALT", state["domain"] + ":", False),
        ("WP_REDIS_HOST", "127.0.0.1", False),
        ("WP_REDIS_PORT", "6379", True),
        ("WP_REDIS_PREFIX", "bagoeswp:" + state["domain"] + ":", False),
        ("DISABLE_WP_CRON", "true", True),
        ("WP_POST_REVISIONS", "10", True),
        ("EMPTY_TRASH_DAYS", "14", True),
        ("AUTOSAVE_INTERVAL", "180", True),
    ]
    for key, value, raw in constants:
        args = ["config", "set", key, value]
        if raw:
            args.append("--raw")
        wp_command(state, args)
    wp_command(state, ["plugin", "install", "litespeed-cache", "--activate"])
    wp_command(state, ["plugin", "install", "redis-cache", "--activate"])
    wp_command(state, ["redis", "enable"], check=False)
    wp_command(state, ["option", "update", "permalink_structure", "/%postname%/"])
    wp_command(state, ["rewrite", "flush", "--hard"])
    htaccess = root / ".htaccess"
    ensure_wordpress_rewrite_rules(htaccess)
    health_asset = root / "wp-content/bagoeswp-health.css"
    atomic_write(health_asset, "/* Managed browser-cache probe for BagoesWP. */\n", 0o644)
    shutil.chown(health_asset, user=state["linux_user"], group=state["linux_user"])
    for path in (root, root / "wp-config.php", htaccess):
        shutil.chown(path, user=state["linux_user"], group=state["linux_user"])
    os.chmod(root, 0o755)
    os.chmod(root / "wp-config.php", 0o640)
    os.chmod(htaccess, 0o644)


def configure_site(state: dict[str, Any]) -> dict[str, int]:
    with global_lock():
        was_configured = bool(state.get("configured"))
        state["configured"] = True
        save_state(state)
        try:
            return apply_ols_config()
        except Exception:
            state["configured"] = was_configured
            save_state(state)
            with contextlib.suppress(Exception):
                apply_ols_config()
            raise


def reserve_site_capacity(state: dict[str, Any]) -> dict[str, int]:
    """Reserve a site's PHP budget before provisioning, including parallel jobs."""
    with global_lock():
        reserved = {
            str(item['domain']): item
            for item in load_managed_states()
            if item.get('configured') or item.get('status') == 'RUNNING'
        }
        reserved[str(state['domain'])] = state
        plan = effective_resource_plan(memory_mb(), os.cpu_count() or 1, len(reserved))
        # Keep existing websites repairable after a resource downgrade. Do not
        # admit additional sites to an already oversubscribed machine.
        if not state.get('configured') and not plan['capacity_ok']:
            raise AgentError(
                'capacity',
                f"Kapasitas PHP tidak cukup: {len(reserved)} situs membutuhkan perkiraan "
                f"{plan['php_estimated_mb']} MiB, anggaran {plan['php_budget_mb']} MiB. "
                f"Batas awal {plan['max_safe_sites']} situs; tambah RAM atau kurangi situs aktif.",
            )
        save_state(state)
        return plan


def public_probe(host: str, token: str) -> bool:
    url = f"http://{host}/.well-known/acme-challenge/bagoeswp-probe"
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "BagoesWP-SSL-Probe/1"})
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status == 200 and response.read().decode("utf-8", "replace").strip() == token
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def ensure_wordpress_rewrite_rules(path: Path) -> bool:
    """Install the canonical single-site WordPress rewrite block idempotently.

    WP-CLI can report a successful hard flush without writing .htaccess when
    the Apache rewrite module is not loaded in its CLI process. OpenLiteSpeed
    still consumes these compatible rules through autoLoadHtaccess.
    """
    begin = "# BEGIN WordPress"
    end = "# END WordPress"
    block = "\n".join(
        [
            begin,
            "<IfModule mod_rewrite.c>",
            "RewriteEngine On",
            "RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]",
            "RewriteBase /",
            r"RewriteRule ^index\.php$ - [L]",
            "RewriteCond %{REQUEST_FILENAME} !-f",
            "RewriteCond %{REQUEST_FILENAME} !-d",
            "RewriteRule . /index.php [L]",
            "</IfModule>",
            end,
            "",
        ]
    )
    content = path.read_text(encoding="utf-8") if path.exists() else ""
    managed = re.compile(
        rf"(?ms)^{re.escape(begin)}\s*$.*?^{re.escape(end)}\s*$\n?"
    )
    if managed.search(content):
        updated = managed.sub(block, content, count=1)
    else:
        prefix = content.rstrip()
        updated = (prefix + "\n\n" if prefix else "") + block
    if updated == content:
        return False
    atomic_write(path, updated, 0o644)
    return True


def add_https_redirect(path: Path) -> None:
    begin = "# BEGIN BagoesWP HTTPS"
    block = "\n".join(
        [
            begin,
            "<IfModule mod_rewrite.c>",
            "RewriteEngine On",
            "RewriteCond %{HTTPS} !=on",
            "RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]",
            "</IfModule>",
            "# END BagoesWP HTTPS",
            "",
        ]
    )
    content = path.read_text(encoding="utf-8") if path.exists() else ""
    if begin not in content:
        atomic_write(path, block + content, 0o644)


def try_ssl(state: dict[str, Any]) -> bool:
    if not state.get("enable_ssl"):
        return False
    root = Path(f"/home/{state['linux_user']}/public_html")
    challenge = root / ".well-known/acme-challenge"
    challenge.mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(18)
    probe = challenge / "bagoeswp-probe"
    atomic_write(probe, token + "\n", 0o644)
    run(["chown", "-R", f"{state['linux_user']}:{state['linux_user']}", str(root / ".well-known")])
    hosts = [state["domain"]]
    if state.get("include_www"):
        hosts.append("www." + state["domain"])
    ready = all(public_probe(host, token) for host in hosts)
    with contextlib.suppress(FileNotFoundError):
        probe.unlink()
    if not ready:
        reason = "DNS/proxy belum mengarah ke website pada VPS"
        if state.get("ssl_active"):
            state["ssl_renewal_error"] = reason
        else:
            state["ssl_active"] = False
            state["ssl_pending_reason"] = reason
        save_state(state)
        return bool(state.get("ssl_active"))
    command = [
        "certbot",
        "certonly",
        "--webroot",
        "--non-interactive",
        "--agree-tos",
        "--keep-until-expiring",
        "--cert-name",
        state["domain"],
        "--email",
        state["admin_email"],
        "-w",
        str(root),
    ]
    for host in hosts:
        command.extend(["-d", host])
    result = run(command, check=False, timeout=600)
    if result.returncode != 0:
        reason = (result.stderr or result.stdout).strip()[-500:]
        if state.get("ssl_active"):
            state["ssl_renewal_error"] = reason
        else:
            state["ssl_active"] = False
            state["ssl_pending_reason"] = reason
        save_state(state)
        return bool(state.get("ssl_active"))
    state["ssl_active"] = True
    state.pop("ssl_pending_reason", None)
    state.pop("ssl_renewal_error", None)
    save_state(state)
    wp_command(state, ["option", "update", "home", f"https://{state['domain']}"])
    wp_command(state, ["option", "update", "siteurl", f"https://{state['domain']}"])
    ensure_wordpress_rewrite_rules(root / ".htaccess")
    add_https_redirect(root / ".htaccess")
    shutil.chown(root / ".htaccess", user=state["linux_user"], group=state["linux_user"])
    # Reload only after both the SSL vhost and .htaccess redirect are ready.
    with global_lock():
        apply_ols_config()
    return True


def local_request(
    state: dict[str, Any],
    path: str = "/",
    *,
    force_http: bool = False,
    timeout: float = 15.0,
) -> dict[str, Any]:
    """Request the local OLS listener while preserving Host and TLS SNI."""
    use_tls = bool(state.get("ssl_active")) and not force_http
    port = 443 if use_tls else 80
    started = time.perf_counter()
    raw_socket = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    connection: socket.socket = raw_socket
    try:
        if use_tls:
            context = ssl.create_default_context()
            connection = context.wrap_socket(raw_socket, server_hostname=str(state["domain"]))
        else:
            connection = raw_socket
        connection.settimeout(timeout)
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {state['domain']}\r\n"
            "User-Agent: BagoesWP-Health/2\r\n"
            "Accept: */*\r\n"
            "Accept-Encoding: gzip, br\r\n"
            "Connection: close\r\n\r\n"
        )
        connection.sendall(request.encode("ascii"))
        response = http.client.HTTPResponse(connection)
        response.begin()
        headers = {key.lower(): value for key, value in response.getheaders()}
        body = response.read(512 * 1024)
        return {
            "status": int(response.status),
            "headers": headers,
            "bytes": len(body),
            "latency_ms": round((time.perf_counter() - started) * 1000, 3),
        }
    finally:
        with contextlib.suppress(Exception):
            connection.close()
        with contextlib.suppress(Exception):
            raw_socket.close()


def validate_ssl_certificate(state: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "active": bool(state.get("ssl_active")),
        "valid": False,
        "hostname_valid": False,
        "days_remaining": None,
        "hosts": {},
        "error": "",
    }
    if not state.get("ssl_active"):
        result["error"] = str(state.get("ssl_pending_reason", "SSL belum aktif"))
        return result
    try:
        context = ssl.create_default_context()
        hosts = [str(state["domain"])]
        if state.get("include_www"):
            hosts.append("www." + str(state["domain"]))
        remaining_values: list[float] = []
        for host in hosts:
            with socket.create_connection(("127.0.0.1", 443), timeout=15) as raw:
                with context.wrap_socket(raw, server_hostname=host) as tls:
                    certificate = tls.getpeercert()
            expires = ssl.cert_time_to_seconds(str(certificate["notAfter"]))
            remaining = max(0.0, (expires - time.time()) / 86400)
            remaining_values.append(remaining)
            result["hosts"][host] = {"valid": remaining > 0, "days_remaining": round(remaining, 1)}
        minimum_remaining = min(remaining_values)
        result.update(
            {
                "valid": minimum_remaining > 0,
                "hostname_valid": True,
                "days_remaining": round(minimum_remaining, 1),
            }
        )
    except (OSError, ssl.SSLError, KeyError, ValueError) as exc:
        result["error"] = str(exc)[:300]
    return result


def cloudflare_probe(state: dict[str, Any]) -> dict[str, Any]:
    scheme = "https" if state.get("ssl_active") else "http"
    request = urllib.request.Request(
        f"{scheme}://{state['domain']}/",
        headers={"User-Agent": "BagoesWP-Cloudflare-Probe/2"},
    )
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            headers = {key.lower(): value for key, value in response.headers.items()}
            return {
                "reachable": True,
                "detected": "cf-ray" in headers or headers.get("server", "").lower() == "cloudflare",
                "cf_cache_status": headers.get("cf-cache-status", ""),
            }
    except urllib.error.HTTPError as exc:
        headers = {key.lower(): value for key, value in exc.headers.items()}
        return {
            "reachable": True,
            "detected": "cf-ray" in headers or headers.get("server", "").lower() == "cloudflare",
            "cf_cache_status": headers.get("cf-cache-status", ""),
            "http_status": exc.code,
        }
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {"reachable": False, "detected": False, "error": str(exc)[:200]}


def wordpress_health(state: dict[str, Any]) -> dict[str, Any]:
    permalink = wp_command(
        state, ["option", "get", "permalink_structure"], check=False, quiet=True
    )
    database = wp_command(
        state, ["db", "query", "SELECT 1;", "--skip-column-names"], check=False, quiet=True
    )
    cron = wp_command(
        state,
        ["cron", "event", "list", "--fields=time", "--format=json"],
        check=False,
        quiet=True,
    )
    due_cron_events: int | None = None
    if cron.returncode == 0:
        with contextlib.suppress(json.JSONDecodeError, TypeError, ValueError):
            events = json.loads(cron.stdout or "[]")
            due_cron_events = sum(int(item["time"]) <= int(time.time()) for item in events)
    prefix = wp_command(state, ["db", "prefix"], check=False, quiet=True).stdout.strip()
    post_ids = wp_command(
        state,
        ["post", "list", "--post_type=post", "--post_status=publish", "--posts_per_page=1", "--format=ids"],
        check=False,
        quiet=True,
    )
    permalink_live_ok: bool | None = None
    permalink_live_status: int | None = None
    permalink_live_error = ""
    permalink_live_tested = False
    permalink_path = ""
    first_id = post_ids.stdout.strip().split()[0] if post_ids.stdout.strip() else ""
    if first_id.isdigit():
        post_url = wp_command(state, ["post", "url", first_id], check=False, quiet=True)
        if post_url.returncode == 0:
            parsed_url = urllib.parse.urlsplit(post_url.stdout.strip())
            permalink_path = parsed_url.path or "/"
            if parsed_url.query:
                permalink_path += "?" + parsed_url.query
            permalink_live_tested = True
            try:
                permalink_response = local_request(state, permalink_path)
                permalink_live_status = int(permalink_response["status"])
                permalink_live_ok = permalink_live_status == 200
            except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
                permalink_live_ok = False
                permalink_live_error = str(exc)[:300]
    autoload_bytes = 0
    if re.fullmatch(r"[A-Za-z0-9_]+", prefix or ""):
        query = (
            f"SELECT COALESCE(SUM(LENGTH(option_value)),0) FROM {prefix}options "
            "WHERE autoload IN ('yes','on','auto-on','auto');"
        )
        autoload = wp_command(
            state, ["db", "query", query, "--skip-column-names"], check=False, quiet=True
        )
        with contextlib.suppress(ValueError):
            autoload_bytes = int(autoload.stdout.strip().splitlines()[-1])
    error_log = Path(f"/home/{state['linux_user']}/logs/error.log")
    slow_log = Path("/var/log/mysql/bagoeswp-slow.log")
    return {
        "permalink": permalink.stdout.strip(),
        "permalink_ok": permalink.returncode == 0 and permalink.stdout.strip() == "/%postname%/",
        "permalink_live_tested": permalink_live_tested,
        "permalink_live_ok": permalink_live_ok,
        "permalink_live_status": permalink_live_status,
        "permalink_live_error": permalink_live_error,
        "permalink_test_path": permalink_path,
        "database_ok": database.returncode == 0,
        "due_cron_events": due_cron_events,
        "autoload_bytes": autoload_bytes,
        "autoload_advisory": autoload_bytes > 800_000,
        "ols_error_log_bytes": error_log.stat().st_size if error_log.exists() else 0,
        "mariadb_slow_log_bytes": slow_log.stat().st_size if slow_log.exists() else 0,
    }


def _cpu_times() -> tuple[int, int]:
    values = [int(value) for value in Path("/proc/stat").read_text(encoding="utf-8").splitlines()[0].split()[1:]]
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    return sum(values), idle


def _resource_sampler(stop: threading.Event, samples: list[dict[str, float]]) -> None:
    previous_total, previous_idle = _cpu_times()
    while not stop.wait(0.1):
        total, idle = _cpu_times()
        total_delta = max(1, total - previous_total)
        idle_delta = max(0, idle - previous_idle)
        memory = memory_snapshot()
        samples.append(
            {
                "cpu_pct": max(0.0, min(100.0, (1 - idle_delta / total_delta) * 100)),
                "memory_pct": (memory["memory_used_mb"] / memory["memory_total_mb"]) * 100,
                "swap_used_mb": float(memory["swap_used_mb"]),
            }
        )
        previous_total, previous_idle = total, idle


def benchmark_site(
    state: dict[str, Any],
    *,
    request_count: int | None = None,
    concurrency: int | None = None,
) -> dict[str, Any]:
    vcpu = os.cpu_count() or 1
    workers = max(2, min(8, int(concurrency or vcpu * 2)))
    total = max(workers, min(60, int(request_count or max(24, workers * 5))))
    for _ in range(3):
        with contextlib.suppress(Exception):
            local_request(state, timeout=20)
    before = memory_snapshot()
    cpu_before = _cpu_times()
    stop = threading.Event()
    samples: list[dict[str, float]] = []
    sampler = threading.Thread(target=_resource_sampler, args=(stop, samples), daemon=True)
    sampler.start()
    responses: list[dict[str, Any]] = []
    errors: list[str] = []
    started = time.perf_counter()
    try:
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="bagoeswp-bench") as pool:
            futures = [pool.submit(local_request, state, timeout=20) for _ in range(total)]
            for future in as_completed(futures):
                try:
                    responses.append(future.result())
                except Exception as exc:
                    errors.append(str(exc)[:160])
    finally:
        stop.set()
        sampler.join(timeout=2)
    duration = max(0.001, time.perf_counter() - started)
    after = memory_snapshot()
    cpu_after = _cpu_times()
    cpu_delta = max(1, cpu_after[0] - cpu_before[0])
    interval_cpu = max(
        0.0,
        min(100.0, (1 - max(0, cpu_after[1] - cpu_before[1]) / cpu_delta) * 100),
    )
    latencies = [float(item["latency_ms"]) for item in responses]
    cache_hits = sum(
        1
        for item in responses
        if str((item.get("headers") or {}).get("x-litespeed-cache", "")).lower() == "hit"
    )
    four_xx = sum(1 for item in responses if 400 <= int(item.get("status", 0)) < 500)
    five_xx = sum(1 for item in responses if int(item.get("status", 0)) >= 500)
    failed = len(errors) + four_xx + five_xx
    observed_memory = [
        before["memory_used_mb"] / before["memory_total_mb"] * 100,
        after["memory_used_mb"] / after["memory_total_mb"] * 100,
        *(item["memory_pct"] for item in samples),
    ]
    return {
        "requests": total,
        "concurrency": workers,
        "completed": len(responses),
        "errors": failed,
        "error_samples": errors[:3],
        "error_rate_pct": round(failed / total * 100, 2),
        "status_4xx": four_xx,
        "status_5xx": five_xx,
        "rps": round(len(responses) / duration, 2),
        "p50_ms": round(percentile(latencies, 0.50), 2),
        "p95_ms": round(percentile(latencies, 0.95), 2),
        "max_ms": round(max(latencies) if latencies else 0.0, 2),
        "cache_hit_pct": round(cache_hits / max(1, len(responses)) * 100, 2),
        "peak_cpu_pct": round(
            max(interval_cpu, max((item["cpu_pct"] for item in samples), default=0.0)), 2
        ),
        "peak_memory_pct": round(max(observed_memory), 2),
        "swap_used_before_mb": before["swap_used_mb"],
        "swap_used_after_mb": after["swap_used_mb"],
        "swap_growth_mb": max(0, after["swap_used_mb"] - before["swap_used_mb"]),
    }


def benchmark_batch(states: list[dict[str, Any]]) -> dict[str, Any]:
    """Exercise all vhosts together with a bounded, cache-oriented workload."""
    if not states:
        return {}
    workers = max(2, min(12, (os.cpu_count() or 1) * 2))
    total = max(workers, min(80, max(30, len(states) * 8)))
    for state in states:
        with contextlib.suppress(Exception):
            local_request(state, timeout=20)
    before = memory_snapshot()
    cpu_before = _cpu_times()
    stop = threading.Event()
    samples: list[dict[str, float]] = []
    sampler = threading.Thread(target=_resource_sampler, args=(stop, samples), daemon=True)
    sampler.start()
    responses: list[tuple[str, dict[str, Any]]] = []
    errors: list[str] = []
    started = time.perf_counter()
    try:
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="bagoeswp-batch") as pool:
            futures = {
                pool.submit(local_request, states[index % len(states)], timeout=20): str(
                    states[index % len(states)]["domain"]
                )
                for index in range(total)
            }
            for future in as_completed(futures):
                try:
                    responses.append((futures[future], future.result()))
                except Exception as exc:
                    errors.append(str(exc)[:160])
    finally:
        stop.set()
        sampler.join(timeout=2)
    duration = max(0.001, time.perf_counter() - started)
    after = memory_snapshot()
    cpu_after = _cpu_times()
    cpu_delta = max(1, cpu_after[0] - cpu_before[0])
    interval_cpu = max(
        0.0,
        min(100.0, (1 - max(0, cpu_after[1] - cpu_before[1]) / cpu_delta) * 100),
    )
    latencies = [float(item[1]["latency_ms"]) for item in responses]
    four_xx = sum(
        1 for _domain, item in responses if 400 <= int(item.get("status", 0)) < 500
    )
    five_xx = sum(1 for _domain, item in responses if int(item.get("status", 0)) >= 500)
    cache_hits = sum(
        1
        for _domain, item in responses
        if str((item.get("headers") or {}).get("x-litespeed-cache", "")).lower() == "hit"
    )
    failed = len(errors) + four_xx + five_xx
    observed_memory = [
        before["memory_used_mb"] / before["memory_total_mb"] * 100,
        after["memory_used_mb"] / after["memory_total_mb"] * 100,
        *(item["memory_pct"] for item in samples),
    ]
    return {
        "requests": total,
        "concurrency": workers,
        "completed": len(responses),
        "errors": failed,
        "error_samples": errors[:3],
        "error_rate_pct": round(failed / total * 100, 2),
        "status_4xx": four_xx,
        "status_5xx": five_xx,
        "rps": round(len(responses) / duration, 2),
        "p95_ms": round(percentile(latencies, 0.95), 2),
        "cache_hit_pct": round(cache_hits / max(1, len(responses)) * 100, 2),
        "peak_cpu_pct": round(
            max(interval_cpu, max((item["cpu_pct"] for item in samples), default=0.0)), 2
        ),
        "peak_memory_pct": round(max(observed_memory), 2),
        "swap_growth_mb": max(0, after["swap_used_mb"] - before["swap_used_mb"]),
    }


def assess_performance(
    checks: dict[str, Any],
    benchmark: dict[str, Any],
    policy: dict[str, float] | None = None,
) -> dict[str, Any]:
    limits = dict(PERFORMANCE_POLICY if policy is None else policy)
    failures: list[str] = []
    comparisons = [
        (float(benchmark.get("p95_ms", 0)), limits["max_p95_ms"], "p95_latency"),
        (float(benchmark.get("error_rate_pct", 100)), limits["max_error_pct"], "request_errors"),
        (float(benchmark.get("peak_cpu_pct", 100)), limits["max_peak_cpu_pct"], "peak_cpu"),
        (float(benchmark.get("peak_memory_pct", 100)), limits["max_peak_memory_pct"], "peak_memory"),
        (float(benchmark.get("swap_growth_mb", 1)), limits["max_swap_growth_mb"], "swap_growth"),
    ]
    for actual, maximum, name in comparisons:
        if actual > maximum:
            failures.append(name)
    if float(benchmark.get("cache_hit_pct", 0)) < limits["min_cache_hit_pct"]:
        failures.append("cache_hit_ratio")
    if not checks.get("browser_cache"):
        failures.append("browser_cache")
    if not checks.get("compression"):
        failures.append("compression")
    if not checks.get("mandatory_ok"):
        failures.append("mandatory_health")
    return {"optimal": not failures, "failed": failures, "policy": limits}


def browser_cache_seconds(headers: dict[str, str]) -> int:
    cache_control = headers.get("cache-control", "")
    match = re.search(r"(?:^|,)\s*max-age=(\d+)", cache_control, re.IGNORECASE)
    if match:
        return int(match.group(1))
    expires = headers.get("expires")
    if not expires:
        return 0
    try:
        expires_at = email.utils.parsedate_to_datetime(expires)
        date_at = email.utils.parsedate_to_datetime(
            headers.get("date", email.utils.format_datetime(dt.datetime.now(dt.timezone.utc)))
        )
        return max(0, int((expires_at - date_at).total_seconds()))
    except (TypeError, ValueError, OverflowError):
        return 0


def redis_status_connected(output: str) -> bool:
    # Redis Object Cache emits `Status: Connected`. A substring check also
    # matches `Not connected` and `disconnected`, hiding a broken cache.
    output = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", output)
    return bool(re.search(r"(?im)^\s*Status:\s*Connected\s*$", output))


def verify_site(state: dict[str, Any]) -> dict[str, Any]:
    checks: dict[str, Any] = {}
    checks["wp_core"] = wp_command(state, ["core", "is-installed"], check=False, quiet=True).returncode == 0
    checks["lscache_plugin"] = (
        wp_command(state, ["plugin", "is-active", "litespeed-cache"], check=False, quiet=True).returncode == 0
    )
    checks["redis_plugin"] = (
        wp_command(state, ["plugin", "is-active", "redis-cache"], check=False, quiet=True).returncode == 0
    )
    redis = wp_command(state, ["redis", "status"], check=False, quiet=True)
    checks["redis_connected"] = redis.returncode == 0 and redis_status_connected(redis.stdout)
    checks["ownership_non_root"] = Path(f"/home/{state['linux_user']}/public_html").stat().st_uid != 0
    first = local_request(state)
    time.sleep(0.25)
    second = local_request(state)
    headers1 = first["headers"]
    headers2 = second["headers"]
    checks["http_status"] = second["status"]
    checks["http_ok"] = second["status"] in {200, 301, 302}
    checks["lscache_first"] = headers1.get("x-litespeed-cache", "").lower() in {"miss", "hit"}
    checks["lscache_hit"] = headers2.get("x-litespeed-cache", "").lower() == "hit"
    checks["compression"] = headers2.get("content-encoding", "").lower() in {"gzip", "br"}
    static = local_request(state, "/wp-content/bagoeswp-health.css")
    static_headers = static["headers"]
    cache_seconds = browser_cache_seconds(static_headers)
    checks["browser_cache_seconds"] = cache_seconds
    checks["browser_cache"] = static["status"] == 200 and cache_seconds >= 15_000_000
    health = wordpress_health(state)
    checks["wordpress_health"] = health
    checks["permalink_ok"] = health["permalink_ok"]
    checks["permalink_live_ok"] = (
        health["permalink_live_ok"] if health["permalink_live_tested"] else True
    )
    checks["database_ok"] = health["database_ok"]
    ssl_check = validate_ssl_certificate(state)
    checks["ssl"] = ssl_check
    checks["ssl_active"] = bool(state.get("ssl_active"))
    checks["ssl_required"] = bool(state.get("enable_ssl"))
    checks["ssl_pending"] = bool(state.get("enable_ssl")) and not bool(state.get("ssl_active"))
    checks["https_redirect_ok"] = True
    if state.get("ssl_active"):
        redirect = local_request(state, force_http=True)
        checks["https_redirect_ok"] = redirect["status"] in {301, 302, 307, 308}
    checks["cloudflare"] = cloudflare_probe(state)
    mandatory = [
        "wp_core",
        "lscache_plugin",
        "redis_plugin",
        "redis_connected",
        "ownership_non_root",
        "database_ok",
        "permalink_ok",
        "permalink_live_ok",
        "http_ok",
        "lscache_hit",
        "browser_cache",
        "https_redirect_ok",
    ]
    if state.get("ssl_active"):
        checks["ssl_certificate_valid"] = bool(ssl_check["valid"] and ssl_check["hostname_valid"])
        mandatory.append("ssl_certificate_valid")
    checks["mandatory_checks"] = mandatory
    checks["mandatory_ok"] = all(bool(checks[key]) for key in mandatory)
    return checks


def failed_mandatory_checks(checks: dict[str, Any]) -> list[str]:
    """Return only failed requirements, excluding advisory/inverted fields."""
    return [
        str(key)
        for key in checks.get("mandatory_checks", [])
        if not bool(checks.get(str(key)))
    ]


def write_report(domain: str, result: dict[str, Any]) -> str:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = REPORT_DIR / f"{domain}-{stamp}.json"
    atomic_write(path, json.dumps(result, indent=2, ensure_ascii=False), 0o600)
    return str(path)


def provision_site(payload: dict[str, Any]) -> dict[str, Any]:
    payload = validate_payload(payload)
    domain = payload["domain"]
    existing = load_state(domain)
    same_configuration = all(
        existing.get(key) == payload[key]
        for key in ("enable_ssl", "include_www", "admin_email")
    )
    if (
        existing.get("status") in {"VERIFIED", "OPTIMAL"}
        and same_configuration
        and (not payload["enable_ssl"] or existing.get("ssl_active"))
    ):
        checks = verify_site(existing)
        if checks["mandatory_ok"]:
            return {
                "status": "VERIFIED",
                "stage": "already_verified",
                "message": "Website sudah ada dan verifikasi ulang berhasil",
                "checks": checks,
            }
    identity = site_identity(domain)
    state = {
        **identity,
        **existing,
        "domain": domain,
        "admin_email": payload["admin_email"],
        "include_www": payload["include_www"],
        "enable_ssl": payload["enable_ssl"],
        "db_password": existing.get("db_password") or random_password(),
        "status": "RUNNING",
    }
    stage = "start"
    try:
        stage = "capacity"
        reserve_site_capacity(state)
        stage = "linux_user"
        ensure_linux_user(state)
        stage = "database"
        ensure_database(state)
        stage = "wordpress"
        ensure_wordpress(state, payload)
        stage = "ols_config"
        plan = configure_site(state)
        state["plan"] = plan
        state["status"] = "INSTALLED"
        state["installed_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
        save_state(state)
        stage = "ssl"
        ssl_active = try_ssl(state) if payload["enable_ssl"] else False
        state = load_state(domain)
        stage = "verify"
        checks = verify_site(state)
        if not checks["mandatory_ok"]:
            failed = failed_mandatory_checks(checks)
            raise AgentError("verify", "Pemeriksaan gagal: " + ", ".join(failed))
        if payload["enable_ssl"] and not ssl_active:
            status = "INSTALLED_PENDING_SSL"
            message = "WordPress terverifikasi; DNS/SSL masih pending"
        else:
            status = "VERIFIED"
            message = "WordPress, OLS, Redis, dan cache terverifikasi"
        state["status"] = status
        save_state(state)
        result = {"status": status, "stage": "complete", "message": message, "checks": checks}
        result["report_path"] = write_report(domain, result)
        return result
    except Exception as exc:
        if isinstance(exc, AgentError) and exc.stage != "command":
            stage = exc.stage
        state["status"] = "FAILED"
        state["failed_stage"] = stage
        state["last_error"] = str(exc)
        save_state(state)
        result = {"status": "FAILED", "stage": stage, "message": str(exc), "checks": {}}
        result["report_path"] = write_report(domain, result)
        return result


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def delete_old_files(root: Path, age_days: int, *, all_files: bool = False) -> tuple[int, int]:
    if not root.exists():
        return 0, 0
    cutoff = time.time() - age_days * 86400
    count = 0
    size = 0
    for path in root.rglob("*"):
        try:
            if not path.is_file() or path.is_symlink() or not _is_within(path, root):
                continue
            if not all_files:
                allowed = path.suffix in {".gz", ".old", ".tmp"} or ".log." in path.name
                if not allowed:
                    continue
            if path.stat().st_mtime > cutoff:
                continue
            file_size = path.stat().st_size
            path.unlink()
            count += 1
            size += file_size
        except OSError:
            continue
    return count, size


def validate_uninstall_payload(payload: dict[str, Any]) -> list[str]:
    raw_domains = payload.get("domains")
    if not isinstance(raw_domains, list) or not raw_domains:
        raise AgentError("uninstall_validation", "Pilih minimal satu domain untuk dihapus")
    if len(raw_domains) > 100:
        raise AgentError("uninstall_validation", "Maksimal 100 domain per uninstall custom")
    domains: list[str] = []
    seen: set[str] = set()
    for value in raw_domains:
        domain = normalize_domain(str(value))
        if domain not in seen:
            seen.add(domain)
            domains.append(domain)
    return domains


def verified_managed_state(domain: str) -> dict[str, Any]:
    state = load_state(domain)
    if not state:
        return {}
    normalized = normalize_domain(str(state.get("domain", "")))
    if normalized != domain:
        raise AgentError("uninstall_safety", f"State domain tidak cocok: {domain}")
    for key, expected in site_identity(domain).items():
        if state.get(key) != expected:
            raise AgentError(
                "uninstall_safety",
                f"Identitas {key} untuk {domain} tidak cocok; penghapusan dibatalkan",
            )
    return state


def safe_remove_tree(path: Path, root: Path, expected_name: str) -> None:
    if path.name != expected_name or path.resolve() == root.resolve() or not _is_within(path, root):
        raise AgentError("uninstall_safety", f"Target direktori tidak aman: {path}")
    if path.exists():
        shutil.rmtree(path)


def detach_site_states(states: list[dict[str, Any]]) -> None:
    backups: dict[Path, str] = {}
    for state in states:
        path = state_path(str(state["domain"]))
        backups[path] = path.read_text(encoding="utf-8")
        detached = dict(state)
        detached["configured"] = False
        detached["status"] = "UNINSTALLING"
        save_state(detached)
    try:
        apply_ols_config()
    except Exception:
        for path, content in backups.items():
            atomic_write(path, content, 0o600)
        raise


def remove_site_resources(state: dict[str, Any]) -> list[str]:
    domain = normalize_domain(str(state["domain"]))
    state = verified_managed_state(domain)
    if not state:
        return []
    identity = site_identity(domain)
    warnings: list[str] = []

    renewal = Path("/etc/letsencrypt/renewal") / f"{domain}.conf"
    live_cert = Path("/etc/letsencrypt/live") / domain
    if state.get("ssl_active") or renewal.exists() or live_cert.exists():
        certbot = run(
            ["certbot", "delete", "--non-interactive", "--cert-name", domain],
            check=False,
            timeout=300,
            quiet=True,
        )
        if certbot.returncode != 0:
            warnings.append(f"sertifikat {domain} belum dapat dihapus")

    database_sql = (
        f"DROP DATABASE IF EXISTS `{identity['db_name']}`;"
        f"DROP USER IF EXISTS '{identity['db_user']}'@'localhost';"
        "FLUSH PRIVILEGES;"
    )
    run(["mariadb", "--protocol=socket"], input_text=database_sql, timeout=120, quiet=True)

    user = identity["linux_user"]
    user_exists = run(["id", "-u", user], check=False, timeout=30, quiet=True).returncode == 0
    if user_exists:
        run(["pkill", "-TERM", "-u", user], check=False, timeout=30, quiet=True)
        deletion = run(["userdel", "--remove", user], check=False, timeout=120, quiet=True)
        if deletion.returncode != 0:
            detail = deletion.stderr.strip() or deletion.stdout.strip() or "userdel gagal"
            raise AgentError("uninstall_user", f"Gagal menghapus user {user}: {detail}")
    safe_remove_tree(Path("/home") / user, Path("/home"), user)

    vhost = OLS_ROOT / "conf/vhosts" / identity["site_key"]
    safe_remove_tree(vhost, OLS_ROOT / "conf/vhosts", identity["site_key"])
    with contextlib.suppress(FileNotFoundError):
        state_path(domain).unlink()
    return warnings


def remove_managed_ols_config() -> None:
    if OLS_MAIN.exists():
        before = OLS_MAIN.read_text(encoding="utf-8")
        updated = re.sub(
            rf"(?m)^\s*{re.escape(MANAGED_INCLUDE)}\s*\n?",
            "",
            before,
        )
        if updated != before:
            try:
                backup_file(OLS_MAIN)
                atomic_write(OLS_MAIN, updated.rstrip() + "\n", 0o600)
                config_test()
                run([str(OLS_ROOT / "bin/lswsctrl"), "restart"], timeout=120)
            except Exception:
                atomic_write(OLS_MAIN, before, 0o600)
                with contextlib.suppress(Exception):
                    run([str(OLS_ROOT / "bin/lswsctrl"), "restart"], check=False, quiet=True)
                raise
    safe_remove_tree(MANAGED_DIR, OLS_ROOT / "conf", "bagoeswp")


def remove_manager_services() -> None:
    timers = (
        "bagoeswp-maintenance.timer",
        "bagoeswp-wpcron.timer",
        "bagoeswp-monitor.timer",
    )
    run(["systemctl", "disable", "--now", *timers], check=False, timeout=120, quiet=True)
    unit_paths = (
        "/etc/systemd/system/bagoeswp-maintenance.service",
        "/etc/systemd/system/bagoeswp-maintenance.timer",
        "/etc/systemd/system/bagoeswp-wpcron.service",
        "/etc/systemd/system/bagoeswp-wpcron.timer",
        "/etc/systemd/system/bagoeswp-monitor.service",
        "/etc/systemd/system/bagoeswp-monitor.timer",
    )
    for value in unit_paths:
        with contextlib.suppress(FileNotFoundError):
            Path(value).unlink()
    run(["systemctl", "daemon-reload"], check=False, timeout=60, quiet=True)


def remove_manager_tuning() -> list[str]:
    warnings: list[str] = []
    mariadb_config = Path("/etc/mysql/mariadb.conf.d/60-bagoeswp.cnf")
    with contextlib.suppress(FileNotFoundError):
        mariadb_config.unlink()

    redis_main = Path("/etc/redis/redis.conf")
    redis_include = Path("/etc/redis/bagoeswp.conf")
    with contextlib.suppress(FileNotFoundError):
        redis_include.unlink()
    if redis_main.exists():
        content = redis_main.read_text(encoding="utf-8")
        updated = re.sub(
            r"(?m)^\s*include\s+/etc/redis/bagoeswp\.conf\s*\n?",
            "",
            content,
        )
        if updated != content:
            atomic_write(redis_main, updated, 0o640)

    if PHP_BIN.exists():
        ini = run([str(PHP_BIN), "--ini"], check=False, timeout=60, quiet=True)
        match = re.search(r"Scan for additional \.ini files in:\s*(\S+)", ini.stdout)
        if match and match.group(1).lower() != "(none)":
            with contextlib.suppress(FileNotFoundError):
                (Path(match.group(1)) / "99-bagoeswp.ini").unlink()

    for service in ("mariadb", "redis-server"):
        restarted = run(
            ["systemctl", "restart", service],
            check=False,
            timeout=120,
            quiet=True,
        )
        if restarted.returncode != 0:
            warnings.append(f"restart {service} gagal setelah melepas tuning BagoesWP")
    return warnings


def remove_global_manager() -> list[str]:
    remove_managed_ols_config()
    remove_manager_services()
    warnings = remove_manager_tuning()
    for path in (
        Path("/etc/letsencrypt/renewal-hooks/deploy/bagoeswp-restart-ols"),
        PERSISTENT_AGENT,
    ):
        with contextlib.suppress(FileNotFoundError):
            path.unlink()
    safe_remove_tree(BASE, BASE.parent, "bagoeswp")
    return warnings


def uninstall_sites(payload: dict[str, Any] | None = None, *, global_mode: bool = False) -> dict[str, Any]:
    if global_mode:
        managed_states = load_managed_states()
        valid_paths = {state_path(str(state["domain"])) for state in managed_states}
        unsafe_paths = sorted(path.name for path in STATE_DIR.glob("*.json") if path not in valid_paths)
        if unsafe_paths:
            raise AgentError(
                "uninstall_safety",
                "Uninstall global dibatalkan karena state tidak aman/rusak: "
                + ", ".join(unsafe_paths),
            )
        requested = [str(state["domain"]) for state in managed_states]
    else:
        requested = validate_uninstall_payload(payload or {})
    removed: list[str] = []
    not_found: list[str] = []
    failed: dict[str, str] = {}
    warnings: list[str] = []
    plan: dict[str, Any] = {}

    with global_lock():
        states: list[dict[str, Any]] = []
        for domain in requested:
            try:
                state = verified_managed_state(domain)
                if state:
                    states.append(state)
                else:
                    not_found.append(domain)
            except Exception as exc:
                failed[domain] = str(exc)
        if states:
            detach_site_states(states)
        for state in states:
            domain = str(state["domain"])
            try:
                warnings.extend(remove_site_resources(state))
                removed.append(domain)
            except Exception as exc:
                failed[domain] = str(exc)
                current = load_state(domain)
                if current:
                    current["configured"] = False
                    current["status"] = "UNINSTALL_FAILED"
                    current["last_uninstall_error"] = str(exc)
                    save_state(current)

        if global_mode and not failed:
            warnings.extend(remove_global_manager())
        elif removed:
            try:
                remaining = load_all_states()
                plan = effective_resource_plan(
                    memory_mb(), os.cpu_count() or 1, len(remaining) or 1
                )
                tune_mariadb(plan)
                tune_redis(plan)
                tune_php(plan)
            except Exception as exc:
                warnings.append("Retune setelah uninstall gagal: " + str(exc))

    status = "ok" if not failed and not warnings else "partial"
    message = f"{len(removed)} domain berhasil dihapus"
    if global_mode and not failed:
        message += "; konfigurasi BagoesWP dilepas, paket server bersama dipertahankan"
    result: dict[str, Any] = {
        "status": status,
        "stage": "uninstall_global" if global_mode else "uninstall_sites",
        "message": message,
        "removed": removed,
        "not_found": not_found,
        "failed": failed,
        "warnings": warnings,
        "plan": plan,
        "stack_packages_retained": True,
    }
    if not global_mode:
        result["report_path"] = write_report("uninstall", result)
    return result


def run_wpcron() -> dict[str, Any]:
    completed = 0
    failed = 0
    for state in load_all_states():
        result = wp_command(state, ["cron", "event", "run", "--due-now"], check=False, quiet=True)
        if result.returncode == 0:
            completed += 1
        else:
            failed += 1
    return {"status": "ok", "completed": completed, "failed": failed}


def cleanup_wordpress_junk(state: dict[str, Any], *, optimize_db: bool = False) -> dict[str, bool]:
    transient = wp_command(state, ["transient", "delete", "--expired"], check=False, quiet=True)
    prefix = wp_command(state, ["db", "prefix"], check=False, quiet=True).stdout.strip()
    spam_ok = False
    if re.fullmatch(r"[A-Za-z0-9_]+", prefix or ""):
        query = (
            f"DELETE FROM {prefix}comments WHERE comment_approved='spam' "
            "AND comment_date_gmt < UTC_TIMESTAMP() - INTERVAL 30 DAY;"
            f"DELETE cm FROM {prefix}commentmeta cm LEFT JOIN {prefix}comments c "
            "ON c.comment_ID=cm.comment_id WHERE c.comment_ID IS NULL;"
        )
        spam_ok = wp_command(state, ["db", "query", query], check=False, quiet=True).returncode == 0
    optimized = True
    if optimize_db:
        optimized = wp_command(state, ["db", "optimize"], check=False, quiet=True).returncode == 0
    return {
        "expired_transients": transient.returncode == 0,
        "old_spam_comments": spam_ok,
        "database_optimized": optimized,
    }


def maintenance() -> dict[str, Any]:
    usage = shutil.disk_usage("/")
    percent = round((usage.used / usage.total) * 100, 2)
    actions: list[dict[str, Any]] = []
    optimize_marker = BASE / "last-db-optimize"
    optimize_due = not optimize_marker.exists() or optimize_marker.stat().st_mtime < time.time() - 7 * 86400
    wordpress_cleanup: dict[str, Any] = {}
    for state in load_all_states():
        wordpress_cleanup[state["domain"]] = cleanup_wordpress_junk(
            state, optimize_db=optimize_due
        )
    if optimize_due:
        atomic_write(optimize_marker, dt.datetime.now(dt.timezone.utc).isoformat() + "\n", 0o600)
    if percent >= 40:
        run(["journalctl", "--vacuum-size=200M"], check=False, quiet=True)
        run(["apt-get", "clean"], check=False, quiet=True)
        for root in (OLS_ROOT / "logs", Path("/var/log/mysql")):
            count, size = delete_old_files(root, 14)
            actions.append({"target": str(root), "files": count, "bytes": size})
    if percent >= 70:
        for state in load_all_states():
            for root in (
                Path(f"/home/{state['linux_user']}/lscache"),
                Path(f"/home/{state['linux_user']}/.wp-cli/cache"),
            ):
                count, size = delete_old_files(root, 7, all_files=True)
                actions.append({"target": str(root), "files": count, "bytes": size})
    if percent >= 85:
        for state in load_all_states():
            root = Path(f"/home/{state['linux_user']}/public_html/wp-content/cache")
            count, size = delete_old_files(root, 2, all_files=True)
            actions.append({"target": str(root), "files": count, "bytes": size})
    after = shutil.disk_usage("/")
    result = {
        "status": "critical" if percent >= 95 else "ok",
        "disk_percent_before": percent,
        "disk_percent_after": round(after.used / after.total * 100, 2),
        "actions": actions,
        "wordpress_cleanup": wordpress_cleanup,
        "note": "Tidak ada uploads, database, tema, plugin, atau backup terakhir yang dihapus.",
    }
    write_report("maintenance", result)
    latest = REPORT_DIR / "maintenance-latest.txt"
    text = [
        f"Waktu UTC: {dt.datetime.now(dt.timezone.utc).isoformat()}",
        f"Disk sebelum: {result['disk_percent_before']}%",
        f"Disk sesudah: {result['disk_percent_after']}%",
        f"Status: {result['status']}",
        result["note"],
    ]
    atomic_write(latest, "\n".join(text) + "\n", 0o600)
    cutoff = time.time() - 30 * 86400
    for path in REPORT_DIR.glob("*.json"):
        if path.stat().st_mtime < cutoff:
            path.unlink()
    return result


def audit() -> dict[str, Any]:
    states = load_all_states()
    plan = effective_resource_plan(memory_mb(), os.cpu_count() or 1, len(states) or 1)
    checks: dict[str, Any] = {
        "lsws": run(["systemctl", "is-active", "lsws"], check=False, quiet=True).stdout.strip(),
        "mariadb": run(["systemctl", "is-active", "mariadb"], check=False, quiet=True).stdout.strip(),
        "redis": run(["redis-cli", "ping"], check=False, quiet=True).stdout.strip(),
        "php_modules": verify_php_runtime(),
        "system": system_snapshot(),
        "sites": {},
    }
    for state in states:
        try:
            checks["sites"][state["domain"]] = verify_site(state)
        except Exception as exc:
            checks["sites"][state["domain"]] = {
                "mandatory_ok": False,
                "error": str(exc)[:500],
            }
    return {"status": "ok", "plan": plan, "checks": checks}


def evaluate_sites(states: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for state in states:
        domain = str(state["domain"])
        try:
            checks = verify_site(state)
            benchmark = benchmark_site(state) if checks["mandatory_ok"] else {}
            if benchmark and float(benchmark.get("cache_hit_pct", 0)) < 90.0:
                log(f"{domain}: cache belum stabil; melakukan warm-up dan tes ulang")
                for _ in range(4):
                    with contextlib.suppress(Exception):
                        local_request(state, timeout=20)
                benchmark = benchmark_site(state)
            performance = assess_performance(checks, benchmark) if benchmark else {
                "optimal": False,
                "failed": ["mandatory_health"],
                "policy": dict(PERFORMANCE_POLICY),
            }
            if not checks["mandatory_ok"]:
                final_status = "FAILED"
            elif checks.get("ssl_pending"):
                final_status = "INSTALLED_PENDING_SSL"
            elif performance["optimal"]:
                final_status = "OPTIMAL"
            else:
                final_status = "VERIFIED"
            results[domain] = {
                **checks,
                "benchmark": benchmark,
                "performance": performance,
                "final_status": final_status,
            }
        except Exception as exc:
            results[domain] = {
                "mandatory_ok": False,
                "final_status": "FAILED",
                "error": str(exc)[:500],
                "benchmark": {},
                "performance": {
                    "optimal": False,
                    "failed": ["audit_exception"],
                    "policy": dict(PERFORMANCE_POLICY),
                },
            }
    return results


def apply_capacity_gate(
    site_results: dict[str, dict[str, Any]], plan: dict[str, int]
) -> None:
    if plan.get("capacity_ok"):
        return
    for result in site_results.values():
        performance = result.get("performance") or {}
        failures = list(performance.get("failed") or [])
        if "php_capacity" not in failures:
            failures.append("php_capacity")
        performance["failed"] = failures
        performance["optimal"] = False
        performance["capacity"] = {
            "sites": plan["site_count"],
            "max_safe_sites": plan["max_safe_sites"],
        }
        result["performance"] = performance
        if result.get("final_status") == "OPTIMAL":
            result["final_status"] = "VERIFIED"


def apply_batch_gate(
    site_results: dict[str, dict[str, Any]], batch: dict[str, Any]
) -> None:
    failures: list[str] = []
    if float(batch.get("p95_ms", 0)) > PERFORMANCE_POLICY["max_p95_ms"]:
        failures.append("batch_p95_latency")
    if float(batch.get("error_rate_pct", 100)) > PERFORMANCE_POLICY["max_error_pct"]:
        failures.append("batch_request_errors")
    if float(batch.get("cache_hit_pct", 0)) < PERFORMANCE_POLICY["min_cache_hit_pct"]:
        failures.append("batch_cache_hit_ratio")
    if float(batch.get("peak_cpu_pct", 100)) > PERFORMANCE_POLICY["max_peak_cpu_pct"]:
        failures.append("batch_peak_cpu")
    if float(batch.get("peak_memory_pct", 100)) > PERFORMANCE_POLICY["max_peak_memory_pct"]:
        failures.append("batch_peak_memory")
    if float(batch.get("swap_growth_mb", 1)) > PERFORMANCE_POLICY["max_swap_growth_mb"]:
        failures.append("batch_swap_growth")
    for result in site_results.values():
        benchmark = result.get("benchmark") or {}
        benchmark["peak_cpu_pct"] = max(
            float(benchmark.get("peak_cpu_pct", 0)), float(batch.get("peak_cpu_pct", 0))
        )
        benchmark["peak_memory_pct"] = max(
            float(benchmark.get("peak_memory_pct", 0)), float(batch.get("peak_memory_pct", 0))
        )
        benchmark["swap_growth_mb"] = max(
            float(benchmark.get("swap_growth_mb", 0)), float(batch.get("swap_growth_mb", 0))
        )
        result["benchmark"] = benchmark
        if not failures:
            continue
        performance = result.get("performance") or {}
        combined = list(performance.get("failed") or [])
        for failure in failures:
            if failure not in combined:
                combined.append(failure)
        performance["failed"] = combined
        performance["optimal"] = False
        result["performance"] = performance
        if result.get("final_status") == "OPTIMAL":
            result["final_status"] = "VERIFIED"


def batch_score(site_results: dict[str, dict[str, Any]]) -> float:
    """Lower is better; mandatory errors dominate performance noise."""
    score = 0.0
    for result in site_results.values():
        benchmark = result.get("benchmark") or {}
        performance = result.get("performance") or {}
        if not result.get("mandatory_ok"):
            score += 1_000_000
        if not performance.get("optimal"):
            score += 100_000
        score += float(benchmark.get("error_rate_pct", 100.0)) * 10_000
        score += max(0.0, float(benchmark.get("peak_cpu_pct", 100.0)) - 90.0) * 1_000
        score += max(0.0, float(benchmark.get("peak_memory_pct", 100.0)) - 90.0) * 1_000
        score += float(benchmark.get("swap_growth_mb", 0.0)) * 5_000
        score += float(benchmark.get("p95_ms", 10_000.0))
    return round(score, 3)


def optimize() -> dict[str, Any]:
    states = load_all_states()
    if not states:
        return {"status": "ok", "stage": "optimize", "checks": {"sites": {}}}
    for service in ("lsws", "mariadb", "redis-server"):
        active = run(["systemctl", "is-active", service], check=False, quiet=True).stdout.strip()
        if active != "active":
            raise AgentError("optimize", f"Service wajib tidak aktif: {service} ({active or 'unknown'})")
    verify_php_runtime()
    baseline_plan = resource_plan(memory_mb(), os.cpu_count() or 1, len(states))
    effective_plan = effective_resource_plan(memory_mb(), os.cpu_count() or 1, len(states))
    site_results = evaluate_sites(states)
    healthy_states = [state for state in states if site_results[str(state["domain"])].get("mandatory_ok")]
    batch_benchmark = benchmark_batch(healthy_states)
    apply_batch_gate(site_results, batch_benchmark)
    apply_capacity_gate(site_results, effective_plan)
    baseline_score = batch_score(site_results)
    current_children = int(effective_plan["php_children_per_site"])
    candidate, reason = choose_php_children(
        current_children,
        int(baseline_plan["php_children_per_site"]),
        site_results,
    )
    tuning: dict[str, Any] = {
        "reason": reason,
        "before_children": current_children,
        "candidate_children": candidate,
        "applied": False,
        "rolled_back": False,
        "baseline_score": baseline_score,
    }
    if candidate != current_children:
        previous_override = load_tuning().get("php_children_per_site")
        try:
            save_tuning(candidate)
            with global_lock():
                apply_ols_config()
            candidate_results = evaluate_sites(states)
            candidate_healthy = [
                state
                for state in states
                if candidate_results[str(state["domain"])].get("mandatory_ok")
            ]
            candidate_batch = benchmark_batch(candidate_healthy)
            apply_batch_gate(candidate_results, candidate_batch)
            candidate_plan = effective_resource_plan(memory_mb(), os.cpu_count() or 1, len(states))
            apply_capacity_gate(candidate_results, candidate_plan)
            candidate_score = batch_score(candidate_results)
            tuning["candidate_score"] = candidate_score
            if candidate_score <= baseline_score:
                site_results = candidate_results
                batch_benchmark = candidate_batch
                effective_plan = effective_resource_plan(memory_mb(), os.cpu_count() or 1, len(states))
                tuning["applied"] = True
            else:
                save_tuning(previous_override)
                with global_lock():
                    apply_ols_config()
                tuning["rolled_back"] = True
                tuning["rollback_reason"] = "benchmark_regression"
        except Exception as exc:
            save_tuning(previous_override)
            with contextlib.suppress(Exception):
                with global_lock():
                    apply_ols_config()
            tuning["rolled_back"] = True
            tuning["rollback_reason"] = str(exc)[:400]
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    for state in states:
        domain = str(state["domain"])
        result = site_results[domain]
        state["status"] = result["final_status"]
        state["last_audit_at"] = now
        state["last_benchmark"] = result.get("benchmark", {})
        if result["final_status"] == "OPTIMAL":
            state["optimal_at"] = now
        else:
            state.pop("optimal_at", None)
        save_state(state)
    checks = {
        "services": {
            "lsws": run(["systemctl", "is-active", "lsws"], check=False, quiet=True).stdout.strip(),
            "mariadb": run(["systemctl", "is-active", "mariadb"], check=False, quiet=True).stdout.strip(),
            "redis": run(["redis-cli", "ping"], check=False, quiet=True).stdout.strip(),
        },
        "system": system_snapshot(),
        "tuning": tuning,
        "batch_benchmark": batch_benchmark,
        "sites": site_results,
    }
    result = {"status": "ok", "stage": "optimize", "plan": effective_plan, "checks": checks}
    result["report_path"] = write_report("optimize", result)
    return result


def monitor() -> dict[str, Any]:
    audited = audit()
    sites = dict((audited.get("checks") or {}).get("sites") or {})
    unhealthy = [domain for domain, checks in sites.items() if not checks.get("mandatory_ok")]
    resources = system_snapshot()
    alerts: list[str] = []
    if unhealthy:
        alerts.append("website_failed:" + ",".join(unhealthy))
    if float(resources["disk_used_pct"]) >= 85:
        alerts.append("disk_above_85_percent")
    memory_pct = resources["memory_used_mb"] / resources["memory_total_mb"] * 100
    if memory_pct >= 90:
        alerts.append("memory_above_90_percent")
    result = {
        "status": "degraded" if alerts else "ok",
        "stage": "monitor",
        "alerts": alerts,
        "checks": audited["checks"],
    }
    result["report_path"] = write_report("monitor", result)
    atomic_write(REPORT_DIR / "monitor-latest.json", json.dumps(result, indent=2), 0o600)
    return result


def retune() -> dict[str, Any]:
    with global_lock():
        states = load_all_states()
        plan = effective_resource_plan(memory_mb(), os.cpu_count() or 1, len(states) or 1)
        tune_mariadb(plan)
        tune_redis(plan)
        tune_php(plan)
        apply_ols_config()
    return {"status": "ok", "stage": "retune", "plan": plan}


def emit_result(result: dict[str, Any]) -> None:
    print("BAGOESWP_RESULT=" + json.dumps(result, ensure_ascii=False, separators=(",", ":")), flush=True)


def decode_payload(value: str) -> dict[str, Any]:
    try:
        raw = base64.urlsafe_b64decode(value.encode("ascii"))
        return json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise AgentError("payload", f"Payload tidak dapat dibaca: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BagoesWP remote agent")
    parser.add_argument(
        "action",
        choices=[
            "preflight",
            "bootstrap",
            "site",
            "maintenance",
            "wpcron",
            "audit",
            "retune",
            "optimize",
            "monitor",
            "uninstall-sites",
            "uninstall-global",
        ],
    )
    payload_options = parser.add_mutually_exclusive_group()
    payload_options.add_argument("--payload", default="")
    payload_options.add_argument("--payload-stdin", action="store_true")
    args = parser.parse_args(argv)
    try:
        payload = args.payload
        if args.payload_stdin:
            # Keep WordPress credentials out of the process argument list.
            payload = sys.stdin.read(1_048_577).strip()
            if len(payload) > 1_048_576:
                raise AgentError("payload", "Payload terlalu besar")
        if args.action == "preflight":
            result = preflight()
        elif args.action == "bootstrap":
            result = bootstrap()
        elif args.action == "site":
            result = provision_site(decode_payload(payload))
        elif args.action == "maintenance":
            result = maintenance()
        elif args.action == "wpcron":
            result = run_wpcron()
        elif args.action == "retune":
            result = retune()
        elif args.action == "optimize":
            result = optimize()
        elif args.action == "monitor":
            result = monitor()
        elif args.action == "uninstall-sites":
            result = uninstall_sites(decode_payload(payload))
        elif args.action == "uninstall-global":
            result = uninstall_sites(global_mode=True)
        else:
            result = audit()
        emit_result(result)
        return 0 if result.get("status") not in {"FAILED", "error"} else 2
    except Exception as exc:
        stage = exc.stage if isinstance(exc, AgentError) else "agent"
        emit_result({"status": "FAILED", "stage": stage, "message": str(exc), "checks": {}})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
