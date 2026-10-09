from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class JobStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    INSTALLED = "INSTALLED"
    INSTALLED_PENDING_SSL = "INSTALLED_PENDING_SSL"
    VERIFIED = "VERIFIED"
    OPTIMAL = "OPTIMAL"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class AuthMethod(str, Enum):
    AUTO = "auto"
    PASSWORD = "password"
    OPENSSH_KEY = "openssh_key"
    PPK = "ppk"
    SSH_AGENT = "ssh_agent"


@dataclass(slots=True)
class ServerConfig:
    host: str
    port: int = 22
    username: str = "root"
    auth_method: AuthMethod = AuthMethod.PASSWORD
    password: str = ""
    key_path: str = ""
    key_passphrase: str = ""
    sudo_password: str = ""
    puttygen_path: str = ""
    concurrency: int = 10
    prepare_stack: bool = True
    install_cleanup: bool = True

    def safe_dict(self) -> dict[str, Any]:
        data = asdict(self)
        for key in ("password", "key_passphrase", "sudo_password"):
            data[key] = "***" if data[key] else ""
        return data


@dataclass(slots=True)
class SiteSpec:
    domain: str
    title: str
    admin_user: str
    admin_email: str
    admin_password: str
    locale: str = "en_US"
    enable_ssl: bool = True
    include_www: bool = True

    def payload(self, server_ip: str = "") -> dict[str, Any]:
        return {
            "domain": self.domain,
            "title": self.title,
            "admin_user": self.admin_user,
            "admin_email": self.admin_email,
            "admin_password": self.admin_password,
            "locale": self.locale,
            "enable_ssl": self.enable_ssl,
            "include_www": self.include_www,
            "server_ip": server_ip,
        }

    def safe_dict(self) -> dict[str, Any]:
        data = self.payload()
        data["admin_password"] = "***"
        return data


@dataclass(slots=True)
class JobResult:
    domain: str
    status: JobStatus
    stage: str = ""
    message: str = ""
    checks: dict[str, Any] = field(default_factory=dict)
    report_path: str = ""

    @classmethod
    def from_agent(cls, domain: str, data: dict[str, Any]) -> "JobResult":
        raw_status = data.get("status", JobStatus.FAILED.value)
        try:
            status = JobStatus(raw_status)
        except ValueError:
            status = JobStatus.FAILED
        return cls(
            domain=domain,
            status=status,
            stage=str(data.get("stage", "")),
            message=str(data.get("message", "")),
            checks=dict(data.get("checks") or {}),
            report_path=str(data.get("report_path", "")),
        )


@dataclass(slots=True)
class AppPaths:
    project_root: Path

    @property
    def remote_agent(self) -> Path:
        return self.project_root / "bagoeswp" / "resources" / "remote_agent.py"


def parse_bool(value: object, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None or value == "":
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}
