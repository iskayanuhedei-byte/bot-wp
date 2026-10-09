from __future__ import annotations

import base64
import contextlib
import json
import sys
import threading
import uuid
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Iterable

from .models import JobResult, JobStatus, ServerConfig, SiteSpec
from .ssh_transport import SSHError, SSHTransport, quote_remote


LogCallback = Callable[[str], None]
StatusCallback = Callable[[str, JobStatus, str], None]
REMOTE_RESULT_PREFIX = "BAGOESWP_RESULT="


def resource_path(relative: str) -> Path:
    if hasattr(sys, "_MEIPASS"):
        frozen_root = Path(getattr(sys, "_MEIPASS"))
        packaged = frozen_root / "bagoeswp" / relative
        return packaged if packaged.exists() else frozen_root / relative
    return Path(__file__).resolve().parent / relative


def encode_payload(payload: dict[str, object]) -> str:
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def parse_agent_result(output: str) -> dict[str, object]:
    for line in reversed(output.splitlines()):
        if line.startswith(REMOTE_RESULT_PREFIX):
            try:
                value = json.loads(line[len(REMOTE_RESULT_PREFIX) :])
            except json.JSONDecodeError as exc:
                raise SSHError(f"Hasil agent bukan JSON valid: {exc}") from exc
            if not isinstance(value, dict):
                raise SSHError("Hasil agent tidak berbentuk objek")
            return value
    raise SSHError("Agent tidak mengirim penanda hasil")


class BulkInstaller:
    def __init__(
        self,
        server: ServerConfig,
        *,
        log: LogCallback | None = None,
        status: StatusCallback | None = None,
    ) -> None:
        self.server = server
        self.log = log or (lambda _message: None)
        self.status = status or (lambda _domain, _status, _message: None)
        self.cancel_event = threading.Event()
        self.remote_agent = f"/tmp/bagoeswp-agent-{uuid.uuid4().hex}.py"
        self._agent_local = resource_path("resources/remote_agent.py")

    def cancel(self) -> None:
        self.cancel_event.set()
        self.log("Permintaan berhenti diterima. Job aktif diselesaikan dengan aman.")

    def _transport(self, prefix: str = "") -> SSHTransport:
        def emit(message: str) -> None:
            self.log(f"{prefix}{message}" if prefix else message)

        return SSHTransport(self.server, emit)

    def test_connection(self) -> dict[str, object]:
        with self._transport() as ssh:
            result = ssh.run("uname -a && id -u", check=True, timeout=30)
            output = result.stdout.strip()
            if ssh.auth_used:
                output = f"Autentikasi: {ssh.auth_used}\n" + output
            try:
                privilege = ssh.run("id -u", sudo=True, check=False, timeout=30)
            except SSHError as exc:
                raise SSHError(
                    "SSH tersambung, tetapi pemeriksaan hak administrator gagal. "
                    "Instalasi memerlukan root atau sudo. " + str(exc)
                ) from exc
            if privilege.exit_code != 0 or privilege.stdout.strip().splitlines()[-1:] != ["0"]:
                detail = privilege.stderr.strip() or "sudo tidak menghasilkan UID root"
                raise SSHError(
                    "SSH tersambung, tetapi akses sudo belum siap. Gunakan user Ubuntu "
                    "yang memiliki sudo; bila sudo meminta password, isi kolom Password sudo. "
                    "Passphrase PPK hanya membuka private key, bukan password sudo. "
                    + detail
                )
            output += "\nHak administrator: siap (root/sudo)"
            return {"status": "ok", "output": output, "auth": ssh.auth_used}

    def _upload_agent(self) -> None:
        if not self._agent_local.is_file():
            raise SSHError(f"Remote agent tidak ditemukan: {self._agent_local}")
        with self._transport() as ssh:
            ssh.upload(self._agent_local, self.remote_agent)
            ssh.run(f"python3 {quote_remote(self.remote_agent)} --help", timeout=30)

    def _cleanup_agent(self) -> None:
        with contextlib.suppress(Exception):
            with self._transport() as ssh:
                ssh.run(
                    f"rm -f -- {quote_remote(self.remote_agent)}",
                    sudo=False,
                    check=False,
                    timeout=30,
                )

    def _agent_action(self, action: str, *, payload: str = "", timeout: int = 3600) -> dict[str, object]:
        command = f"python3 {quote_remote(self.remote_agent)} {quote_remote(action)}"
        if payload:
            command += " --payload-stdin"
        with self._transport() as ssh:
            result = ssh.run(
                command,
                sudo=True,
                timeout=timeout,
                check=False,
                display_command=command,
                input_text=payload + "\n" if payload else "",
            )
        try:
            data = parse_agent_result(result.stdout)
        except SSHError as exc:
            if result.exit_code != 0 and any(
                line.lstrip().startswith("sudo:") for line in result.stderr.splitlines()
            ):
                raise SSHError(
                    "SSH tersambung, tetapi agent belum dapat berjalan sebagai root. "
                    "Periksa hak sudo dan kolom Password sudo; passphrase PPK bukan password sudo. "
                    + result.stderr.strip()
                ) from exc
            raise
        if result.exit_code not in {0, 2} and data.get("status") != "FAILED":
            raise SSHError(result.stderr.strip() or f"Agent exit {result.exit_code}")
        return data

    def prepare(self) -> dict[str, object]:
        self._upload_agent()
        self.log("Menjalankan preflight Ubuntu, RAM, CPU, dan disk...")
        preflight = self._agent_action("preflight", timeout=120)
        if preflight.get("status") == "FAILED":
            raise SSHError(str(preflight.get("message", "Preflight gagal")))
        self.log(
            "Resource VPS: "
            f"{preflight.get('vcpu', '?')} vCPU, "
            f"RAM {preflight.get('memory_total_mb', preflight.get('memory_mb', '?'))} MB, "
            f"swap {preflight.get('swap_total_mb', '?')} MB, "
            f"disk kosong {preflight.get('disk_free_gib', '?')} GiB."
        )
        for warning in preflight.get("warnings", []) or []:
            self.log("PERINGATAN: " + str(warning))
        if self.server.prepare_stack:
            self.log("Menyiapkan stack OLS satu kali. Tahap ini dapat memakan waktu.")
            bootstrap = self._agent_action("bootstrap", timeout=3600)
            if bootstrap.get("status") == "FAILED":
                raise SSHError(str(bootstrap.get("message", "Bootstrap gagal")))
            return bootstrap
        return preflight

    def uninstall(
        self,
        domains: Iterable[str] | None = None,
        *,
        global_mode: bool = False,
    ) -> dict[str, object]:
        domain_list = list(dict.fromkeys(domains or []))
        if not global_mode and not domain_list:
            raise ValueError("Pilih minimal satu domain untuk di-uninstall")
        try:
            self._upload_agent()
            if global_mode:
                self.log("Menghapus seluruh website dan konfigurasi yang dikelola BagoesWP...")
                result = self._agent_action("uninstall-global", timeout=3600)
            else:
                self.log(f"Menghapus {len(domain_list)} domain yang dipilih...")
                payload = encode_payload({"domains": domain_list})
                result = self._agent_action(
                    "uninstall-sites", payload=payload, timeout=3600
                )
            if result.get("status") == "FAILED":
                raise SSHError(str(result.get("message", "Uninstall gagal")))
            return result
        finally:
            self._cleanup_agent()

    def _install_one(self, site: SiteSpec) -> JobResult:
        if self.cancel_event.is_set():
            result = JobResult(site.domain, JobStatus.CANCELLED, "queue", "Dibatalkan sebelum dimulai")
            self.status(site.domain, result.status, result.message)
            return result
        self.status(site.domain, JobStatus.RUNNING, "Memulai instalasi")
        try:
            payload = encode_payload(site.payload(server_ip=self.server.host))
            data = self._agent_action("site", payload=payload, timeout=3600)
            result = JobResult.from_agent(site.domain, data)
        except Exception as exc:
            result = JobResult(site.domain, JobStatus.FAILED, "transport", str(exc))
        self.status(site.domain, result.status, result.message)
        return result

    def _fail_unverified_batch(
        self,
        results: list[JobResult],
        *,
        stage: str,
        message: str,
    ) -> None:
        for result in results:
            if result.status not in {
                JobStatus.INSTALLED,
                JobStatus.INSTALLED_PENDING_SSL,
                JobStatus.VERIFIED,
                JobStatus.OPTIMAL,
            }:
                continue
            result.status = JobStatus.FAILED
            result.stage = stage
            result.message = message
            self.status(result.domain, result.status, result.message)

    def install(self, sites: Iterable[SiteSpec]) -> list[JobResult]:
        site_list = list(sites)
        if not site_list:
            raise ValueError("Tidak ada domain untuk dipasang")
        self.cancel_event.clear()
        results: list[JobResult] = []
        try:
            self.prepare()
            workers = max(1, min(10, int(self.server.concurrency), len(site_list)))
            self.log(f"Menjalankan {len(site_list)} domain dengan maksimal {workers} job aktif.")
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="bagoeswp") as executor:
                futures: dict[Future[JobResult], SiteSpec] = {
                    executor.submit(self._install_one, site): site for site in site_list
                }
                for future in as_completed(futures):
                    try:
                        results.append(future.result())
                    except Exception as exc:
                        site = futures[future]
                        result = JobResult(site.domain, JobStatus.FAILED, "worker", str(exc))
                        self.status(site.domain, result.status, result.message)
                        results.append(result)
            if not self.cancel_event.is_set():
                self.log("Menyesuaikan ulang OLS, PHP, MariaDB, dan Redis untuk jumlah domain final...")
                try:
                    retune = self._agent_action("retune", timeout=900)
                except Exception as exc:
                    self.log("PERINGATAN retune tidak dapat dijalankan: " + str(exc))
                    retune = {"status": "FAILED", "message": str(exc)}
                if retune.get("status") == "FAILED":
                    detail = str(retune.get("message", "gagal"))
                    self.log("PERINGATAN retune: " + detail)
                    self._fail_unverified_batch(
                        results,
                        stage="final_retune",
                        message="Retune akhir gagal; hasil tidak dinyatakan terverifikasi: " + detail,
                    )
                else:
                    self.log("Menjalankan audit, benchmark ringan, dan tuning adaptif...")
                    try:
                        audit = self._agent_action("optimize", timeout=3600)
                    except Exception as exc:
                        self.log("PERINGATAN audit akhir tidak dapat dijalankan: " + str(exc))
                        audit = {"status": "FAILED"}
                    if audit.get("status") == "ok":
                        site_checks = dict((audit.get("checks") or {}).get("sites") or {})
                        for result in results:
                            checks = site_checks.get(result.domain)
                            if not isinstance(checks, dict):
                                if result.status in {
                                    JobStatus.INSTALLED,
                                    JobStatus.INSTALLED_PENDING_SSL,
                                    JobStatus.VERIFIED,
                                    JobStatus.OPTIMAL,
                                }:
                                    result.status = JobStatus.FAILED
                                    result.stage = "final_audit"
                                    result.message = "Audit akhir tidak mengembalikan hasil domain"
                                    self.status(result.domain, result.status, result.message)
                                continue
                            result.checks = checks
                            if result.status in {
                                JobStatus.INSTALLED,
                                JobStatus.VERIFIED,
                                JobStatus.OPTIMAL,
                                JobStatus.INSTALLED_PENDING_SSL,
                            } and not checks.get("mandatory_ok"):
                                result.status = JobStatus.FAILED
                                result.stage = "final_audit"
                                result.message = "Audit akhir gagal setelah retune"
                                self.status(result.domain, result.status, result.message)
                            elif result.status is not JobStatus.FAILED:
                                raw_status = str(checks.get("final_status", JobStatus.VERIFIED.value))
                                try:
                                    result.status = JobStatus(raw_status)
                                except ValueError:
                                    result.status = JobStatus.VERIFIED
                                result.stage = "final_optimize"
                                if result.status is JobStatus.OPTIMAL:
                                    result.message = "Terverifikasi dan memenuhi ambang performa"
                                elif result.status is JobStatus.INSTALLED_PENDING_SSL:
                                    result.message = "Terverifikasi lokal; DNS/SSL masih pending"
                                else:
                                    failed = (checks.get("performance") or {}).get("failed", [])
                                    suffix = ": " + ", ".join(map(str, failed)) if failed else ""
                                    result.message = "Terverifikasi; ambang optimal belum terpenuhi" + suffix
                                self.status(result.domain, result.status, result.message)
                    else:
                        detail = str(audit.get("message", "agent audit tidak mengirim hasil valid"))
                        self.log("PERINGATAN audit akhir: " + detail)
                        self._fail_unverified_batch(
                            results,
                            stage="final_audit",
                            message="Audit akhir tidak selesai; hasil tidak dinyatakan terverifikasi: "
                            + detail,
                        )
            order = {site.domain: index for index, site in enumerate(site_list)}
            results.sort(key=lambda item: order[item.domain])
            return results
        finally:
            self._cleanup_agent()


def summarize_results(results: list[JobResult]) -> dict[str, int]:
    summary = {status.value: 0 for status in JobStatus}
    for result in results:
        summary[result.status.value] += 1
    return summary
