from __future__ import annotations

import threading
import time
import unittest
import base64
import json
from types import SimpleNamespace
from unittest.mock import patch

from bagoeswp.models import JobResult, JobStatus, ServerConfig, SiteSpec
from bagoeswp.orchestrator import BulkInstaller, encode_payload, parse_agent_result
from bagoeswp.ssh_transport import SSHError


class _FakeTransport:
    def __init__(self, calls: list[tuple[tuple[object, ...], dict[str, object]]] | None = None):
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def run(self, *args, **kwargs):
        if self.calls is not None:
            self.calls.append((args, kwargs))

        class Result:
            exit_code = 0
            stdout = 'BAGOESWP_RESULT={"status":"ok"}\n'
            stderr = ""

        return Result()


class TrackingInstaller(BulkInstaller):
    def __init__(self, server: ServerConfig):
        super().__init__(server)
        self.active = 0
        self.maximum = 0
        self.guard = threading.Lock()

    def prepare(self):
        return {"status": "ok"}

    def _transport(self, prefix: str = ""):
        return _FakeTransport()

    def _agent_action(self, action: str, **_kwargs):
        if action == "audit":
            return {"status": "ok", "checks": {"sites": {}}}
        return {"status": "ok"}

    def _install_one(self, site: SiteSpec) -> JobResult:
        with self.guard:
            self.active += 1
            self.maximum = max(self.maximum, self.active)
        time.sleep(0.03)
        with self.guard:
            self.active -= 1
        return JobResult(site.domain, JobStatus.VERIFIED, "test", "ok")


class CaptureInstaller(BulkInstaller):
    def __init__(self, server: ServerConfig):
        super().__init__(server)
        self.calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def _transport(self, prefix: str = ""):
        return _FakeTransport(self.calls)


class FailingPrepareInstaller(CaptureInstaller):
    def prepare(self):
        raise RuntimeError("bootstrap gagal")


class FailingRetuneInstaller(TrackingInstaller):
    def _agent_action(self, action: str, **_kwargs):
        if action == "retune":
            return {"status": "FAILED", "message": "konfigurasi ditolak"}
        return super()._agent_action(action, **_kwargs)


class OptimalInstaller(TrackingInstaller):
    def _agent_action(self, action: str, **_kwargs):
        if action == "optimize":
            return {
                "status": "ok",
                "checks": {
                    "sites": {
                        "site.example.com": {
                            "mandatory_ok": True,
                            "final_status": "OPTIMAL",
                            "performance": {"optimal": True, "failed": []},
                        }
                    }
                },
            }
        return {"status": "ok"}


class UninstallCaptureInstaller(BulkInstaller):
    def __init__(self, server: ServerConfig):
        super().__init__(server)
        self.actions: list[tuple[str, dict[str, object]]] = []
        self.cleaned = False

    def _upload_agent(self) -> None:
        return None

    def _cleanup_agent(self) -> None:
        self.cleaned = True

    def _agent_action(self, action: str, **kwargs):
        self.actions.append((action, kwargs))
        return {"status": "ok", "removed": []}


class OrchestratorTests(unittest.TestCase):
    def _connection_transport(self, *, exit_code=0, uid="0\n", stderr=""):
        transport = _FakeTransport([])
        transport.auth_used = "PPK"

        def run(command, **kwargs):
            transport.calls.append(((command,), kwargs))
            if kwargs.get("sudo"):
                return SimpleNamespace(exit_code=exit_code, stdout=uid, stderr=stderr)
            return SimpleNamespace(exit_code=0, stdout="Ubuntu\n1000\n", stderr="")

        transport.run = run
        return transport

    def test_connection_requires_read_only_sudo_check_after_ssh_login(self) -> None:
        installer = BulkInstaller(ServerConfig(host="127.0.0.1", username="ubuntu"))
        transport = self._connection_transport()
        with patch.object(installer, "_transport", return_value=transport):
            result = installer.test_connection()
        self.assertEqual(result["auth"], "PPK")
        self.assertIn("Hak administrator: siap", result["output"])
        args, kwargs = transport.calls[-1]
        self.assertEqual(args[0], "id -u")
        self.assertTrue(kwargs["sudo"])
        self.assertFalse(kwargs["check"])

    def test_connection_explains_sudo_denial_separately_from_ppk_login(self) -> None:
        installer = BulkInstaller(ServerConfig(host="127.0.0.1", username="ubuntu"))
        transport = self._connection_transport(exit_code=1, uid="", stderr="sudo: a password is required")
        with patch.object(installer, "_transport", return_value=transport):
            with self.assertRaisesRegex(SSHError, "SSH tersambung.*Password sudo"):
                installer.test_connection()

    def test_connection_rejects_successful_command_without_root_privilege(self) -> None:
        installer = BulkInstaller(ServerConfig(host="127.0.0.1", username="ubuntu"))
        transport = self._connection_transport(uid="1000\n")
        with patch.object(installer, "_transport", return_value=transport):
            with self.assertRaisesRegex(SSHError, "akses sudo belum siap"):
                installer.test_connection()

    def test_agent_action_explains_sudo_failure_without_result_marker(self) -> None:
        installer = BulkInstaller(ServerConfig(host="127.0.0.1", username="ubuntu"))
        transport = self._connection_transport(exit_code=1, uid="", stderr="sudo: a password is required")
        with patch.object(installer, "_transport", return_value=transport):
            with self.assertRaisesRegex(SSHError, "SSH tersambung.*Password sudo"):
                installer._agent_action("preflight")

    def test_agent_result_parser(self) -> None:
        parsed = parse_agent_result('log\nBAGOESWP_RESULT={"status":"ok"}\n')
        self.assertEqual(parsed["status"], "ok")

    def test_payload_does_not_use_shell_json(self) -> None:
        encoded = encode_payload({"title": "A title with ' quotes $(unsafe)"})
        self.assertNotIn("$", encoded)
        self.assertNotIn("'", encoded)

    def test_concurrency_never_exceeds_ten(self) -> None:
        server = ServerConfig(host="127.0.0.1", password="x", concurrency=50)
        installer = TrackingInstaller(server)
        sites = [
            SiteSpec(f"site{i}.example.com", "Title", "admin", "admin@example.com", "abcdefghijkl")
            for i in range(20)
        ]
        results = installer.install(sites)
        self.assertEqual(len(results), 20)
        self.assertEqual(installer.maximum, 10)

    def test_payload_only_uses_stdin_and_is_absent_from_remote_process_arguments(self) -> None:
        installer = CaptureInstaller(ServerConfig(host="127.0.0.1", password="x"))
        secret = "RahasiaSekali123!"
        secret_payload = encode_payload({"admin_password": secret})
        installer._agent_action("site", payload=secret_payload)
        args, kwargs = installer.calls[-1]
        self.assertTrue(str(args[0]).endswith(" --payload-stdin"))
        self.assertEqual(kwargs["input_text"], secret_payload + "\n")
        self.assertEqual(kwargs["display_command"], args[0])
        for exposed in (str(args[0]), str(kwargs["display_command"])):
            self.assertNotIn(secret_payload, exposed)
            self.assertNotIn(secret, exposed)

    def test_actions_without_payload_do_not_read_stdin(self) -> None:
        installer = CaptureInstaller(ServerConfig(host="127.0.0.1", password="x"))
        installer._agent_action("preflight")
        args, kwargs = installer.calls[-1]
        self.assertNotIn("--payload", args[0])
        self.assertEqual(kwargs["input_text"], "")

    def test_remote_agent_cleanup_runs_after_prepare_failure(self) -> None:
        installer = FailingPrepareInstaller(ServerConfig(host="127.0.0.1", password="x"))
        site = SiteSpec("site.example.com", "Title", "admin", "admin@example.com", "abcdefghijkl")
        with self.assertRaisesRegex(RuntimeError, "bootstrap gagal"):
            installer.install([site])
        self.assertTrue(any("rm -f --" in str(args[0]) for args, _kwargs in installer.calls))

    def test_retune_failure_downgrades_success(self) -> None:
        installer = FailingRetuneInstaller(ServerConfig(host="127.0.0.1", password="x"))
        site = SiteSpec("site.example.com", "Title", "admin", "admin@example.com", "abcdefghijkl")
        results = installer.install([site])
        self.assertEqual(results[0].status, JobStatus.FAILED)
        self.assertEqual(results[0].stage, "final_retune")

    def test_final_optimize_can_promote_verified_to_optimal(self) -> None:
        installer = OptimalInstaller(ServerConfig(host="127.0.0.1", password="x"))
        site = SiteSpec("site.example.com", "Title", "admin", "admin@example.com", "abcdefghijkl")
        results = installer.install([site])
        self.assertEqual(results[0].status, JobStatus.OPTIMAL)
        self.assertEqual(results[0].stage, "final_optimize")

    def test_unknown_agent_status_fails_closed(self) -> None:
        result = JobResult.from_agent("site.example.com", {"status": "ALMOST_GOOD"})
        self.assertEqual(result.status, JobStatus.FAILED)

    def test_custom_uninstall_uses_redacted_encoded_payload(self) -> None:
        installer = UninstallCaptureInstaller(ServerConfig(host="127.0.0.1", password="x"))
        installer.uninstall(["one.example.com", "two.example.com"])
        action, kwargs = installer.actions[-1]
        payload = json.loads(base64.urlsafe_b64decode(str(kwargs["payload"])).decode())
        self.assertEqual(action, "uninstall-sites")
        self.assertEqual(payload["domains"], ["one.example.com", "two.example.com"])
        self.assertTrue(installer.cleaned)

    def test_global_uninstall_has_no_domain_payload(self) -> None:
        installer = UninstallCaptureInstaller(ServerConfig(host="127.0.0.1", password="x"))
        installer.uninstall(global_mode=True)
        action, kwargs = installer.actions[-1]
        self.assertEqual(action, "uninstall-global")
        self.assertNotIn("payload", kwargs)
        self.assertTrue(installer.cleaned)


if __name__ == "__main__":
    unittest.main()
