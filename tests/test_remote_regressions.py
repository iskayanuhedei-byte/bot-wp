from __future__ import annotations

import base64
import contextlib
import io
import json
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from bagoeswp.resources import remote_agent


def managed_state(domain: str = "example.com", **overrides: object) -> dict[str, object]:
    return {
        **remote_agent.site_identity(domain),
        "domain": domain,
        "admin_email": "admin@example.com",
        "include_www": False,
        "enable_ssl": False,
        "ssl_active": False,
        "configured": True,
        "status": "VERIFIED",
        **overrides,
    }


def site_payload(**overrides: object) -> dict[str, object]:
    return {
        "domain": "example.com",
        "title": "Example",
        "admin_user": "admin",
        "admin_email": "admin@example.com",
        "admin_password": "local_test_password_123",
        "include_www": False,
        "enable_ssl": False,
        **overrides,
    }


class ResourceCapacityRegressionTests(unittest.TestCase):
    def test_requested_vps_profiles_limit_children_as_site_count_grows(self) -> None:
        profiles = {
            (8192, 2): [(1, 10, True), (5, 2, True), (10, 1, False)],
            (8192, 4): [(1, 10, True), (5, 2, True), (10, 1, False)],
            (16384, 4): [(1, 10, True), (5, 4, True), (10, 2, True)],
        }
        for (memory, cpus), cases in profiles.items():
            for sites, children, fits in cases:
                with self.subTest(memory=memory, cpus=cpus, sites=sites):
                    plan = remote_agent.resource_plan(memory, cpus, sites)
                    self.assertEqual(plan["php_children_per_site"], children)
                    self.assertEqual(bool(plan["capacity_ok"]), fits)
                    if fits:
                        self.assertLessEqual(plan["php_estimated_mb"], plan["php_budget_mb"])

    def test_capacity_includes_php_processes_and_opcache_for_every_worker(self) -> None:
        for memory in (2048, 4096, 8192, 32768):
            for cpus in (2, 16):
                for sites in (1, 2, 10, 100):
                    with self.subTest(memory=memory, cpus=cpus, sites=sites):
                        plan = remote_agent.resource_plan(memory, cpus, sites)
                        groups = sites * plan["ols_workers"]
                        footprint = groups * (plan["php_children_per_site"] * 256 + 80)
                        self.assertEqual(plan["php_process_memory_mb"], 256)
                        self.assertEqual(plan["opcache_mb_per_site"], 64)
                        self.assertEqual(plan["opcache_overhead_mb"], groups * 80)
                        self.assertEqual(plan["php_estimated_mb"], footprint)
                        self.assertEqual(plan["capacity_ok"], int(footprint <= plan["php_budget_mb"]))
                        self.assertEqual(
                            plan["max_safe_sites"],
                            plan["php_budget_mb"] // (plan["ols_workers"] * 336),
                        )

    def test_two_gib_cannot_admit_a_third_php_process_group(self) -> None:
        self.assertTrue(remote_agent.resource_plan(2048, 2, 2)["capacity_ok"])
        overloaded = remote_agent.resource_plan(2048, 2, 3)
        self.assertFalse(overloaded["capacity_ok"])
        self.assertGreater(overloaded["php_estimated_mb"], overloaded["php_budget_mb"])

    def test_capacity_does_not_claim_one_site_when_even_one_cannot_fit(self) -> None:
        plan = remote_agent.resource_plan(512, 16, 1)
        self.assertEqual(plan["max_safe_sites"], 0)
        self.assertFalse(plan["capacity_ok"])

    def reserve(self, candidate: dict[str, object], states: list[dict[str, object]]) -> object:
        with (
            patch.object(remote_agent, "global_lock", side_effect=contextlib.nullcontext),
            patch.object(remote_agent, "load_managed_states", return_value=states),
            patch.object(remote_agent, "memory_mb", return_value=2048),
            patch.object(remote_agent.os, "cpu_count", return_value=2),
            patch.object(remote_agent, "save_state"),
        ):
            return remote_agent.reserve_site_capacity(candidate)

    def test_running_site_reservations_count_toward_admission(self) -> None:
        states = [
            managed_state("one.example.com"),
            managed_state("two.example.com", configured=False, status="RUNNING"),
        ]
        with self.assertRaises(remote_agent.AgentError) as caught:
            self.reserve(managed_state(configured=False, status="RUNNING"), states)
        self.assertEqual(caught.exception.stage, "capacity")

    def test_failed_unconfigured_sites_do_not_consume_a_reservation(self) -> None:
        states = [
            managed_state("one.example.com"),
            managed_state("failed.example.com", configured=False, status="FAILED"),
        ]
        self.reserve(managed_state(configured=False, status="RUNNING"), states)

    def test_candidate_is_not_counted_twice_if_already_saved_as_running(self) -> None:
        candidate = managed_state(configured=False, status="RUNNING")
        self.reserve(candidate, [managed_state("one.example.com"), dict(candidate)])

    def test_existing_configured_site_can_be_repaired_above_capacity(self) -> None:
        candidate = managed_state(status="RUNNING")
        states = [candidate, managed_state("one.example.com"), managed_state("two.example.com")]
        self.reserve(candidate, states)

    def test_overcapacity_provision_fails_before_creating_server_resources(self) -> None:
        states = [managed_state("one.example.com"), managed_state("two.example.com")]
        saved: list[dict[str, object]] = []
        with (
            patch.object(remote_agent, "load_state", return_value={}),
            patch.object(remote_agent, "load_managed_states", return_value=states),
            patch.object(remote_agent, "memory_mb", return_value=2048),
            patch.object(remote_agent.os, "cpu_count", return_value=2),
            patch.object(remote_agent, "global_lock", side_effect=contextlib.nullcontext),
            patch.object(remote_agent, "save_state", side_effect=lambda state: saved.append(dict(state))),
            patch.object(remote_agent, "write_report", return_value="/unused/report.json"),
            patch.object(remote_agent, "ensure_linux_user") as linux_user,
            patch.object(remote_agent, "ensure_database") as database,
            patch.object(remote_agent, "ensure_wordpress") as wordpress,
            patch.object(remote_agent, "configure_site") as configure,
            patch.object(remote_agent, "verify_site") as verify,
        ):
            result = remote_agent.provision_site(site_payload())
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["stage"], "capacity")
        for operation in (linux_user, database, wordpress, configure, verify):
            operation.assert_not_called()
        self.assertTrue(saved)
        self.assertEqual(saved[-1]["status"], "FAILED")


class SSLRetryRegressionTests(unittest.TestCase):
    def failed_ssl_attempt(self, *, existing_ssl: bool, probe_ready: bool) -> tuple[bool, dict[str, object]]:
        state = managed_state(enable_ssl=True, ssl_active=existing_ssl)
        certbot_result = SimpleNamespace(returncode=1, stdout="", stderr="renewal failed")
        with (
            patch.object(remote_agent, "Path", return_value=MagicMock()),
            patch.object(remote_agent, "atomic_write"),
            patch.object(remote_agent, "run", return_value=certbot_result),
            patch.object(remote_agent, "public_probe", return_value=probe_ready),
            patch.object(remote_agent, "save_state"),
            patch.object(
                remote_agent,
                "validate_ssl_certificate",
                return_value={"valid": existing_ssl, "hostname_valid": existing_ssl},
            ),
            patch.object(remote_agent, "wp_command") as wp,
            patch.object(remote_agent, "apply_ols_config") as configure,
        ):
            result = remote_agent.try_ssl(state)
        wp.assert_not_called()
        configure.assert_not_called()
        return result, state

    def test_public_probe_failure_preserves_existing_ssl(self) -> None:
        result, state = self.failed_ssl_attempt(existing_ssl=True, probe_ready=False)
        self.assertTrue(result)
        self.assertTrue(state["ssl_active"])
        self.assertTrue(state["ssl_renewal_error"])

    def test_certbot_failure_preserves_existing_ssl(self) -> None:
        result, state = self.failed_ssl_attempt(existing_ssl=True, probe_ready=True)
        self.assertTrue(result)
        self.assertTrue(state["ssl_active"])
        self.assertTrue(state["ssl_renewal_error"])

    def test_new_site_probe_failure_remains_pending_ssl(self) -> None:
        result, state = self.failed_ssl_attempt(existing_ssl=False, probe_ready=False)
        self.assertFalse(result)
        self.assertFalse(state["ssl_active"])
        self.assertTrue(state["ssl_pending_reason"])

    def test_new_site_certbot_failure_remains_pending_ssl(self) -> None:
        result, state = self.failed_ssl_attempt(existing_ssl=False, probe_ready=True)
        self.assertFalse(result)
        self.assertFalse(state["ssl_active"])
        self.assertTrue(state["ssl_pending_reason"])


class ReprovisionRegressionTests(unittest.TestCase):
    def provision(self, existing: dict[str, object], payload: dict[str, object]) -> tuple[dict, MagicMock, MagicMock]:
        current = dict(existing)

        def save(state: dict[str, object]) -> None:
            current.clear()
            current.update(state)

        def activate_ssl(state: dict[str, object]) -> bool:
            state["ssl_active"] = True
            save(state)
            return True

        with (
            patch.object(remote_agent, "load_state", side_effect=lambda _domain: dict(current)),
            patch.object(remote_agent, "save_state", side_effect=save),
            patch.object(remote_agent, "reserve_site_capacity"),
            patch.object(remote_agent, "ensure_linux_user"),
            patch.object(remote_agent, "ensure_database"),
            patch.object(remote_agent, "ensure_wordpress"),
            patch.object(remote_agent, "configure_site", return_value={}) as configure,
            patch.object(remote_agent, "try_ssl", side_effect=activate_ssl) as ssl,
            patch.object(remote_agent, "verify_site", return_value={"mandatory_ok": True}),
            patch.object(remote_agent, "write_report", return_value="/unused/report.json"),
        ):
            result = remote_agent.provision_site(payload)
        return result, configure, ssl

    def test_unchanged_verified_site_still_returns_without_reprovisioning(self) -> None:
        result, configure, ssl = self.provision(managed_state(), site_payload())
        self.assertEqual(result["stage"], "already_verified")
        configure.assert_not_called()
        ssl.assert_not_called()

    def test_enabling_ssl_on_verified_http_site_attempts_issuance(self) -> None:
        result, configure, ssl = self.provision(managed_state(), site_payload(enable_ssl=True))
        self.assertEqual(result["stage"], "complete")
        configure.assert_called_once()
        ssl.assert_called_once()

    def test_requested_ssl_cannot_early_return_while_certificate_is_pending(self) -> None:
        result, _configure, ssl = self.provision(
            managed_state(enable_ssl=True, ssl_active=False), site_payload(enable_ssl=True)
        )
        self.assertEqual(result["stage"], "complete")
        ssl.assert_called_once()

    def test_alias_and_certificate_email_changes_are_applied(self) -> None:
        for change in ({"include_www": True}, {"admin_email": "new@example.com"}):
            with self.subTest(change=change):
                result, configure, _ssl = self.provision(managed_state(), site_payload(**change))
                self.assertEqual(result["stage"], "complete")
                configure.assert_called_once()


class RedisHealthRegressionTests(unittest.TestCase):
    def test_status_parser_requires_an_exact_connected_status(self) -> None:
        for output in ("Status: Connected", "Status: connected\nClient: PhpRedis", "\x1b[32mStatus: Connected\x1b[0m"):
            with self.subTest(output=output):
                self.assertTrue(remote_agent.redis_status_connected(output))
        for output in ("Status: Not connected", "Status: disconnected", "Status: Not Connected\nPrevious status: Connected", "connected", "Client: connected", "Status: Connected with errors", ""):
            with self.subTest(output=output):
                self.assertFalse(remote_agent.redis_status_connected(output))

    def test_disconnected_redis_cannot_pass_mandatory_site_health(self) -> None:
        def wp(_state: dict, args: list[str], **_kwargs: object) -> SimpleNamespace:
            output = "Status: Not connected" if args == ["redis", "status"] else ""
            return SimpleNamespace(returncode=0, stdout=output, stderr="")

        path = MagicMock()
        path.stat.return_value.st_uid = 1000
        headers = {
            "x-litespeed-cache": "hit",
            "content-encoding": "gzip",
            "cache-control": "public, max-age=15552000",
        }
        with (
            patch.object(remote_agent, "Path", return_value=path),
            patch.object(remote_agent, "wp_command", side_effect=wp),
            patch.object(remote_agent, "local_request", return_value={"status": 200, "headers": headers}),
            patch.object(remote_agent, "wordpress_health", return_value={"permalink_ok": True, "permalink_live_tested": False, "database_ok": True}),
            patch.object(remote_agent, "validate_ssl_certificate", return_value={}),
            patch.object(remote_agent, "cloudflare_probe", return_value={}),
            patch.object(remote_agent.time, "sleep"),
        ):
            checks = remote_agent.verify_site(managed_state())
        self.assertFalse(checks["redis_connected"])
        self.assertFalse(checks["mandatory_ok"])
        self.assertEqual(remote_agent.failed_mandatory_checks(checks), ["redis_connected"])


class StdinPayloadRegressionTests(unittest.TestCase):
    def test_site_and_uninstall_decode_payloads_from_bounded_stdin(self) -> None:
        for action, function, payload in (
            ("site", "provision_site", site_payload(enable_ssl=True)),
            ("uninstall-sites", "uninstall_sites", {"domains": ["example.com", "two.example.com"]}),
        ):
            with self.subTest(action=action):
                encoded = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
                stream = MagicMock(wraps=io.StringIO(encoded + "\n"))
                result = {"status": "VERIFIED" if action == "site" else "ok"}
                with (
                    patch.object(remote_agent.sys, "stdin", stream),
                    patch.object(remote_agent, function, return_value=result) as operation,
                    patch.object(remote_agent, "emit_result") as emit,
                ):
                    exit_code = remote_agent.main([action, "--payload-stdin"])
                self.assertEqual(exit_code, 0)
                stream.read.assert_called_once_with(1_048_577)
                operation.assert_called_once_with(payload)
                emit.assert_called_once_with(result)

    def test_oversized_stdin_is_rejected_before_site_provisioning(self) -> None:
        stream = MagicMock(wraps=io.StringIO("x" * 1_048_577))
        with (
            patch.object(remote_agent.sys, "stdin", stream),
            patch.object(remote_agent, "provision_site") as provision,
            patch.object(remote_agent, "emit_result") as emit,
        ):
            exit_code = remote_agent.main(["site", "--payload-stdin"])
        self.assertEqual(exit_code, 2)
        stream.read.assert_called_once_with(1_048_577)
        provision.assert_not_called()
        failure = emit.call_args.args[0]
        self.assertEqual(failure["status"], "FAILED")
        self.assertEqual(failure["stage"], "payload")

    def test_malformed_stdin_is_reported_as_a_payload_failure(self) -> None:
        with (
            patch.object(remote_agent.sys, "stdin", io.StringIO("invalid payload")),
            patch.object(remote_agent, "provision_site") as provision,
            patch.object(remote_agent, "emit_result") as emit,
        ):
            exit_code = remote_agent.main(["site", "--payload-stdin"])
        self.assertEqual(exit_code, 2)
        provision.assert_not_called()
        self.assertEqual(emit.call_args.args[0]["stage"], "payload")


if __name__ == "__main__":
    unittest.main()
