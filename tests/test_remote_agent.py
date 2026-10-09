from __future__ import annotations

import inspect
import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from bagoeswp.resources import remote_agent


def sample_state(domain: str = "example.com") -> dict[str, object]:
    identity = remote_agent.site_identity(domain)
    return {
        **identity,
        "domain": domain,
        "admin_email": "admin@example.com",
        "include_www": True,
        "ssl_active": False,
        "configured": True,
    }


class RemoteAgentTests(unittest.TestCase):
    def test_meminfo_detects_memory_and_swap(self) -> None:
        parsed = remote_agent.parse_meminfo(
            "MemTotal:       8388608 kB\nMemAvailable:   4194304 kB\n"
            "SwapTotal:      2097152 kB\nSwapFree:       1048576 kB\n"
        )
        self.assertEqual(parsed["MemTotal"], 8192)
        self.assertEqual(parsed["SwapTotal"], 2048)

    def test_percentile_interpolates(self) -> None:
        self.assertEqual(remote_agent.percentile([10.0, 20.0, 30.0], 0.5), 20.0)
        self.assertEqual(remote_agent.percentile([], 0.95), 0.0)

    def test_resource_plan_caps_workers(self) -> None:
        small = remote_agent.resource_plan(2048, 4, 10)
        large = remote_agent.resource_plan(32768, 16, 10)
        self.assertEqual(small["ols_workers"], 1)
        self.assertEqual(large["ols_workers"], 2)
        self.assertGreaterEqual(small["php_children_per_site"], 1)
        self.assertLessEqual(large["php_children_per_site"], 10)

    def test_resource_budgets_fit_supported_ram(self) -> None:
        for memory in (2048, 4096, 8192, 32768):
            plan = remote_agent.resource_plan(memory, 8, 10)
            allocated = sum(
                plan[key]
                for key in (
                    "os_reserve_mb",
                    "mariadb_mb",
                    "redis_mb",
                    "ols_budget_mb",
                    "php_budget_mb",
                )
            )
            self.assertLessEqual(allocated, memory)

    def test_php_max_connections_matches_children(self) -> None:
        state = sample_state()
        plan = remote_agent.resource_plan(8192, 4, 10)
        config = remote_agent.render_vhost_config(state, plan)
        children = plan["php_children_per_site"]
        self.assertIn(f"maxConns                {children}", config)
        self.assertIn(f"PHP_LSAPI_CHILDREN={children}", config)
        self.assertIn("extUser                 bw", config)
        self.assertNotIn("extUser                 root", config)

    def test_vhost_enables_browser_cache_and_compression(self) -> None:
        config = remote_agent.render_vhost_config(
            sample_state(), remote_agent.resource_plan(8192, 4, 4)
        )
        self.assertIn("enableGzip                1", config)
        self.assertIn("enableExpires           1", config)
        self.assertIn("image/*=A15552000", config)

    def test_optional_lsphp_package_names_are_not_precheck_fatal(self) -> None:
        required = ["openlitespeed", "lsphp83", "lsphp83-common"]
        optional = ["lsphp83-gd", "lsphp83-mbstring", "lsphp83-xml", "lsphp83-zip"]
        selected, missing = remote_agent.select_packages(
            required, optional, set(required)
        )
        self.assertEqual(selected, required)
        self.assertEqual(missing, [])

    def test_required_lsphp_package_is_still_strict(self) -> None:
        selected, missing = remote_agent.select_packages(
            ["openlitespeed", "lsphp83"], ["lsphp83-zip"], {"openlitespeed"}
        )
        self.assertEqual(selected, ["openlitespeed"])
        self.assertEqual(missing, ["lsphp83"])

    def test_php_runtime_accepts_gd_or_imagick(self) -> None:
        base = {"mysqli", "curl", "mbstring", "redis", "xml", "zip", "zend opcache"}
        with_gd = remote_agent.php_runtime_checks(base | {"gd"}, True)
        with_imagick = remote_agent.php_runtime_checks(base | {"imagick"}, True)
        without_image = remote_agent.php_runtime_checks(base, True)
        self.assertTrue(with_gd["image_processing"])
        self.assertTrue(with_imagick["image_processing"])
        self.assertFalse(without_image["image_processing"])

    def test_litespeed_stack_refreshes_official_repository(self) -> None:
        source = inspect.getsource(remote_agent.install_litespeed_stack)
        self.assertIn("ensure_litespeed_repository()", source)
        self.assertNotIn('package_available("openlitespeed")', source)

    def test_systemd_alias_is_enabled_through_canonical_unit(self) -> None:
        calls: list[list[str]] = []

        def fake_run(args, **_kwargs):
            calls.append(args)
            stdout = "lshttpd.service\n" if "show" in args else ""
            return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

        with patch.object(remote_agent, "run", side_effect=fake_run):
            canonical = remote_agent.enable_and_start_service("lsws")
        self.assertEqual(canonical, "lshttpd.service")
        self.assertIn(["systemctl", "enable", "lshttpd.service"], calls)
        self.assertIn(["systemctl", "start", "lsws"], calls)

    def test_ols_server_identity_is_parsed_from_main_config(self) -> None:
        user, group = remote_agent.parse_ols_server_identity(
            "serverName test\nuser nobody\ngroup nogroup\npriority 0\n"
        )
        self.assertEqual((user, group), ("nobody", "nogroup"))

    def test_only_known_example_ownership_warnings_are_tolerated(self) -> None:
        warning = (
            "[WARN] [config:server:vhosts:vhost:Example] Uid of "
            "/usr/local/lsws/Example/html/ is 0, smaller than minimum requirement 11, "
            "use server uid!\n"
            "[WARN] [config:server:vhosts:vhost:Example] Gid of "
            "/usr/local/lsws/Example/html/ is 0, smaller than minimum requirement 10, "
            "use server gid!"
        )
        self.assertTrue(remote_agent.only_known_example_ownership_warnings(warning))
        self.assertFalse(
            remote_agent.only_known_example_ownership_warnings(
                warning + "\n[ERROR] invalid listener configuration"
            )
        )

    def test_config_test_repairs_example_before_accepting_known_warning(self) -> None:
        warning = (
            "[WARN] [config:server:vhosts:vhost:Example] Uid of "
            "/usr/local/lsws/Example/html/ is 0, smaller than minimum requirement 11, "
            "use server uid!"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "bin/openlitespeed"
            binary.parent.mkdir()
            binary.touch()
            with (
                patch.object(remote_agent, "OLS_ROOT", root),
                patch.object(remote_agent, "repair_packaged_example_ownership") as repair,
                patch.object(
                    remote_agent,
                    "run",
                    return_value=SimpleNamespace(returncode=1, stdout=warning, stderr=""),
                ),
            ):
                remote_agent.config_test()
            repair.assert_called_once_with()

    def test_uninstall_payload_normalizes_and_deduplicates(self) -> None:
        domains = remote_agent.validate_uninstall_payload(
            {"domains": ["HTTPS://Example.com/path", "www.example.com", "two.example.com"]}
        )
        self.assertEqual(domains, ["example.com", "two.example.com"])

    def test_uninstall_rejects_tampered_site_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_dir = Path(directory)
            state = sample_state()
            state["linux_user"] = "root"
            with patch.object(remote_agent, "STATE_DIR", state_dir):
                remote_agent.state_path("example.com").write_text(
                    json.dumps(state), encoding="utf-8"
                )
                with self.assertRaisesRegex(remote_agent.AgentError, "linux_user"):
                    remote_agent.verified_managed_state("example.com")

    def test_detach_state_is_restored_when_ols_config_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_dir = Path(directory)
            state = sample_state()
            state_path = state_dir / "example.com.json"
            original = json.dumps(state, indent=2)
            state_path.write_text(original, encoding="utf-8")
            with (
                patch.object(remote_agent, "STATE_DIR", state_dir),
                patch.object(remote_agent, "apply_ols_config", side_effect=RuntimeError("invalid")),
            ):
                with self.assertRaisesRegex(RuntimeError, "invalid"):
                    remote_agent.detach_site_states([state])
            self.assertEqual(state_path.read_text(encoding="utf-8"), original)

    def test_safe_remove_tree_stays_inside_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"
            target = root / "bw-test"
            outside = Path(directory) / "outside"
            target.mkdir(parents=True)
            outside.mkdir()
            remote_agent.safe_remove_tree(target, root, "bw-test")
            self.assertFalse(target.exists())
            with self.assertRaises(remote_agent.AgentError):
                remote_agent.safe_remove_tree(outside, root, "outside")

    def test_global_uninstall_never_purges_shared_stack_packages(self) -> None:
        source = inspect.getsource(remote_agent.remove_global_manager)
        self.assertNotIn("apt-get", source)
        self.assertNotIn("purge", source)

    def test_browser_cache_header_must_match_long_ttl(self) -> None:
        self.assertEqual(
            remote_agent.browser_cache_seconds({"cache-control": "public, max-age=15552000"}),
            15552000,
        )
        self.assertEqual(remote_agent.browser_cache_seconds({"cache-control": "max-age=60"}), 60)

    def test_wordpress_rewrite_rules_are_created_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            htaccess = Path(directory) / ".htaccess"
            htaccess.write_text("# custom rule\n", encoding="utf-8")
            self.assertTrue(remote_agent.ensure_wordpress_rewrite_rules(htaccess))
            first = htaccess.read_text(encoding="utf-8")
            self.assertIn("# custom rule", first)
            self.assertIn("RewriteRule . /index.php [L]", first)
            self.assertFalse(remote_agent.ensure_wordpress_rewrite_rules(htaccess))
            self.assertEqual(htaccess.read_text(encoding="utf-8"), first)

    def test_ssl_reload_occurs_after_redirect_is_written(self) -> None:
        source = inspect.getsource(remote_agent.try_ssl)
        self.assertLess(source.index("add_https_redirect"), source.index("apply_ols_config()"))

    def test_failed_check_list_excludes_ssl_pending_and_aggregate(self) -> None:
        checks = {
            "mandatory_checks": ["wp_core", "permalink_live_ok"],
            "wp_core": True,
            "permalink_live_ok": False,
            "ssl_pending": False,
            "mandatory_ok": False,
        }
        self.assertEqual(
            remote_agent.failed_mandatory_checks(checks), ["permalink_live_ok"]
        )

    def test_performance_requires_every_threshold(self) -> None:
        checks = {"mandatory_ok": True, "browser_cache": True, "compression": True}
        benchmark = {
            "p95_ms": 100,
            "cache_hit_pct": 100,
            "error_rate_pct": 0,
            "peak_cpu_pct": 50,
            "peak_memory_pct": 60,
            "swap_growth_mb": 0,
        }
        self.assertTrue(remote_agent.assess_performance(checks, benchmark)["optimal"])
        benchmark["cache_hit_pct"] = 50
        assessment = remote_agent.assess_performance(checks, benchmark)
        self.assertFalse(assessment["optimal"])
        self.assertIn("cache_hit_ratio", assessment["failed"])

    def test_adaptive_tuning_is_bounded(self) -> None:
        pressured = {
            "example.com": {
                "benchmark": {
                    "peak_cpu_pct": 95,
                    "peak_memory_pct": 70,
                    "swap_growth_mb": 0,
                    "error_rate_pct": 0,
                }
            }
        }
        candidate, reason = remote_agent.choose_php_children(3, 4, pressured)
        self.assertEqual((candidate, reason), (2, "resource_pressure"))
        candidate, _reason = remote_agent.choose_php_children(1, 4, pressured)
        self.assertEqual(candidate, 1)

    def test_adaptive_tuning_recovers_only_to_safe_baseline(self) -> None:
        healthy = {
            "example.com": {
                "benchmark": {
                    "peak_cpu_pct": 40,
                    "peak_memory_pct": 60,
                    "swap_growth_mb": 0,
                    "error_rate_pct": 0,
                }
            }
        }
        candidate, reason = remote_agent.choose_php_children(2, 3, healthy)
        self.assertEqual((candidate, reason), (3, "headroom_recovery"))

    def test_capacity_gate_prevents_false_optimal_status(self) -> None:
        results = {
            "example.com": {
                "mandatory_ok": True,
                "final_status": "OPTIMAL",
                "performance": {"optimal": True, "failed": []},
            }
        }
        plan = remote_agent.resource_plan(2048, 2, 10)
        remote_agent.apply_capacity_gate(results, plan)
        self.assertEqual(results["example.com"]["final_status"], "VERIFIED")
        self.assertIn("php_capacity", results["example.com"]["performance"]["failed"])

    def test_batch_pressure_prevents_false_optimal_status(self) -> None:
        results = {
            "example.com": {
                "mandatory_ok": True,
                "final_status": "OPTIMAL",
                "benchmark": {"peak_cpu_pct": 40, "peak_memory_pct": 50, "swap_growth_mb": 0},
                "performance": {"optimal": True, "failed": []},
            }
        }
        batch = {
            "p95_ms": 200,
            "error_rate_pct": 0,
            "cache_hit_pct": 100,
            "peak_cpu_pct": 95,
            "peak_memory_pct": 70,
            "swap_growth_mb": 0,
        }
        remote_agent.apply_batch_gate(results, batch)
        self.assertEqual(results["example.com"]["final_status"], "VERIFIED")
        self.assertIn("batch_peak_cpu", results["example.com"]["performance"]["failed"])

    def test_ssl_validation_never_disables_certificate_checks(self) -> None:
        source = inspect.getsource(remote_agent.validate_ssl_certificate)
        self.assertIn("ssl.create_default_context", source)
        self.assertNotIn("CERT_NONE", source)

    def test_manager_config_is_deterministic(self) -> None:
        a = sample_state("b.example.com")
        b = sample_state("a.example.com")
        first = remote_agent.render_manager_config([a, b])
        second = remote_agent.render_manager_config([b, a])
        self.assertEqual(first, second)

    def test_database_grant_is_not_global(self) -> None:
        source = inspect.getsource(remote_agent.ensure_database)
        self.assertNotIn("ON *.*", source)
        self.assertIn("ON `{db_name}`.*", source)

    def test_cleanup_only_deletes_inside_allowlisted_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "cache"
            outside = Path(directory) / "outside.txt"
            root.mkdir()
            old = root / "old.cache"
            old.write_text("cache", encoding="utf-8")
            outside.write_text("keep", encoding="utf-8")
            old_time = time.time() - 10 * 86400
            old.touch()
            import os

            os.utime(old, (old_time, old_time))
            count, _size = remote_agent.delete_old_files(root, 7, all_files=True)
            self.assertEqual(count, 1)
            self.assertFalse(old.exists())
            self.assertTrue(outside.exists())


if __name__ == "__main__":
    unittest.main()
