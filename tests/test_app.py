from __future__ import annotations

import unittest
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from bagoeswp.app import BagoesWPApp
from bagoeswp.models import AuthMethod, JobResult, JobStatus


class AppBusyTests(unittest.TestCase):
    def _fake_app(self, *, failed: bool = True) -> SimpleNamespace:
        app = SimpleNamespace(
            _busy=False,
            results=[JobResult("example.com", JobStatus.FAILED)] if failed else [],
        )
        for name in (
            "start_button", "test_button", "import_button", "bulk_add_button",
            "remove_list_button", "uninstall_selected_button", "uninstall_global_button",
            "retry_button", "export_button", "stop_button", "header_status",
        ):
            setattr(app, name, SimpleNamespace(configure=Mock()))
        return app

    def test_busy_disables_retry_and_domain_mutations_after_failed_batch(self) -> None:
        app = self._fake_app()
        BagoesWPApp._set_busy(app, True)
        self.assertTrue(app._busy)
        for name in (
            "start_button", "test_button", "import_button", "bulk_add_button",
            "remove_list_button", "retry_button", "uninstall_selected_button",
            "uninstall_global_button", "export_button",
        ):
            getattr(app, name).configure.assert_called_once_with(state="disabled")

    def test_finishing_task_restores_retry_from_current_results(self) -> None:
        app = self._fake_app()
        BagoesWPApp._set_busy(app, False)
        self.assertFalse(app._busy)
        app.retry_button.configure.assert_called_once_with(state="normal")
        app.export_button.configure.assert_called_once_with(state="normal")

    def test_empty_results_keep_retry_and_export_disabled(self) -> None:
        app = self._fake_app(failed=False)
        BagoesWPApp._set_busy(app, False)
        app.retry_button.configure.assert_called_once_with(state="disabled")
        app.export_button.configure.assert_called_once_with(state="disabled")

    def test_connection_check_does_not_enable_cancel_provisioning(self) -> None:
        app = self._fake_app()
        BagoesWPApp._set_busy(app, True, cancellable=False)
        app.stop_button.configure.assert_called_once_with(state="disabled")

    def test_busy_callbacks_return_before_starting_other_work(self) -> None:
        # These callbacks must be safe even if invoked from a binding while disabled.
        app = SimpleNamespace(_busy=True)
        for name in (
            "_test_connection", "_start", "_retry_failed", "_uninstall_selected",
            "_uninstall_global", "_import_csv", "_bulk_add", "_remove_selected",
        ):
            with self.subTest(callback=name):
                getattr(BagoesWPApp, name)(app)
        BagoesWPApp._run_uninstall(app, ["example.com"], global_mode=False)

    def test_ppk_server_config_does_not_require_removed_puttygen_widget(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            key_path = Path(directory) / "server.ppk"
            key_path.write_text("fixture", encoding="utf-8")
            values = {
                "host": "127.0.0.1", "port": "22", "user": "ubuntu", "auth": "PPK",
                "password": "", "key": str(key_path), "passphrase": "",
                "sudo": "", "concurrent": "2", "prepare": True,
            }
            app = SimpleNamespace(**{
                name + "_var": SimpleNamespace(get=lambda value=value: value)
                for name, value in values.items()
            })
            config = BagoesWPApp._server_config(app)
        self.assertEqual(config.auth_method, AuthMethod.PPK)
        self.assertEqual(config.username, "ubuntu")
        self.assertEqual(config.puttygen_path, "")


if __name__ == "__main__":
    unittest.main()
