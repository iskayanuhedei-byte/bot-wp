from types import SimpleNamespace
import unittest
from unittest.mock import patch

from bagoeswp.resources import remote_agent


class MariaDBCompatibilityTests(unittest.TestCase):
    def test_generated_config_avoids_removed_mariadb_10_11_option(self):
        # Ubuntu 24.04 supplies MariaDB 10.11, which removed the old InnoDB
        # instances option. A non-loose unknown variable aborts server startup.
        with (
            patch.object(remote_agent, "atomic_write") as write,
            patch.object(remote_agent, "run", return_value=SimpleNamespace(stdout="1\n")) as run,
        ):
            plan = remote_agent.resource_plan(8192, 4, 5)
            remote_agent.tune_mariadb(plan)
        config = write.call_args.args[1]
        self.assertNotIn("innodb_buffer_pool_instances", config)
        self.assertIn(f"innodb_buffer_pool_size={plan['mariadb_mb']}M", config)
        run.assert_any_call(["systemctl", "restart", "mariadb"], timeout=120)
        run.assert_any_call(["mariadb", "--protocol=socket", "-Nse", "SELECT 1"], quiet=True)


if __name__ == "__main__":
    unittest.main()
