import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from discovery.kiterunner import KiteRunner


class KiterunnerSeedScanTests(unittest.TestCase):
    @patch("discovery.kiterunner.subprocess.run")
    def test_seed_paths_compile_to_kitebuilder_and_run_as_get_api_scan(self, run):
        commands = []
        seed_file_contents = []

        def run_command(command, **kwargs):
            commands.append(command)
            if command[1:3] == ["kb", "convert"]:
                seed_file_contents.append(Path(command[3]).read_text(encoding="utf-8"))
                Path(command[4]).write_bytes(b"compiled")
                return subprocess.CompletedProcess(command, 0, "", "")
            output = json.dumps({"method": "GET", "path": "/api/orders"})
            return subprocess.CompletedProcess(command, 0, output, "")

        run.side_effect = run_command
        outcome = KiteRunner().kiterunner_seed_scan(
            "http://localhost:8085",
            [
                "/api/orders",
                "/api/orders",
                "/api/:orderId",
                "/api/orders?include=items",
                "/api/inventory",
            ],
            num=1000,
            timeout_seconds=12,
        )

        self.assertEqual(seed_file_contents, ["/api/orders\n/api/inventory\n"])
        self.assertEqual(len(commands), 2)
        scan_command = commands[1]
        self.assertEqual(
            scan_command[1:3], ["scan", "localhost:8085"]
        )
        self.assertIn("-A=apiroutes-260227:100", scan_command)
        self.assertIn("--force-method", scan_command)
        self.assertEqual(scan_command[scan_command.index("--force-method") + 1], "GET")
        self.assertEqual(scan_command[scan_command.index("--max-redirects") + 1], "0")
        self.assertTrue(scan_command[scan_command.index("-w") + 1].endswith("seeds.kite"))
        self.assertEqual(outcome["results"][0]["discovery_phase"], "seeded")
        self.assertEqual(outcome["target"], "http://localhost:8085")
        self.assertEqual(outcome["seed_count"], 2)
        self.assertEqual(outcome["exit_code"], 0)
        self.assertEqual(outcome["result_count"], 1)
        self.assertEqual(run.call_args_list[1].kwargs["timeout"], 12)

    @patch("discovery.kiterunner.subprocess.run")
    def test_empty_static_seed_set_does_not_run_kiterunner(self, run):
        outcome = KiteRunner().kiterunner_seed_scan(
            "http://localhost:8085",
            ["/api/${id}", "/api/:id", "/api/orders?active=true"],
        )
        self.assertEqual(outcome["results"], [])
        self.assertEqual(outcome["seed_count"], 0)
        self.assertIsNone(outcome["exit_code"])
        run.assert_not_called()

    def test_target_normalization_preserves_https_and_custom_port(self):
        self.assertEqual(
            KiteRunner()._normalize_target("https://localhost:9000"),
            "https://localhost:9000",
        )
        self.assertEqual(
            KiteRunner()._command_target("https://localhost:9000"),
            "localhost:9000",
        )

    @patch("discovery.kiterunner.subprocess.run")
    def test_regular_scan_passes_kiterunner_host_without_url_scheme(self, run):
        run.return_value = subprocess.CompletedProcess(
            ["kr.exe", "scan", "localhost:8085"], 0, "", ""
        )

        outcome = KiteRunner().kiterunner_scan(
            "http://localhost:8085",
            1000,
            return_outcome=True,
        )

        command = run.call_args.args[0]
        self.assertEqual(command[1:3], ["scan", "localhost:8085"])
        self.assertEqual(outcome["target"], "http://localhost:8085")
        self.assertEqual(outcome["command"], command)

    @patch("discovery.kiterunner.subprocess.run")
    def test_seeded_scan_failure_reports_command_exit_and_diagnostics(self, run):
        def run_command(command, **kwargs):
            if command[1:3] == ["kb", "convert"]:
                Path(command[4]).write_bytes(b"compiled")
                return subprocess.CompletedProcess(command, 0, "", "")
            return subprocess.CompletedProcess(
                command, 2, "", "gateway connection failed"
            )

        run.side_effect = run_command

        with self.assertRaisesRegex(
            RuntimeError,
            r"exit_code=2.*gateway connection failed",
        ):
            KiteRunner().kiterunner_seed_scan(
                "http://localhost:8085", ["/api/orders"]
            )


if __name__ == "__main__":
    unittest.main()
