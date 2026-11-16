#!/usr/bin/env python3
"""Dry-run regression for the workbench-only UI build scope (no builds or Go)."""

import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class UpdateUIScopeTest(unittest.TestCase):
    def dry_run(self, *options: str) -> str:
        return subprocess.check_output(
            ["make", "-j1", "-n", "update-ui", "GOTESTSUM_EXISTS=no", *options],
            cwd=ROOT,
            text=True,
        )

    def test_workbench_only_excludes_static_reports(self):
        commands = self.dry_run("WORKBENCH_ONLY=1")
        self.assertNotIn("platform/static-reports", commands)
        self.assertNotIn("public/static-reports", commands)
        self.assertIn("cd platform/vigolium-workbench && bun install && bun run build", commands)
        self.assertIn("ui_source_manifest.py --write", commands)

    def test_default_keeps_both_ui_builds(self):
        commands = self.dry_run("WORKBENCH_ONLY=0")
        self.assertIn("cd platform/static-reports && bun install && bun run build", commands)
        self.assertIn("cd platform/vigolium-workbench && bun install && bun run build", commands)
        self.assertIn("ui_source_manifest.py --write", commands)


if __name__ == "__main__":
    unittest.main()
