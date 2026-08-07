# Copyright 2026 harrylabsj
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""kiwi-catalog CLI tests (phase 3 迁移: catalog command group)."""

from __future__ import annotations

import argparse
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from kiwi_catalog.cli import build_parser, main


class CatalogCliTest(unittest.TestCase):
    def _run(self, db_file: Path, *args: str) -> str:
        output = StringIO()
        with redirect_stdout(output):
            try:
                main(["--db", str(db_file), *args])
            except SystemExit:
                pass
        return output.getvalue()

    def test_all_catalog_commands_registered(self) -> None:
        parser = build_parser()
        subparsers = [
            a for a in parser._actions if isinstance(a, argparse._SubParsersAction)
        ][0]
        catalog = subparsers.choices["catalog"]
        catalog_cmds = list(catalog._actions[-1].choices.keys())
        self.assertEqual(
            sorted(catalog_cmds),
            ["claim", "doctor", "get", "refresh", "register", "reinstate",
             "search", "stats", "suspend", "verify"],
        )

    def test_stats_outputs_runtime_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "catalog.sqlite"
            out = self._run(db, "catalog", "stats", "--format", "json")
            stats = json.loads(out)
            self.assertEqual(stats["catalog_agent_count"], 0)
            self.assertIn("runtime_metrics", stats)
            self.assertIn("derived", stats["runtime_metrics"])

    def test_register_then_search_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "catalog.sqlite"
            reg_out = self._run(db, "catalog", "register", "--domain", "merchant.example")
            self.assertIn("Registered catalog agent: cagt_", reg_out)
            search_out = self._run(db, "catalog", "search", "--q", "merchant")
            self.assertIn("cagt_", search_out)

    def test_owner_token_argument_accepted(self) -> None:
        parser = build_parser()
        subparsers = [
            a for a in parser._actions if isinstance(a, argparse._SubParsersAction)
        ][0]
        catalog = subparsers.choices["catalog"]
        claim = catalog._actions[-1].choices["claim"]
        opts = {a.dest for a in claim._actions}
        self.assertIn("owner_token", opts)
        self.assertNotIn("merchant_token", opts)


if __name__ == "__main__":
    unittest.main()
