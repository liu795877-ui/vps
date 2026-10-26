"""Local fault injection for the frozen publisher; no SSH or service calls."""

import ast
import copy
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

import update_operations as publisher


class PublisherTransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="operations-publisher-review-")
        self.addCleanup(self.temp.cleanup)
        self.stage = Path(self.temp.name) / "stage"
        self.stage.mkdir()
        (self.stage / "manifest.json").write_text(json.dumps({"files": []}), encoding="utf-8")
        tree = ast.parse(publisher.PROGRAM)
        # Load definitions only, removing the remote action dispatcher itself.
        dispatcher = next(index for index, item in enumerate(tree.body) if isinstance(item, ast.Try))
        definitions = ast.Module(body=tree.body[:dispatcher], type_ignores=[])
        ast.fix_missing_locations(definitions)
        self.namespace = {"STAGE": str(self.stage), "ACTION": "local-review"}
        exec(compile(definitions, "operations_remote_definitions", "exec"), self.namespace)
        self.target = Path(self.temp.name) / "opt"
        self.target.mkdir()
        self.namespace["target"] = self.target
        self.commands = []
        self.namespace["run"] = lambda args, **kwargs: self.commands.append(args) or SimpleNamespace(stdout=b"")
        self.namespace["start_panel"] = lambda: self.commands.append(["synthetic-panel-ready"])
        self.namespace["wait_proxy"] = lambda user: None
        self.namespace["atomic"] = lambda path, payload, info: path.write_bytes(payload)
        self.before = {"users": [], "configs": {}, "states": {}}
        self.namespace["stable_preservation"] = lambda before: copy.deepcopy(before)
        (self.stage / "before").mkdir()
        self.write_private("before/snapshot.private.json", self.before)

    def write_private(self, name, value):
        self.namespace["private_json"](self.stage / name, value)

    def entry(self, name, original, candidate, actual=None):
        path = self.target / name
        if original is not None:
            path.write_bytes(original)
            backup = self.stage / "before/files" / name
            backup.parent.mkdir(parents=True, exist_ok=True)
            backup.write_bytes(original)
        # The real publisher stores absolute Linux paths under before/files.
        # Use a logical relative backup key in this Windows-only local fixture.
        entry = {"path": str(path), "existed": original is not None, "backup": name,
                 "before_sha256": hashlib.sha256(original).hexdigest() if original is not None else None,
                 "after_sha256": hashlib.sha256(candidate).hexdigest(), "attributes": {}}
        if actual is not None:
            path.write_bytes(actual)
        return entry

    def transaction(self, entries, **kwargs):
        value = {"installed": entries, "restarted": [], "vendor_install_started": False,
                 "vendor_installed": False, "vendor_existed": False}
        value.update(kwargs)
        self.write_private("transaction.private.json", value)
        return value

    def test_planned_and_installed_files_restore_without_touching_unmodified_bytes(self):
        entries = [self.entry("old.py", b"old", b"new", b"new"),
                   self.entry("not-yet.py", b"unchanged", b"candidate"),
                   self.entry("new.py", None, b"created", b"created"),
                   self.entry("not-created.py", None, b"planned")]
        self.transaction(entries)
        self.namespace["rollback"]()
        self.assertEqual((self.target / "old.py").read_bytes(), b"old")
        self.assertEqual((self.target / "not-yet.py").read_bytes(), b"unchanged")
        self.assertFalse((self.target / "new.py").exists())
        self.assertFalse((self.target / "not-created.py").exists())
        self.assertTrue(self.namespace["result"]["configuration_rollback_succeeded"])

    def test_concurrent_account_change_stops_all_restores_before_first_write(self):
        first = self.entry("source.py", b"old-source", b"new-source", b"new-source")
        second = self.entry("state.json", b"old-state", b"migrated-state", b"legitimate-user-change")
        self.transaction([first, second])
        with self.assertRaisesRegex(RuntimeError, "concurrent change"):
            self.namespace["rollback"]()
        self.assertEqual((self.target / "source.py").read_bytes(), b"new-source")
        self.assertEqual((self.target / "state.json").read_bytes(), b"legitimate-user-change")

    def test_vendor_move_failure_restores_original_directory_before_any_restart(self):
        old = self.stage / "before/vendor"
        old.mkdir()
        (old / "old.py").write_bytes(b"old-dependency")
        hashes = self.namespace["vendor_hashes"](old)
        self.transaction([], vendor_install_started=True, vendor_existed=True,
                         vendor_before_sha256=hashes, vendor_after_sha256={"new.py": "synthetic"})
        self.namespace["rollback"]()
        self.assertEqual((self.target / "vendor/old.py").read_bytes(), b"old-dependency")
        self.assertFalse(old.exists())

    def test_modified_vendor_stops_source_restoration_and_ignores_only_python_caches(self):
        entry = self.entry("source.py", b"old-source", b"new-source", b"new-source")
        vendor = self.target / "vendor"
        vendor.mkdir()
        dependency = vendor / "dependency.py"
        dependency.write_bytes(b"installed")
        hashes = self.namespace["vendor_hashes"](vendor)
        (vendor / "__pycache__").mkdir()
        (vendor / "__pycache__/dependency.pyc").write_bytes(b"runtime-cache")
        self.assertEqual(self.namespace["vendor_hashes"](vendor), hashes)
        dependency.write_bytes(b"external-upgrade")
        self.transaction([entry], vendor_install_started=True, vendor_existed=False,
                         vendor_before_sha256={}, vendor_after_sha256=hashes)
        with self.assertRaisesRegex(RuntimeError, "dependency change"):
            self.namespace["rollback"]()
        self.assertEqual((self.target / "source.py").read_bytes(), b"new-source")

    def test_stats_migration_preserves_every_existing_identity_rule_exit_and_history(self):
        import sys
        sys.path.insert(0, str(publisher.ROOT))
        import configure_reality
        state_path, config_path = self.target / "state.json", self.target / "config.json"
        config = configure_reality.server_config("11111111-1111-4111-8111-111111111111", "A" * 43, "0123456789abcdef")
        config["inbounds"][0]["port"] = 443
        config["custom_retained"] = {"value": "preserve unknown non-stats fields"}
        state = {"base": copy.deepcopy(config), "managed_hash": "old-hash", "auto_id": "old-auto",
                 "public": "old-public", "short": "old-short", "rule_token": "old-rule",
                 "active_id": "selected-exit", "exits": [{"client_id": "old-fixed"}],
                 "applied_exits": [{"client_id": "old-fixed"}], "domains": ["proxy.example"],
                 "direct_domains": ["direct.example"], "routing_mode": "smart", "profile": "old-full-yaml",
                 "history": [{"config": copy.deepcopy(config)}], "updated": "original-timestamp"}
        state_path.write_text(json.dumps(state), encoding="utf-8")
        config_path.write_text(json.dumps(config), encoding="utf-8")
        user = {"id": "admin", "port": 443, "state": str(state_path), "config": str(config_path)}
        mutations = self.namespace["migration_candidates"]({"users": [user]})
        generated_config = json.loads(mutations[0][1])
        generated_state = json.loads(mutations[1][1])
        self.assertEqual(generated_config["inbounds"][0]["settings"]["clients"][0]["id"],
                         config["inbounds"][0]["settings"]["clients"][0]["id"])
        self.assertEqual(generated_config["inbounds"][0]["streamSettings"], config["inbounds"][0]["streamSettings"])
        self.assertEqual(generated_config["custom_retained"], config["custom_retained"])
        for key in state:
            if key != "managed_hash":
                self.assertEqual(generated_state[key], state[key])
        self.assertEqual(generated_state["managed_hash"], hashlib.sha256(mutations[0][1]).hexdigest())
        self.assertEqual(generated_config["api"]["listen"], "127.0.0.1:15443")
        self.assertEqual(generated_config["api"]["services"], ["StatsService"])
        self.assertTrue(any(command[1:4] == ["run", "-test", "-config"] for command in self.commands))
        # Local review never installs those candidate bytes.
        self.assertEqual(json.loads(state_path.read_text(encoding="utf-8")), state)
        self.assertEqual(json.loads(config_path.read_text(encoding="utf-8")), config)


if __name__ == "__main__":
    unittest.main()
