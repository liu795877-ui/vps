"""Encryption, restore isolation/rollback and genuine traffic enforcement tests."""

import base64
import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from panel import accounts, backups, server, telemetry


class Controls:
    def __init__(self):
        self.calls = []
        self.fail_once = False

    def apply(self, blocked, rates):
        self.calls.append((set(blocked), dict(rates)))
        if self.fail_once:
            self.fail_once = False
            raise RuntimeError("kernel refused update")


class Fixture(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory(prefix="panel-operations-")
        self.addCleanup(td.cleanup)
        self.directory = Path(td.name)
        self.owner = server.Manager(self.directory / "owner", "8.8.8.8",
                                    self.directory / "owner" / "config.json", demo=True)
        self.auth_path = self.owner.directory / "auth.private.json"
        server.atomic_write(self.auth_path, server.json_bytes(server.password_record("owner-password-2026")))
        self.accounts = accounts.Accounts(self.owner, self.auth_path, demo=True)
        self.member = self.accounts.create_user({"username": "member_a", "password": "member-password-2026",
                                                "display_name": "成员 A"})
        self.clock_value = 1791500000.0

    def clock(self):
        return self.clock_value


class TrafficTests(Fixture):
    def setUp(self):
        super().setUp()
        self.controls = Controls()
        self.statistics = {}
        self.fail_queries = False
        self.epoch = "MainPID=10\nExecMainStartTimestampMonotonic=1234"
        self.traffic = telemetry.Telemetry(self.accounts, controls=self.controls,
                                           runner=self.run_command, clock=self.clock)

    def run_command(self, args, check=True):
        if self.fail_queries:
            raise RuntimeError("unavailable")
        if args[0] == "ss":
            return SimpleNamespace(stdout=b"0 0 8.8.8.8:1443 1.1.1.1:5000\n", returncode=0)
        if args[0] == "systemctl":
            return SimpleNamespace(stdout=self.epoch.encode(), returncode=0)
        port = int(next(arg.split(":")[-1] for arg in args if arg.startswith("--server="))) - 15000
        stats = self.statistics.get(port, {"up": 0, "down": 0})
        payload = {"stat": [{"name": "user>>>panel-auto@exits.invalid>>>traffic>>>" + direction,
                              "value": str(value)} for direction, value in
                             (("uplink", stats["up"]), ("downlink", stats["down"]))]}
        return SimpleNamespace(stdout=json.dumps(payload).encode(), returncode=0)

    def test_augmentation_preserves_routing_credentials_and_is_private(self):
        base = copy.deepcopy(self.owner.state["base"])
        base["inbounds"][0]["settings"]["clients"].append({"id": "unchanged", "email": "route@example"})
        before = copy.deepcopy(base)
        result = telemetry.augment_config(base)
        self.assertEqual(base, before)
        self.assertEqual(len(result["inbounds"]), 1)
        self.assertEqual(result["inbounds"][0]["settings"]["clients"][1]["email"], "route@example")
        self.assertEqual(result["inbounds"][0]["settings"]["clients"][0]["id"],
                         before["inbounds"][0]["settings"]["clients"][0]["id"])
        self.assertTrue(telemetry.validate_augmentation(result))
        result["api"]["listen"] = "0.0.0.0:15443"
        with self.assertRaises(ValueError):
            telemetry.validate_augmentation(result)

    def test_real_counters_deltas_speeds_isolation_and_restart_reset(self):
        port = self.member["port"]
        self.statistics[port] = {"up": 100, "down": 300}
        self.traffic.tick()
        self.assertEqual(self.traffic.snapshot(self.member["id"])["total_bytes"], 400)
        self.assertEqual(self.traffic.snapshot("admin")["total_bytes"], 0)
        self.clock_value += 10
        self.statistics[port] = {"up": 200, "down": 600}
        self.traffic.tick()
        snapshot = self.traffic.snapshot(self.member["id"])
        self.assertEqual((snapshot["up_rate"], snapshot["down_rate"], snapshot["connections"]), (10, 30, 1))
        reloaded = telemetry.Telemetry(self.accounts, controls=self.controls, runner=self.run_command, clock=self.clock)
        reloaded.tick()
        self.assertEqual(reloaded.snapshot(self.member["id"])["total_bytes"], 800)
        self.clock_value += 10
        self.statistics[port] = {"up": 20, "down": 60}
        reloaded.tick()
        self.assertEqual(reloaded.snapshot(self.member["id"])["total_bytes"], 880)
        self.clock_value += 10
        self.epoch = "MainPID=11\nExecMainStartTimestampMonotonic=4567"
        self.statistics[port] = {"up": 100, "down": 300}
        reloaded.tick()
        self.assertEqual(reloaded.snapshot(self.member["id"])["total_bytes"], 1280)

    def test_quota_pauses_only_entrance_and_month_reset_unblocks(self):
        self.statistics[self.member["port"]] = {"up": 100, "down": 300}
        self.traffic.tick()
        self.traffic.set_limits(self.member["id"], 400, 1000000)
        snapshot = self.traffic.snapshot(self.member["id"])
        self.assertTrue(snapshot["over_quota"])
        self.assertTrue(snapshot["quota_enforced"])
        self.assertTrue(snapshot["rate_enforced"])
        self.assertEqual(self.controls.calls[-1], ({1443}, {1443: 1000000}))
        self.assertTrue(self.accounts._record(self.member["id"])["enabled"])
        self.clock_value += 40 * 86400
        self.traffic.tick()
        self.assertFalse(self.traffic.snapshot(self.member["id"])["over_quota"])
        self.assertEqual(self.controls.calls[-1][0], set())

    def test_kernel_failure_restores_previous_limits_and_plan(self):
        self.traffic.set_limits(self.member["id"], 0, 1000000)
        self.controls.fail_once = True
        with self.assertRaises(server.PanelError):
            self.traffic.set_limits(self.member["id"], 500, 2000000)
        snapshot = self.traffic.snapshot(self.member["id"])
        self.assertEqual((snapshot["quota_bytes"], snapshot["rate_bps"]), (0, 1000000))
        self.assertEqual(self.controls.calls[-1], (set(), {1443: 1000000}))

    def test_unavailable_statistics_are_explicit_and_invalid_limits_rejected(self):
        self.fail_queries = True
        self.traffic.tick()
        snapshot = self.traffic.snapshot(self.member["id"])
        self.assertFalse(snapshot["available"])
        self.assertIsNone(snapshot["connections"])
        for quota, rate in ((True, 0), (-1, 0), (0, 99999), (0, "1000")):
            with self.assertRaises(server.PanelError):
                self.traffic.set_limits(self.member["id"], quota, rate)

    def test_unlimited_default_has_no_network_mutations(self):
        calls = []
        control = telemetry.LinuxControls(self.owner.directory, runner=lambda args, check=True: calls.append(args))
        control.apply(set(), {})
        self.assertEqual(calls, [])

    def test_partial_quota_failure_remains_owned_and_is_cleared_on_rollback(self):
        calls, failed = [], [False]

        def runner(args, check=True):
            calls.append(args)
            if (telemetry.CHAIN_OUT in args and "REJECT" in args and not failed[0]):
                failed[0] = True
                raise RuntimeError("partial netfilter update")
            return SimpleNamespace(stdout=b"", returncode=0)

        control = telemetry.LinuxControls(self.owner.directory, runner=runner)
        with self.assertRaises(RuntimeError):
            control.apply({1443}, {})
        self.assertTrue(control.state["quota_owned"])
        control.apply(set(), {})
        self.assertFalse(control.state["quota_owned"])
        self.assertEqual(sum(1 for args in calls if "-F" in args), 4)
        self.assertTrue(any(args[-4:] == ["-i", "lo", "-j", "RETURN"] for args in calls))

    def test_failed_rate_install_preserves_untouched_original_qdisc(self):
        calls = []

        def runner(args, check=True):
            calls.append(args)
            if args[:3] == ["ip", "route", "show"]:
                return SimpleNamespace(stdout=b"default via 1.1.1.1 dev eth0\n", returncode=0)
            if args[:3] == ["tc", "qdisc", "show"]:
                return SimpleNamespace(stdout=b"qdisc pfifo_fast 0: dev eth0 root refcnt 2\n", returncode=0)
            if args[:3] == ["tc", "qdisc", "replace"]:
                raise RuntimeError("permission denied before kernel change")
            return SimpleNamespace(stdout=b"", returncode=0)

        control = telemetry.LinuxControls(self.owner.directory, runner=runner)
        with self.assertRaises(RuntimeError):
            control.apply(set(), {1443: 1000000})
        control.apply(set(), {})
        self.assertFalse(control.state.get("owned"))
        self.assertFalse(any(args[:3] == ["tc", "qdisc", "del"] for args in calls))

    def test_quota_allows_termination_resets_before_output_port_rejection(self):
        calls = []

        def runner(args, check=True):
            calls.append(args)
            return SimpleNamespace(stdout=b"", returncode=0)

        control = telemetry.LinuxControls(self.owner.directory, runner=runner)
        control.quota({1443})
        output = [args for args in calls if telemetry.CHAIN_OUT in args and "-A" in args]
        self.assertEqual(output[0][-4:], ["-o", "lo", "-j", "RETURN"])
        self.assertIn("--tcp-flags", output[1])
        self.assertEqual(output[1][-5:], ["--tcp-flags", "RST", "RST", "-j", "RETURN"])
        self.assertIn("--sport", output[2])
        self.assertIn("REJECT", output[2])


class BackupTests(Fixture):
    PASSWORD = "portable-password-2026"

    def setUp(self):
        super().setUp()
        self.backup = backups.BackupManager(self.accounts, clock=self.clock)

    def make_portable(self):
        item = self.backup.create("测试完整备份")
        exported = self.backup.export(item["id"], self.PASSWORD)
        data, filename = self.backup.download(exported["download_token"])
        self.assertTrue(filename.endswith(".nvbackup"))
        return data

    def preview(self, archive):
        return self.backup.preview(base64.b64encode(archive).decode(), self.PASSWORD)

    def test_encrypted_full_snapshot_and_export_has_no_plaintext_credentials(self):
        archive = self.make_portable()
        self.assertNotIn(b"owner-password", archive)
        self.assertNotIn(self.owner.state["auto_id"].encode(), archive)
        plaintext = backups.decrypt(archive, password=self.PASSWORD, require_portable=True)
        snapshot = json.loads(plaintext)
        self.assertIn("admin/auth.json", snapshot["files"])
        self.assertIn("members/" + self.member["id"] + "/config.json", snapshot["files"])
        with self.assertRaises(server.PanelError):
            backups.decrypt(archive, password="wrong-password-2026")
        data = json.loads(archive)
        encrypted = bytearray(base64.b64decode(data["data"]))
        encrypted[0] ^= 1
        data["data"] = base64.b64encode(encrypted).decode()
        with self.assertRaises(server.PanelError):
            backups.decrypt(json.dumps(data).encode(), password=self.PASSWORD)

    def test_restore_auth_rules_disabled_member_and_in_memory_caches(self):
        self.accounts.set_enabled(self.member["id"], False)
        archive = self.make_portable()
        original_auth = self.auth_path.read_bytes()
        original_domains = list(self.owner.state["domains"])
        self.accounts.reset_password("admin", "different-password-2026")
        self.owner.set_routing(["changed.example"], "smart", ["direct.example"])
        self.accounts.set_enabled(self.member["id"], True)
        preview = self.preview(archive)
        result = self.backup.restore(preview["preview_token"], "RESTORE")
        self.assertTrue(result["needs_reload"])
        self.assertEqual(self.auth_path.read_bytes(), original_auth)
        self.assertFalse(self.accounts._record(self.member["id"])["enabled"])
        self.assertEqual(self.owner.state["domains"], original_domains)
        self.assertIsNotNone(self.accounts.authenticate("admin", "owner-password-2026"))

    def test_preview_detects_concurrent_user_edit_without_overwriting(self):
        preview = self.preview(self.make_portable())
        self.owner.set_routing(["new.example"], "smart", [])
        state = self.owner.state_path.read_bytes()
        with self.assertRaises(server.PanelError):
            self.backup.restore(preview["preview_token"], "RESTORE")
        self.assertEqual(self.owner.state_path.read_bytes(), state)

    def test_background_samples_do_not_invalidate_restore_preview(self):
        preview = self.preview(self.make_portable())
        server.atomic_write(self.owner.directory / "traffic.private.json", b'{"version":1,"users":{}}')
        result = self.backup.restore(preview["preview_token"], "RESTORE")
        self.assertTrue(result["restored"])

    def test_uploaded_path_traversal_and_hash_mismatch_are_rejected(self):
        archive = self.make_portable()
        decoded = json.loads(backups.decrypt(archive, password=self.PASSWORD))
        malicious = copy.deepcopy(decoded)
        malicious["files"]["../../etc/passwd"] = malicious["files"]["admin/auth.json"]
        for candidate in (malicious, decoded):
            if candidate is decoded:
                candidate["files"]["admin/auth.json"]["sha256"] = "0" * 64
            archive = backups.encrypt(json.dumps(candidate).encode(), password=self.PASSWORD)
            with self.assertRaises(server.PanelError):
                self.preview(archive)

    def test_wrong_node_and_symlink_source_rejected(self):
        snapshot = json.loads(backups.decrypt(self.make_portable(), password=self.PASSWORD))
        snapshot["public_ip"] = "1.1.1.1"
        with self.assertRaises(server.PanelError):
            self.preview(backups.encrypt(json.dumps(snapshot).encode(), password=self.PASSWORD))
        if hasattr(Path, "symlink_to"):
            target = self.directory / "outside.json"
            target.write_bytes(b"private")
            link = self.owner.directory / "health.private.json"
            try:
                link.symlink_to(target)
            except OSError:
                return
            with self.assertRaises(server.PanelError):
                self.backup.create()

    def test_expired_download_and_preview_and_daily_schedule(self):
        item = self.backup.create()
        exported = self.backup.export(item["id"], self.PASSWORD)
        data, filename = self.backup.download(exported["download_token"])
        preview = self.preview(data)
        self.clock_value += 601
        with self.assertRaises(server.PanelError):
            self.backup.download(exported["download_token"])
        with self.assertRaises(server.PanelError):
            self.backup.restore(preview["preview_token"], "RESTORE")
        self.clock_value += 86400
        self.backup.tick()
        self.assertEqual(len(self.backup.list()["backups"]), 2)
        self.backup.schedule(False)
        self.clock_value += 86400
        self.backup.tick()
        self.assertEqual(len(self.backup.list()["backups"]), 2)

    def test_failed_runtime_rolls_back_complete_original_files(self):
        archive = self.make_portable()
        self.owner.set_routing(["live.example"], "smart", [])
        original = self.owner.state_path.read_bytes()
        preview = self.preview(archive)
        calls = []
        failed = [False]

        def runtime(action, records):
            calls.append(action)
            if action == "start" and not failed[0]:
                failed[0] = True
                raise RuntimeError("node startup failed")

        self.backup.runtime = runtime
        with mock.patch.object(self.backup, "_runtime", side_effect=runtime):
            with self.assertRaises(server.PanelError):
                self.backup.restore(preview["preview_token"], "RESTORE")
        self.assertEqual(self.owner.state_path.read_bytes(), original)
        self.assertEqual(self.owner.state["domains"], ["live.example"])
        self.assertEqual(calls, ["stop", "start", "stop", "start"])


if __name__ == "__main__":
    unittest.main()
