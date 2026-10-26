"""Expanded entrance archives, legacy restores, stale previews and rollback.

All accounts and TLS material belong to isolated demo directories. Runtime
failure coverage injects service callbacks and never controls real services.
"""

import copy
import json
import unittest

from panel import backups, ports, server
from panel import test_hy2_backups as accelerated
from panel import test_operations as legacy


class ExpandedEntranceBackupTests(legacy.Fixture):
    # Reuse HY2 setup/identity helpers without inheriting the existing tests,
    # which would otherwise run the complete old suite a second time.
    PASSWORD = accelerated.AcceleratedBackupTests.PASSWORD
    records = accelerated.AcceleratedBackupTests.records
    enable_hy2 = accelerated.AcceleratedBackupTests.enable_hy2
    snapshot = accelerated.AcceleratedBackupTests.snapshot
    refresh_config = accelerated.AcceleratedBackupTests.refresh_config
    portable = accelerated.AcceleratedBackupTests.portable
    preview = accelerated.AcceleratedBackupTests.preview
    replace_file = staticmethod(accelerated.AcceleratedBackupTests.replace_file)

    def setUp(self):
        super().setUp()
        state = copy.deepcopy(self.owner.state)
        state["base"]["inbounds"][0]["port"] = 443
        config, profile = self.owner.build(state, state["active_id"])
        payload = server.json_bytes(config)
        server.atomic_write(self.owner.config_path, payload)
        state.update(profile=profile, managed_hash=server.digest(payload))
        self.owner.save(state)
        self.backup = backups.BackupManager(self.accounts, clock=self.clock)

    def expand_members(self, total, member_ports=None):
        selected = ports.SUPPORTED_MEMBER_PORTS if member_ports is None else member_ports
        self.accounts.configure_entrances({"member_ports": list(selected), "cloud_confirmed": True})
        for number in range(len(self.accounts.records), total):
            self.accounts.create_user({"username": "member_" + str(number + 1),
                                       "display_name": "成员 " + str(number + 1),
                                       "password": "expanded-member-password-2026"})

    def decoded_archive(self, archive):
        return json.loads(backups.decrypt(archive, password=self.PASSWORD, require_portable=True))

    @staticmethod
    def file_hashes(snapshot):
        return {name: item["sha256"] for name, item in snapshot["files"].items()}

    def test_full_capacity_archive_contains_every_member_hy2_identity_and_entrance_pool(self):
        self.expand_members(len(ports.SUPPORTED_MEMBER_PORTS))
        self.enable_hy2()
        archive = self.portable()
        snapshot = self.decoded_archive(archive)
        records, decoded = self.backup._validate_snapshot(snapshot)
        self.assertEqual(len(records), len(ports.SUPPORTED_MEMBER_PORTS) + 1)
        self.assertEqual({record["port"] for record in records}, set(ports.SUPPORTED_PUBLIC_PORTS))
        self.assertEqual(json.loads(decoded["system/entrance-pool.private.json"]),
                         {"version": 1, "member_ports": list(ports.SUPPORTED_MEMBER_PORTS)})
        self.assertEqual(json.loads(decoded["system/hy2.private.json"]), self.original_registry)
        self.assertTrue(backups.HY2_FILES.issubset(decoded))
        for record in records:
            prefix = "admin/" if record["id"] == "admin" else "members/" + record["id"] + "/"
            config = json.loads(decoded[prefix + "config.json"])
            self.assertEqual(config["inbounds"][0]["port"], record["port"])
            self.assertEqual(config["inbounds"][1]["settings"]["accounts"][0]["pass"],
                             self.original_registry["accounts"][record["id"]]["socks_password"])
            self.assertNotIn(self.original_registry["accounts"][record["id"]]["password"].encode(), archive)
        preview = self.preview(archive)
        self.assertEqual(preview["changes"]["users"], len(records))
        self.assertEqual(len(preview["users"]), len(records))

    def test_expanded_archive_validates_and_restores_when_current_pool_is_default(self):
        legacy_archive = self.portable()
        self.expand_members(4)
        self.enable_hy2()
        archive = self.portable()
        archived_snapshot = self.decoded_archive(archive)
        archived_ids = {record["id"] for record in self.records()}
        archived_pool = self.accounts.member_ports
        archived_credentials = copy.deepcopy(self.acceleration.data)
        self.backup.restore(self.preview(legacy_archive)["preview_token"], "RESTORE")
        self.assertEqual(self.accounts.member_ports, ports.DEFAULT_MEMBER_PORTS)
        self.assertEqual(len(self.accounts.records), 1)
        self.assertFalse(self.accounts.entrance_pool_path.exists())
        records, decoded = self.backup._validate_snapshot(archived_snapshot)
        self.assertEqual({record["id"] for record in records}, archived_ids)
        self.assertIn("system/entrance-pool.private.json", decoded)
        # Validation must use the archived catalog without changing live state.
        self.assertEqual(self.accounts.member_ports, ports.DEFAULT_MEMBER_PORTS)
        self.assertFalse(self.accounts.entrance_pool_path.exists())
        restored = self.backup.restore(self.preview(archive)["preview_token"], "RESTORE")
        self.assertTrue(restored["restored"])
        self.assertEqual(restored["users"], 5)
        self.assertEqual(self.accounts.member_ports, archived_pool)
        self.assertEqual({record["id"] for record in self.records()}, archived_ids)
        self.assertEqual(self.acceleration.data, archived_credentials)
        for record in self.records():
            manager = self.accounts._manager(record)
            config = json.loads(manager.config_path.read_text(encoding="utf-8"))
            self.assertEqual(config["inbounds"][0]["port"], record["port"])
            self.assertEqual(config["inbounds"][1]["settings"]["accounts"][0]["pass"],
                             archived_credentials["accounts"][record["id"]]["socks_password"])

    def test_legacy_archive_removes_expanded_pool_and_restores_default_allocation(self):
        archive = self.portable()
        self.assertNotIn("system/entrance-pool.private.json", self.decoded_archive(archive)["files"])
        self.expand_members(3)
        self.enable_hy2()
        self.assertTrue(self.accounts.entrance_pool_path.exists())
        restored = self.backup.restore(self.preview(archive)["preview_token"], "RESTORE")
        self.assertTrue(restored["restored"])
        self.assertEqual(self.accounts.member_ports, ports.DEFAULT_MEMBER_PORTS)
        self.assertFalse(self.accounts.entrance_pool_path.exists())
        self.assertEqual([record["id"] for record in self.accounts.records], [self.member["id"]])
        self.assertFalse(self.acceleration.enabled)
        self.assertIsNone(self.acceleration.data)
        self.assertEqual(self.accounts.entrance_summary()["capacity"], 3)
        member = self.accounts.create_user({"username": "after_restore", "password": "new-member-password-2026"})
        self.assertEqual(member["port"], 2443)
        with self.assertRaises(server.PanelError):
            self.accounts.create_user({"username": "beyond_default", "password": "new-member-password-2026"})

    def test_pool_edit_invalidates_restore_preview_without_changing_member_credentials(self):
        self.expand_members(1, ports.DEFAULT_MEMBER_PORTS)
        self.enable_hy2()
        preview = self.preview(self.portable())
        original_ids = [record["id"] for record in self.accounts.records]
        credentials = copy.deepcopy(self.acceleration.data)
        original_pool = self.accounts.entrance_pool_path.read_bytes()
        expanded_pool = ports.DEFAULT_MEMBER_PORTS + (3444,)
        self.accounts.configure_entrances({"member_ports": list(expanded_pool), "cloud_confirmed": True})
        changed_pool = self.accounts.entrance_pool_path.read_bytes()
        self.assertNotEqual(changed_pool, original_pool)
        with self.assertRaises(server.PanelError) as error:
            self.backup.restore(preview["preview_token"], "RESTORE")
        self.assertEqual(error.exception.status, 409)
        self.assertEqual(self.accounts.entrance_pool_path.read_bytes(), changed_pool)
        self.assertEqual(self.accounts.member_ports, expanded_pool)
        self.assertEqual([record["id"] for record in self.accounts.records], original_ids)
        self.assertEqual(self.acceleration.data, credentials)

    def test_expanded_archive_requires_its_allocated_entrances_in_the_archived_pool(self):
        self.expand_members(3)
        self.enable_hy2()
        original = self.snapshot()
        missing = copy.deepcopy(original)
        del missing["files"]["system/entrance-pool.private.json"]
        truncated = copy.deepcopy(original)
        self.replace_file(truncated, "system/entrance-pool.private.json",
                          {"version": 1, "member_ports": list(ports.DEFAULT_MEMBER_PORTS)})
        before = self.file_hashes(self.snapshot())
        for candidate in (missing, truncated):
            with self.subTest(pool_present="system/entrance-pool.private.json" in candidate["files"]):
                with self.assertRaises(server.PanelError):
                    self.backup._validate_snapshot(candidate)
                self.assertEqual(self.file_hashes(self.snapshot()), before)
                self.assertEqual(self.accounts.member_ports, ports.SUPPORTED_MEMBER_PORTS)

    def test_failed_restore_rolls_back_pool_new_member_and_current_hy2_credentials(self):
        archived_pool = ports.DEFAULT_MEMBER_PORTS + (3444,)
        self.expand_members(3, archived_pool)
        self.enable_hy2()
        archive = self.portable()
        self.accounts.configure_entrances({"member_ports": list(ports.SUPPORTED_MEMBER_PORTS),
                                          "cloud_confirmed": True})
        newer = self.accounts.create_user({"username": "newer_member", "password": "new-member-password-2026"})
        self.acceleration.rotate(self.accounts._record("admin"))
        self.refresh_config(self.accounts._record("admin"))
        original = self.snapshot()
        original_ids = {record["id"] for record in self.records()}
        original_pool = self.accounts.entrance_pool_path.read_bytes()
        credentials = copy.deepcopy(self.acceleration.data)
        preview = self.preview(archive)
        calls, failed = [], [False]

        def runtime(action, records):
            calls.append(action)
            if action == "start" and not failed[0]:
                self.assertEqual(self.accounts.member_ports, archived_pool)
                self.assertNotIn(newer["id"], {record["id"] for record in records})
                failed[0] = True
                raise RuntimeError("synthetic startup failure")

        self.backup._runtime = runtime
        with self.assertRaises(server.PanelError):
            self.backup.restore(preview["preview_token"], "RESTORE")
        self.assertEqual(calls, ["stop", "start", "stop", "start"])
        self.assertEqual(self.accounts.entrance_pool_path.read_bytes(), original_pool)
        self.assertEqual(self.accounts.member_ports, ports.SUPPORTED_MEMBER_PORTS)
        self.assertEqual({record["id"] for record in self.records()}, original_ids)
        self.assertEqual(self.acceleration.data, credentials)
        self.assertEqual(self.file_hashes(self.snapshot()), self.file_hashes(original))


if __name__ == "__main__":
    unittest.main()
