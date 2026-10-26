"""Account lifecycle, authenticated AUTO bridging and rollback invariants."""
import copy
import json
from types import SimpleNamespace
import unittest
from unittest import mock

from panel import hy2, server, telemetry
from panel import test_accounts


class IntegrationTests(unittest.TestCase):
    setUp = test_accounts.AccountsTests.setUp
    create = test_accounts.AccountsTests.create

    def adopt(self):
        registry = {"version": 1, "enabled": True, "certificate_sha256": "a" * 64,
                    "sni": "raksmart-hy2.local", "accounts": {"admin": hy2._entry(443)}}
        server.atomic_write(self.owner.directory / "hy2.private.json", server.json_bytes(registry))
        self.integration = hy2.Integration(self.accounts)
        self.accounts.acceleration = self.integration
        state = copy.deepcopy(self.owner.state)
        state["base"] = telemetry.augment_config(state["base"])
        state["active_id"] = "server"
        config, profile = self.owner.build(state, "server")
        server.atomic_write(self.owner.config_path, server.json_bytes(config))
        state.update(managed_hash=server.digest(self.owner.config_path.read_bytes()), profile=profile)
        self.owner.save(state)
        return config

    def test_optional_adoption_has_no_side_effects(self):
        original = self.owner.config_path.read_bytes()
        integration = hy2.Integration(self.accounts)
        self.assertFalse(integration.enabled)
        self.assertFalse(integration.prepare(self.accounts._record("admin")))
        self.assertEqual(original, self.owner.config_path.read_bytes())
        self.assertEqual(integration.public_metadata(443), {"enabled": False})

    def test_production_startup_restores_certificate_access_after_manager_initialization(self):
        self.adopt()
        self.accounts.demo = False
        try:
            with mock.patch.object(hy2.Integration, "validate_tls") as validate:
                hy2.Integration(self.accounts)
            validate.assert_called_once_with()
        finally:
            self.accounts.demo = True

    def test_create_has_separate_secrets_and_authenticated_auto_route(self):
        self.adopt()
        first, second = self.create(), self.create("member_b")
        entries = self.integration.data["accounts"]
        for key in ("password", "api_secret", "socks_password"):
            self.assertEqual(len({item[key] for item in entries.values()}), 3)
        for record in [self.accounts._record("admin"), first, second]:
            manager = self.accounts._manager(record)
            config = json.loads(manager.config_path.read_bytes())
            self.integration.validate_running(record, config)
            self.assertEqual(len(manager.state["base"]["inbounds"]), 1)
            rules = config["routing"]["rules"]
            bridge = next(rule for rule in rules if rule.get("inboundTag") == ["panel-hy2-socks"])
            auto = next(rule for rule in rules if rule.get("user") == ["panel-auto@exits.invalid"]
                        and rule.get("network") == "tcp")
            self.assertEqual(bridge["outboundTag"], auto["outboundTag"])
            self.assertLess(rules.index(bridge), rules.index(auto))
            self.assertTrue(any(rule.get("ip") == server.base.PRIVATE_RANGES and rule.get("outboundTag") == "block"
                                for rule in rules[:rules.index(bridge)]))
            self.assertNotIn("email", config["inbounds"][1]["settings"]["accounts"][0])
            self.assertIn("type: hysteria2", manager.state["profile"])
            self.assertNotIn(entries[record["id"]]["socks_password"], manager.state["profile"])

    def test_failed_create_and_delete_restore_registry_and_files(self):
        self.adopt()
        original = self.integration.snapshot_registry()
        with mock.patch.object(self.accounts, "_save", side_effect=OSError("registry unavailable")):
            with self.assertRaises(server.PanelError):
                self.create()
        self.assertEqual(self.integration.data, original)
        self.assertFalse((self.integration.runtime / "1443.yaml").exists())
        member = self.create()
        original = self.integration.snapshot_registry()
        with mock.patch.object(self.accounts, "_save", side_effect=OSError("registry unavailable")):
            with self.assertRaises(server.PanelError):
                self.accounts.delete_user(member["id"])
        self.assertEqual(self.integration.data, original)
        self.assertTrue(self.accounts.manager(member["id"]).config_path.exists())
        self.assertTrue((self.integration.runtime / "1443.yaml").exists())

    def test_rotation_replaces_both_proxy_protocol_credentials_only_for_member(self):
        self.adopt()
        member, other = self.create(), self.create("member_b")
        manager = self.accounts.manager(member["id"])
        before = self.integration.snapshot_registry()
        password = copy.deepcopy(self.accounts._record(member["id"])["auth"])
        self.accounts.rotate_credentials(member["id"])
        after = self.integration.data
        self.assertNotEqual(before["accounts"][member["id"]]["password"], after["accounts"][member["id"]]["password"])
        self.assertNotEqual(before["accounts"][member["id"]]["socks_password"], after["accounts"][member["id"]]["socks_password"])
        self.assertEqual(before["accounts"][other["id"]], after["accounts"][other["id"]])
        self.assertEqual(password, self.accounts._record(member["id"])["auth"])
        self.integration.validate_running(member, json.loads(manager.config_path.read_bytes()))
        self.assertIn(after["accounts"][member["id"]]["password"], manager.state["profile"])

    def test_failed_rotation_restores_hy2_and_reality(self):
        self.adopt()
        member = self.create()
        manager = self.accounts.manager(member["id"])
        original = manager.config_path.read_bytes(), manager.state_path.read_bytes()
        registry = self.integration.snapshot_registry()
        with mock.patch.object(manager, "save", side_effect=OSError("state unavailable")):
            with self.assertRaises(server.PanelError):
                self.accounts.rotate_credentials(member["id"])
        self.assertEqual(registry, self.integration.data)
        self.assertEqual(original, (manager.config_path.read_bytes(), manager.state_path.read_bytes()))

    def test_delete_releases_hy2_port_without_reusing_old_secret(self):
        self.adopt()
        member = self.create()
        old = self.integration.data["accounts"][member["id"]]["password"]
        self.accounts.delete_user(member["id"])
        self.assertNotIn(member["id"], self.integration.data["accounts"])
        self.assertFalse((self.integration.runtime / "1443.yaml").exists())
        replacement = self.create("member_new")
        self.assertEqual(replacement["port"], 1443)
        self.assertNotEqual(old, self.integration.data["accounts"][replacement["id"]]["password"])

    def test_query_uses_native_direction_and_refuses_unknown_identity(self):
        self.adopt()
        record = self.accounts._record("admin")
        self.integration.runner = lambda args: SimpleNamespace(stdout="MainPID=10\nExecMainStartTimestampMonotonic=100")
        self.integration.api = lambda record, resource: {"user": {"tx": 42, "rx": 91}} if resource == "traffic" else {"user": 2}
        counters, sessions, epoch = self.integration.query(record)
        self.assertEqual(counters, {"hy2>>>traffic>>>uplink": 42, "hy2>>>traffic>>>downlink": 91})
        self.assertEqual(sessions, 2)
        self.assertIn("MainPID=10", epoch)
        self.integration.api = lambda record, resource: {"other": 2}
        with self.assertRaises(ValueError):
            self.integration.query(record)

    def test_composition_updates_historical_bridge_without_duplicate(self):
        config = self.adopt()
        original_profile = self.owner.state["profile"]
        composed, profile = self.integration.compose(config, original_profile, 443, "8.8.8.8")
        self.assertEqual(composed, config)
        self.assertEqual(profile, original_profile)
        self.integration.rotate(self.accounts._record("admin"))
        composed, profile = self.integration.compose(config, original_profile, 443, "8.8.8.8")
        self.integration.validate_running(self.accounts._record("admin"), composed)
        self.assertEqual(len(composed["inbounds"]), 2)

    def test_backup_stops_old_member_but_samples_only_live_accounts(self):
        orphan = {"id": "f" * 16, "port": 2443, "enabled": False}
        app = SimpleNamespace(demo=False, accounts=self.accounts,
            acceleration=SimpleNamespace(stop=mock.Mock()), telemetry=SimpleNamespace(sample_user=mock.Mock()))
        with mock.patch.object(server.base, "command") as command:
            server.Application._backup_runtime(app, "stop", [self.accounts._record("admin"), orphan])
        app.telemetry.sample_user.assert_called_once_with("admin")
        self.assertEqual(app.acceleration.stop.call_count, 2)
        self.assertTrue(any(call[0][0] == ["systemctl", "stop", self.accounts._service(orphan)]
                            for call in command.call_args_list))

    def test_enable_failure_recovers_disabled_state_and_stops_both_transports(self):
        self.adopt()
        member = self.create()
        self.accounts.set_enabled(member["id"], False)
        with mock.patch.object(self.integration, "start", side_effect=RuntimeError("not ready")), \
                mock.patch.object(self.integration, "stop") as stop:
            with self.assertRaises(server.PanelError):
                self.accounts.set_enabled(member["id"], True)
        self.assertFalse(self.accounts._record(member["id"])["enabled"])
        stop.assert_called_once()


if __name__ == "__main__":
    unittest.main()
