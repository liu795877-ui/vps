"""Confirmed entrance pools, complete port topology and expanded isolation."""

import ast
import copy
import json
from pathlib import Path
import socket
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

from panel import accounts, hy2, ports, server, telemetry
from panel import test_accounts, test_hy2_integration


class PortTopologyTests(unittest.TestCase):
    def test_all_catalog_ports_are_mutually_safe_and_keep_original_private_offsets(self):
        self.assertTrue(ports.validate_topology(ports.SUPPORTED_PUBLIC_PORTS))
        self.assertEqual(ports.private_port(443, "xray_stats"), 15443)
        self.assertEqual(ports.private_port(443, "hy2_socks"), 16043)
        self.assertEqual(ports.private_port(443, "hy2_stats"), 19043)
        self.assertTrue(ports.validate_topology((8443, 1443, 2443)))
        self.assertEqual(ports.private_port(8443, "xray_stats"), 23443)

    def test_detects_all_cross_service_offsets_and_public_loopback_collisions(self):
        for port in (1043, 3443, 4043, 15443, 16043, 19043, 443):
            with self.subTest(port=port), self.assertRaises(ValueError):
                ports.validate_topology((443, port))
        for port in (-1, 0, True, 46936, 65536, "3444"):
            with self.subTest(port=port), self.assertRaises(ValueError):
                ports.validate_topology((port,))

    def test_white_list_duplicates_booleans_and_excess_ports_are_rejected(self):
        for candidate in ([3445], [1443, 1443], [True], [443], [8443], list(range(9))):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                ports.validate_member_ports(candidate)

    def test_sources_parse_using_python36_grammar(self):
        for module in (ports, accounts, hy2, telemetry):
            source = Path(module.__file__).read_text(encoding="utf-8")
            if sys.version_info >= (3, 8):
                ast.parse(source, feature_version=(3, 6))
            else:
                ast.parse(source)


class EntrancePoolTests(unittest.TestCase):
    setUp = test_accounts.AccountsTests.setUp
    create = test_accounts.AccountsTests.create
    assert_original_owner = test_accounts.AccountsTests.assert_original_owner

    def expand(self):
        return self.accounts.configure_entrances({"member_ports": [1443, 2443, 3444],
                                                 "cloud_confirmed": True})

    def test_default_summary_does_not_create_pool_or_report_public_success(self):
        summary = self.accounts.entrance_summary()
        self.assertEqual((summary["capacity"], summary["total_users"], summary["available_count"]), (3, 1, 2))
        self.assertEqual(summary["public_verification"], "not_checked")
        self.assertEqual(summary["member_ports"], [1443, 2443])
        self.assertEqual(summary["supported_member_ports"], list(ports.SUPPORTED_MEMBER_PORTS))
        self.assertEqual(summary["allocations"][0]["username"], "admin")
        self.assertFalse(self.accounts.entrance_pool_path.exists())
        self.assertNotIn("auth", json.dumps(summary))

    def test_3443_is_rejected_with_the_actual_cross_account_collision(self):
        with self.assertRaises(server.PanelError) as caught:
            self.accounts.configure_entrances({"member_ports": [1443, 2443, 3443], "cloud_confirmed": True})
        self.assertIn("19043", str(caught.exception))
        self.assertFalse(self.accounts.entrance_pool_path.exists())
        self.assert_original_owner()

    def test_cloud_confirmation_is_required_before_expansion(self):
        for confirmation in (None, False, 1, "yes"):
            request = {"member_ports": [1443, 2443, 3444]}
            if confirmation is not None:
                request["cloud_confirmed"] = confirmation
            with self.subTest(confirmation=confirmation), self.assertRaises(server.PanelError):
                self.accounts.configure_entrances(request)
        self.assertEqual(self.accounts.member_ports, (1443, 2443))
        self.assertFalse(self.accounts.entrance_pool_path.exists())

    def test_third_member_gets_3444_and_reload_keeps_isolated_identity(self):
        first, second = self.create(), self.create("member_b")
        before = self.accounts.manager(first["id"]).state_path.read_bytes()
        self.expand()
        phases = []
        third = self.accounts.create_user({"username": "member_c", "password": "member-password-2026"},
                                          progress=lambda stage, message: phases.append(stage))
        self.assertEqual(third["port"], 3444)
        self.assertEqual(phases, ["validating", "allocating", "configuration", "services", "local_ready", "complete"])
        self.assertEqual(self.accounts.entrance_summary()["available_count"], 0)
        reloaded = accounts.Accounts(self.owner, self.auth_path, demo=True)
        self.assertEqual(reloaded.member_ports, (1443, 2443, 3444))
        self.assertEqual(reloaded.authenticate("member_c", "member-password-2026")["id"], third["id"])
        self.assertNotEqual(self.accounts.manager(first["id"]).state["auto_id"],
                            reloaded.manager(third["id"]).state["auto_id"])
        self.assertEqual(self.accounts.manager(first["id"]).state_path.read_bytes(), before)
        self.assertEqual(self.accounts.manager(second["id"]).state["exits"], [])
        self.assert_original_owner()

    def test_assigned_disabled_port_cannot_be_removed_and_pool_stays_identical(self):
        self.expand()
        first = self.create()
        self.accounts.set_enabled(first["id"], False)
        before = self.accounts.entrance_pool_path.read_bytes()
        with self.assertRaises(server.PanelError):
            self.accounts.configure_entrances({"member_ports": [2443, 3444], "cloud_confirmed": False})
        self.assertEqual(self.accounts.entrance_pool_path.read_bytes(), before)
        self.assertEqual(self.accounts.entrance_summary()["allocations"][1]["status"], "disabled")

    def test_expansion_probes_public_tcp_udp_and_every_private_tcp_port(self):
        self.accounts.demo = False
        with mock.patch.object(socket, "socket") as factory:
            probe = factory.return_value.__enter__.return_value
            self.expand()
        self.assertEqual([call[0][0] for call in factory.call_args_list], [socket.AF_INET] * 5)
        self.assertEqual([call[0][1] for call in factory.call_args_list],
                         [socket.SOCK_STREAM, socket.SOCK_DGRAM] + [socket.SOCK_STREAM] * 3)
        self.assertEqual([call[0][0] for call in probe.bind.call_args_list],
                         [("0.0.0.0", 3444), ("0.0.0.0", 3444),
                          ("127.0.0.1", 18444), ("127.0.0.1", 19044), ("127.0.0.1", 22044)])
        self.assertEqual(self.accounts.entrance_summary()["public_verification"], "not_checked")

    def test_any_existing_listener_blocks_expansion_before_saving_pool(self):
        self.accounts.demo = False
        for kind, address, port, service in ports.bindings(3444):
            target = (kind, address, port)
            with self.subTest(target=target), mock.patch.object(socket, "socket") as factory:
                def construct(family, protocol):
                    probe = mock.MagicMock()
                    def bind(value):
                        if (protocol,) + value == target:
                            raise OSError("already bound")
                    probe.__enter__.return_value.bind.side_effect = bind
                    return probe
                factory.side_effect = construct
                with self.assertRaises(server.PanelError):
                    self.expand()
                self.assertFalse(self.accounts.entrance_pool_path.exists())
                self.assertEqual(self.accounts.member_ports, (1443, 2443))

    def test_progress_observer_failure_does_not_undo_committed_member(self):
        def progress(stage, message):
            raise RuntimeError("observer unavailable")
        member = self.accounts.create_user({"username": "member_c", "password": "member-password-2026"}, progress)
        self.assertEqual(self.accounts.authenticate("member_c", "member-password-2026")["id"], member["id"])


class ExpandedHy2Tests(unittest.TestCase):
    setUp = test_accounts.AccountsTests.setUp
    create = test_accounts.AccountsTests.create
    expand = EntrancePoolTests.expand
    adopt = test_hy2_integration.IntegrationTests.adopt

    def test_expanded_member_has_hy2_profile_private_bridge_and_independent_credentials(self):
        self.adopt()
        first, second = self.create(), self.create("member_b")
        self.expand()
        third = self.create("member_c")
        config = json.loads(self.accounts.manager(third["id"]).config_path.read_bytes())
        self.integration.validate_running(third, config)
        self.assertEqual(config["api"]["listen"], "127.0.0.1:18444")
        self.assertEqual(config["inbounds"][1]["port"], 19044)
        self.assertEqual(self.integration.config(third)["trafficStats"]["listen"], "127.0.0.1:22044")
        self.assertEqual(third["hy2_port"], 3444)
        hy2.validate_registry(self.integration.data)
        for key in ("password", "api_secret", "socks_password"):
            self.assertEqual(len({item[key] for item in self.integration.data["accounts"].values()}), 4)
        reloaded = accounts.Accounts(self.owner, self.auth_path, demo=True)
        integration = hy2.Integration(reloaded)
        reloaded.acceleration = integration
        self.assertTrue(integration.has_record(third))
        self.assertEqual(reloaded.manager(third["id"]).state["auto_id"],
                         self.accounts.manager(third["id"]).state["auto_id"])
        response = json.dumps(self.accounts.entrance_summary())
        self.assertNotIn(self.integration.data["accounts"][third["id"]]["password"], response)

    def test_registry_failure_after_write_rolls_back_new_member_and_preserves_existing_accounts(self):
        self.adopt()
        first, second = self.create(), self.create("member_b")
        self.expand()
        before_users = self.accounts.users_path.read_bytes()
        before_pool = self.accounts.entrance_pool_path.read_bytes()
        before_hy2 = copy.deepcopy(self.integration.data)
        before_first = self.accounts.manager(first["id"]).state_path.read_bytes()
        before_owner = self.owner.config_path.read_bytes()
        original_save = self.accounts._save
        def fail_after_save(records):
            original_save(records)
            raise OSError("durability observer failed")
        with mock.patch.object(self.accounts, "_save", side_effect=fail_after_save):
            with self.assertRaises(server.PanelError):
                self.create("member_c")
        self.assertEqual(self.accounts.users_path.read_bytes(), before_users)
        self.assertEqual(self.accounts.entrance_pool_path.read_bytes(), before_pool)
        self.assertEqual(self.integration.data, before_hy2)
        self.assertFalse((self.integration.runtime / "3444.yaml").exists())
        self.assertEqual(len(self.accounts.records), 2)
        self.assertEqual(self.accounts.manager(first["id"]).state_path.read_bytes(), before_first)
        self.assertTrue(self.accounts.authenticate("member_b", "member-password-2026"))
        self.assertEqual(self.owner.config_path.read_bytes(), before_owner)


class ConfiguredControlsTests(unittest.TestCase):
    setUp = test_accounts.AccountsTests.setUp

    def test_kernel_controls_follow_pool_and_reject_unconfigured_catalog_port(self):
        calls = []
        def runner(args, check=True):
            calls.append(args)
            return SimpleNamespace(stdout=b"", returncode=0)
        controls = telemetry.LinuxControls(self.owner.directory, runner=runner,
            managed_ports=lambda: (self.accounts._owner_port(),) + self.accounts.member_ports)
        with self.assertRaises(ValueError):
            controls.quota({3444})
        self.assertEqual(calls, [])
        self.accounts.configure_entrances({"member_ports": [1443, 2443, 3444], "cloud_confirmed": True})
        controls.quota({3444})
        self.assertTrue(any("3444" in command for command in calls))
        with self.assertRaises(ValueError):
            controls.quota({4444})


if __name__ == "__main__":
    unittest.main()
