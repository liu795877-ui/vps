"""Local transport state is independent from account flags and public reachability."""

import subprocess
from types import SimpleNamespace
import unittest
from unittest import mock

from panel import hy2, server, test_accounts, test_hy2_integration


class ServiceStatusTests(unittest.TestCase):
    setUp = test_accounts.AccountsTests.setUp
    create = test_accounts.AccountsTests.create
    adopt = test_hy2_integration.IntegrationTests.adopt

    def member_with_hy2(self):
        self.adopt()
        return self.create()

    def command_for(self, statuses):
        def command(args, check=True, timeout=30):
            self.assertEqual(args[:4], ["systemctl", "show", "--property=LoadState", "--property=ActiveState"])
            self.assertEqual(args[-1], "--no-pager")
            self.assertFalse(check)
            self.assertEqual(timeout, 3)
            value = statuses[args[-2]]
            if isinstance(value, Exception):
                raise value
            if isinstance(value, tuple):
                return SimpleNamespace(returncode=value[0], stdout=value[1])
            return SimpleNamespace(returncode=0,
                                   stdout=("LoadState=loaded\nActiveState=" + value + "\n").encode("ascii"))
        return command

    def test_production_transports_are_checked_independently_and_use_managed_units(self):
        member = self.member_with_hy2()
        reality = self.accounts.manager(member["id"]).service_name
        accelerated = hy2.Integration.service(member)
        self.accounts.demo = False
        for tcp, udp, expected in (("active", "inactive", (True, False)), ("failed", "active", (False, True)),
                                   ("active", "active", (True, True)), ("inactive", "failed", (False, False))):
            with self.subTest(tcp=tcp, udp=udp), mock.patch.object(
                    server.base, "command", side_effect=self.command_for({reality: tcp, accelerated: udp})) as command:
                result = self.accounts.get(member["id"])
                self.assertEqual((result["service_active"], result["hy2_service_active"]), expected)
                self.assertEqual(result["hy2_port"], member["port"])
                self.assertEqual({call.args[0][-2] for call in command.call_args_list}, {reality, accelerated})
        self.assertEqual(self.accounts.entrance_summary()["public_verification"], "not_checked")

    def test_failed_command_or_unknown_unit_remains_unknown_without_hiding_other_transport(self):
        member = self.member_with_hy2()
        reality = self.accounts.manager(member["id"]).service_name
        accelerated = hy2.Integration.service(member)
        self.accounts.demo = False
        failures = tuple((code, b"LoadState=loaded\nActiveState=active\n")
                         for code in (1, 2, 3, 4, -15, None, True, "0")) + (
            (0, b"LoadState=not-found\nActiveState=inactive\n"),
            (3, b"LoadState=not-found\nActiveState=inactive\n"),
            (0, b"LoadState=error\nActiveState=inactive\n"),
            (0, b"LoadState=masked\nActiveState=inactive\n"),
            OSError("systemctl unavailable"), subprocess.TimeoutExpired("systemctl", 3),
            RuntimeError("synthetic private output"))
        for failure in failures:
            for failing_service in (reality, accelerated):
                statuses = {reality: "active", accelerated: "active"}
                statuses[failing_service] = failure
                with self.subTest(failure=failure, service=failing_service), mock.patch.object(
                        server.base, "command", side_effect=self.command_for(statuses)):
                    result = self.accounts.get(member["id"])
                    key = "service_active" if failing_service == reality else "hy2_service_active"
                    other = "hy2_service_active" if key == "service_active" else "service_active"
                    self.assertIsNone(result[key])
                    self.assertTrue(result[other])
                    self.assertNotIn("synthetic private output", str(result))

    def test_transitional_or_unrecognized_activity_is_unknown(self):
        self.accounts.demo = False
        for activity in ("activating", "deactivating", "reloading", "unknown", "", "maintenance"):
            with self.subTest(activity=activity), mock.patch.object(
                    server.base, "command", side_effect=self.command_for({"xray.service": activity})):
                self.assertIsNone(self.accounts.get("admin")["service_active"])

    def test_incomplete_or_malformed_observations_are_unknown(self):
        self.accounts.demo = False
        outputs = (b"", b"ActiveState=active\n", b"LoadState=loaded\n",
                   b"LoadState=loaded\nActiveState\n", b"LoadState=loaded\nActiveState=active\nActiveState=failed\n",
                   b"LoadState=loaded\nLoadState=not-found\nActiveState=active\n", b"\xff", None, 123)
        for output in outputs:
            with self.subTest(output=output), mock.patch.object(
                    server.base, "command", side_effect=self.command_for({"xray.service": (0, output)})):
                self.assertIsNone(self.accounts.get("admin")["service_active"])

    def test_text_and_bytes_output_use_keys_without_depending_on_order(self):
        self.accounts.demo = False
        for output in (b"ActiveState=active\nLoadState=loaded\n", "ActiveState=active\nLoadState=loaded\n"):
            with self.subTest(output=output), mock.patch.object(
                    server.base, "command", side_effect=self.command_for({"xray.service": (0, output)})):
                self.assertTrue(self.accounts.get("admin")["service_active"])

    def test_disabled_production_member_still_reports_observed_state(self):
        member = self.member_with_hy2()
        self.accounts.set_enabled(member["id"], False)
        reality = self.accounts._managers[member["id"]].service_name
        accelerated = hy2.Integration.service(member)
        self.accounts.demo = False
        for tcp, udp, expected in (("inactive", "failed", (False, False)), ("active", "active", (True, True))):
            with self.subTest(tcp=tcp, udp=udp), mock.patch.object(
                    server.base, "command", side_effect=self.command_for({reality: tcp, accelerated: udp})):
                result = self.accounts.get(member["id"])
                self.assertFalse(result["enabled"])
                self.assertEqual((result["service_active"], result["hy2_service_active"]), expected)

    def test_demo_enabled_and_disabled_statuses_use_no_external_commands(self):
        with mock.patch.object(server.base, "command", side_effect=AssertionError("external command in demo")) as command:
            member = self.member_with_hy2()
            self.assertTrue(member["service_active"])
            self.assertTrue(member["hy2_service_active"])
            disabled = self.accounts.set_enabled(member["id"], False)
            self.assertFalse(disabled["service_active"])
            self.assertFalse(disabled["hy2_service_active"])
            enabled = self.accounts.set_enabled(member["id"], True)
            self.assertTrue(enabled["service_active"])
            self.assertTrue(enabled["hy2_service_active"])
            command.assert_not_called()

    def test_admin_checks_main_xray_and_443_hy2_units(self):
        self.adopt()
        self.accounts.demo = False
        with mock.patch.object(server.base, "command", side_effect=self.command_for({
                "xray.service": "active", "raksmart-hy2@443.service": "inactive"})):
            result = self.accounts.get("admin")
        self.assertTrue(result["service_active"])
        self.assertFalse(result["hy2_service_active"])

    def test_account_without_hy2_does_not_query_a_hy2_unit(self):
        member = self.create()
        reality = self.accounts.manager(member["id"]).service_name
        self.accounts.demo = False
        with mock.patch.object(server.base, "command", side_effect=self.command_for({reality: "active"})) as command:
            result = self.accounts.get(member["id"])
        self.assertTrue(result["service_active"])
        self.assertIsNone(result["hy2_service_active"])
        self.assertIsNone(result["hy2_port"])
        command.assert_called_once()


if __name__ == "__main__":
    unittest.main()
