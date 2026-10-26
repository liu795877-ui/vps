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
            self.assertEqual(args[:3], ["systemctl", "is-active", "--quiet"])
            self.assertFalse(check)
            self.assertEqual(timeout, 3)
            value = statuses[args[-1]]
            if isinstance(value, Exception):
                raise value
            return SimpleNamespace(returncode=value)
        return command

    def test_production_transports_are_checked_independently_and_use_managed_units(self):
        member = self.member_with_hy2()
        reality = self.accounts.manager(member["id"]).service_name
        accelerated = hy2.Integration.service(member)
        self.accounts.demo = False
        for tcp, udp, expected in ((0, 3, (True, False)), (3, 0, (False, True)),
                                   (0, 0, (True, True)), (3, 3, (False, False))):
            with self.subTest(tcp=tcp, udp=udp), mock.patch.object(
                    server.base, "command", side_effect=self.command_for({reality: tcp, accelerated: udp})) as command:
                result = self.accounts.get(member["id"])
                self.assertEqual((result["service_active"], result["hy2_service_active"]), expected)
                self.assertEqual(result["hy2_port"], member["port"])
                self.assertEqual({call[0][0][-1] for call in command.call_args_list}, {reality, accelerated})
        self.assertEqual(self.accounts.entrance_summary()["public_verification"], "not_checked")

    def test_failed_command_or_unknown_unit_remains_unknown_without_hiding_other_transport(self):
        member = self.member_with_hy2()
        reality = self.accounts.manager(member["id"]).service_name
        accelerated = hy2.Integration.service(member)
        self.accounts.demo = False
        failures = (1, 2, 4, -15, None, True, "0", OSError("systemctl unavailable"),
                    subprocess.TimeoutExpired("systemctl", 3), RuntimeError("synthetic private output"))
        for failure in failures:
            for failing_service in (reality, accelerated):
                statuses = {reality: 0, accelerated: 0}
                statuses[failing_service] = failure
                with self.subTest(failure=failure, service=failing_service), mock.patch.object(
                        server.base, "command", side_effect=self.command_for(statuses)):
                    result = self.accounts.get(member["id"])
                    key = "service_active" if failing_service == reality else "hy2_service_active"
                    other = "hy2_service_active" if key == "service_active" else "service_active"
                    self.assertIsNone(result[key])
                    self.assertTrue(result[other])
                    self.assertNotIn("synthetic private output", str(result))

    def test_disabled_production_member_still_reports_observed_state(self):
        member = self.member_with_hy2()
        self.accounts.set_enabled(member["id"], False)
        reality = self.accounts._managers[member["id"]].service_name
        accelerated = hy2.Integration.service(member)
        self.accounts.demo = False
        for tcp, udp, expected in ((3, 3, (False, False)), (0, 0, (True, True))):
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
                "xray.service": 0, "raksmart-hy2@443.service": 3})):
            result = self.accounts.get("admin")
        self.assertTrue(result["service_active"])
        self.assertFalse(result["hy2_service_active"])

    def test_account_without_hy2_does_not_query_a_hy2_unit(self):
        member = self.create()
        reality = self.accounts.manager(member["id"]).service_name
        self.accounts.demo = False
        with mock.patch.object(server.base, "command", side_effect=self.command_for({reality: 0})) as command:
            result = self.accounts.get(member["id"])
        self.assertTrue(result["service_active"])
        self.assertIsNone(result["hy2_service_active"])
        self.assertIsNone(result["hy2_port"])
        command.assert_called_once()


if __name__ == "__main__":
    unittest.main()
