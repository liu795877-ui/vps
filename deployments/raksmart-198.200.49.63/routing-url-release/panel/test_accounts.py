"""Account isolation, provisioning rollback, and credential boundary tests."""

import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from panel import accounts
from panel import server


class AccountsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="panel-accounts-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.owner = server.Manager(self.directory / "owner", "8.8.8.8",
                                    self.directory / "owner" / "config.json", demo=True)
        self.auth_path = self.owner.directory / "auth.private.json"
        server.atomic_write(self.auth_path, server.json_bytes(server.password_record("owner-password-2026")))
        self.initial_auth = self.auth_path.read_bytes()
        self.initial_config = self.owner.config_path.read_bytes()
        self.initial_state = copy.deepcopy(self.owner.state)
        self.accounts = accounts.Accounts(self.owner, self.auth_path, demo=True)

    def create(self, username="member_a"):
        return self.accounts.create_user({"username": username, "password": "member-password-2026",
                                          "display_name": "成员 " + username})

    def assert_original_owner(self):
        self.assertEqual(self.auth_path.read_bytes(), self.initial_auth)
        self.assertEqual(self.owner.config_path.read_bytes(), self.initial_config)
        self.assertEqual(self.owner.state, self.initial_state)

    def test_existing_admin_is_preserved_and_registry_survives_reload(self):
        member = self.create()
        reloaded = accounts.Accounts(self.owner, self.auth_path, demo=True)
        self.assertEqual(reloaded.authenticate("admin", "owner-password-2026")["id"], "admin")
        self.assertEqual(reloaded.authenticate("member_a", "member-password-2026")["id"], member["id"])
        self.assertIsNone(reloaded.authenticate("member_a", "owner-password-2026"))
        self.assertIsNone(reloaded.authenticate("unknown", "member-password-2026"))
        self.assertEqual(reloaded.manager(member["id"]).state,
                         self.accounts.manager(member["id"]).state)
        self.assert_original_owner()

    def test_independent_identities_ports_profiles_and_custom_rules(self):
        a, b = self.create(), self.create("member_b")
        first, second = self.accounts.manager(a["id"]), self.accounts.manager(b["id"])
        self.assertEqual([a["port"], b["port"]], [1443, 2443])
        self.assertEqual(first.service_name, "xray-panel@" + a["id"] + ".service")
        all_managers = [self.owner, first, second]
        for field in ("auto_id", "rule_token", "public", "short"):
            self.assertEqual(len({manager.state[field] for manager in all_managers}), 3)
        self.assertEqual(len({manager.state["base"]["inbounds"][0]["settings"]["clients"][0]["id"]
                              for manager in all_managers}), 3)
        self.assertEqual(len({manager.state["base"]["inbounds"][0]["streamSettings"]["realitySettings"]["privateKey"]
                              for manager in all_managers}), 3)
        for member, manager in ((a, first), (b, second)):
            self.assertEqual(manager.state["routing_mode"], "smart")
            self.assertEqual(manager.state["active_id"], "server")
            self.assertIn("    port: " + str(member["port"]), manager.state["profile"])
            self.assertIn(manager.state["auto_id"], manager.state["profile"])
            self.assertNotIn(self.owner.state["auto_id"], manager.state["profile"])
            self.assertEqual(manager.state["base"]["inbounds"][0]["streamSettings"]["realitySettings"]["target"],
                             self.owner.state["base"]["inbounds"][0]["streamSettings"]["realitySettings"]["target"])
        first.set_routing(["first.example"], "smart", ["direct.second.example"])
        self.assertIn("first.example", self.accounts.rule_snapshot(first.state["rule_token"], "proxy"))
        self.assertNotIn("first.example", self.accounts.rule_snapshot(second.state["rule_token"], "proxy"))
        first.edit_exit({"name": "A own exit", "address": "proxy.first.example", "port": 1080,
                         "auth": "credentials", "username": "private-a", "password": "proxy-secret-a",
                         "expected_ip": ""})
        self.assertEqual(len(first.state["exits"]), 1)
        self.assertEqual(second.state["exits"], [])
        self.assert_original_owner()

    def test_public_account_response_does_not_expose_secrets(self):
        member = self.create()
        manager = self.accounts.manager(member["id"])
        response = json.dumps(self.accounts.list_users())
        stored = self.accounts.users_path.read_text(encoding="utf-8")
        self.assertNotIn("member-password-2026", stored)
        self.assertNotIn("member-password-2026", response)
        for value in (manager.state["auto_id"], manager.state["rule_token"],
                      manager.state["base"]["inbounds"][0]["streamSettings"]["realitySettings"]["privateKey"],
                      self.accounts.records[0]["auth"]["hash"], str(manager.config_path)):
            self.assertNotIn(value, response)
        self.assertEqual(member["role"], "member")
        self.assertEqual(member["exit_count"], 0)

    def test_users_cannot_choose_paths_ports_ids_or_roles(self):
        for key, value in (("port", 443), ("id", "../../admin"), ("service", "xray.service"),
                           ("config_path", "/usr/local/etc/xray/config.json"), ("role", "admin")):
            with self.subTest(key=key):
                with self.assertRaises(server.PanelError):
                    self.accounts.create_user({"username": "member_a", "password": "member-password-2026",
                                               key: value})
        for name in ("../root", "a/b", "admin", "ADMIN", "a", "bad name"):
            with self.subTest(name=name):
                with self.assertRaises(server.PanelError):
                    self.create(name)
        self.assertEqual(self.accounts.records, [])
        self.assert_original_owner()

    def test_reloaded_disabled_account_and_mismatched_member_port_are_guarded(self):
        member = self.create()
        manager = self.accounts.manager(member["id"])
        self.accounts.set_enabled(member["id"], False)
        reloaded = accounts.Accounts(self.owner, self.auth_path, demo=True)
        self.assertFalse(reloaded.get(member["id"])["enabled"])
        self.assertTrue(reloaded._managers[member["id"]].disabled)
        self.assertIsNone(reloaded.authenticate("member_a", "member-password-2026"))
        self.accounts.set_enabled(member["id"], True)
        state = copy.deepcopy(manager.state)
        state["base"]["inbounds"][0]["port"] = self.owner.state["base"]["inbounds"][0]["port"]
        server.atomic_write(manager.state_path, server.json_bytes(state))
        reloaded = accounts.Accounts(self.owner, self.auth_path, demo=True)
        with self.assertRaises(server.PanelError) as caught:
            reloaded.manager(member["id"])
        self.assertEqual(caught.exception.status, 409)
        self.assert_original_owner()

    def test_capacity_and_disabled_member_retains_its_reserved_port(self):
        a, b = self.create(), self.create("member_b")
        self.accounts.set_enabled(a["id"], False)
        with self.assertRaises(server.PanelError) as caught:
            self.create("member_c")
        self.assertEqual(caught.exception.status, 409)
        self.assertEqual(self.accounts.get(b["id"])["port"], 2443)
        self.assertEqual(len(self.accounts.list_users()), 3)

    def test_disable_blocks_login_manager_jobs_and_capability_without_affecting_other_user(self):
        a, b = self.create(), self.create("member_b")
        manager = self.accounts.manager(a["id"])
        token = manager.state["rule_token"]
        self.assertEqual(self.accounts.set_enabled(a["id"], False)["enabled"], False)
        self.assertTrue(manager.disabled)
        self.assertIsNone(self.accounts.authenticate("member_a", "member-password-2026"))
        with self.assertRaises(server.PanelError) as caught:
            self.accounts.manager(a["id"])
        self.assertEqual(caught.exception.status, 403)
        with self.assertRaises(server.PanelError):
            manager.start_job("apply", "server")
        with self.assertRaises(server.PanelError) as caught:
            self.accounts.rule_snapshot(token, "direct")
        self.assertEqual(caught.exception.status, 404)
        self.assertTrue(self.accounts.authenticate("member_b", "member-password-2026")["enabled"])
        self.assertEqual(self.accounts.set_enabled(a["id"], True)["enabled"], True)
        self.assertFalse(manager.disabled)
        self.assertEqual(manager.state["rule_token"], token)
        self.assertIs(self.accounts.manager(b["id"]), self.accounts.manager(b["id"]))
        self.assert_original_owner()

    def test_running_member_job_and_admin_cannot_be_disabled(self):
        member = self.create()
        manager = self.accounts.manager(member["id"])
        manager.operation.acquire()
        try:
            with self.assertRaises(server.PanelError) as caught:
                self.accounts.set_enabled(member["id"], False)
            self.assertEqual(caught.exception.status, 409)
        finally:
            manager.operation.release()
        self.assertTrue(self.accounts.get(member["id"])["enabled"])
        with self.assertRaises(server.PanelError) as caught:
            self.accounts.set_enabled("admin", False)
        self.assertEqual(caught.exception.status, 403)

    def test_password_reset_and_self_change_are_independent(self):
        member = self.create()
        with self.assertRaises(server.PanelError):
            self.accounts.change_password(member["id"], "wrong-current-password", "new-password-2026")
        self.accounts.change_password(member["id"], "member-password-2026", "new-password-2026")
        self.assertIsNone(self.accounts.authenticate("member_a", "member-password-2026"))
        self.assertIsNotNone(self.accounts.authenticate("member_a", "new-password-2026"))
        self.accounts.reset_password(member["id"], "reset-password-2026")
        self.assertIsNone(self.accounts.authenticate("member_a", "new-password-2026"))
        self.assertIsNotNone(self.accounts.authenticate("member_a", "reset-password-2026"))
        self.assert_original_owner()
        self.accounts.change_password("admin", "owner-password-2026", "owner-new-password-2026")
        self.assertIsNone(self.accounts.authenticate("admin", "owner-password-2026"))
        self.assertIsNotNone(self.accounts.authenticate("admin", "owner-new-password-2026"))
        self.assertIsNotNone(self.accounts.authenticate("member_a", "reset-password-2026"))

    def production_fixture(self):
        instance = accounts.Accounts(self.owner, self.auth_path, demo=False)
        command = mock.Mock(return_value=SimpleNamespace(returncode=0, stdout=""))
        patches = (mock.patch.object(accounts, "CONFIG_ROOT", self.directory / "production-config"),
                   mock.patch.object(instance, "_keys", return_value=("A" * 43, "B" * 43)),
                   mock.patch.object(instance, "_wait_ready"),
                   mock.patch.object(server.base, "command", command),
                   mock.patch.object(accounts.socket, "socket"))
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        return instance, command

    def test_production_validates_then_starts_only_new_template_instance(self):
        instance, command = self.production_fixture()
        member = instance.create_user({"username": "member_a", "password": "member-password-2026"})
        calls = [call[0][0] for call in command.call_args_list]
        service = "xray-panel@" + member["id"] + ".service"
        self.assertEqual(calls[0][1:4], ["run", "-test", "-config"])
        self.assertIn(["systemctl", "enable", service], calls)
        self.assertIn(["systemctl", "start", service], calls)
        self.assertFalse(any("xray.service" in call for call in calls))
        self.assertTrue(instance.manager(member["id"]).config_path.is_file())
        self.assert_original_owner()

    def test_failed_member_start_rolls_back_only_new_files_and_service(self):
        instance, command = self.production_fixture()
        instance._wait_ready.side_effect = RuntimeError("simulated listener failure")
        with self.assertRaises(server.PanelError):
            instance.create_user({"username": "member_a", "password": "member-password-2026"})
        calls = [call[0][0] for call in command.call_args_list]
        self.assertTrue(any(call[:2] == ["systemctl", "stop"] for call in calls))
        self.assertTrue(any(call[:2] == ["systemctl", "disable"] for call in calls))
        self.assertFalse(any("xray.service" in call for call in calls))
        self.assertEqual(instance.records, [])
        self.assertEqual(list(instance.directory.iterdir()), [])
        self.assertEqual(list((self.directory / "production-config").iterdir()), [])
        self.assert_original_owner()

    def test_registry_failure_after_start_stops_new_instance_and_keeps_existing_member(self):
        instance, command = self.production_fixture()
        first = instance.create_user({"username": "member_a", "password": "member-password-2026"})
        first_manager = instance.manager(first["id"])
        registry = instance.users_path.read_bytes()
        command.reset_mock()
        with mock.patch.object(instance, "_save", side_effect=OSError("disk full")):
            with self.assertRaises(server.PanelError):
                instance.create_user({"username": "member_b", "password": "member-password-2026"})
        calls = [call[0][0] for call in command.call_args_list]
        self.assertFalse(any(first_manager.service_name in call for call in calls))
        self.assertEqual(instance.users_path.read_bytes(), registry)
        self.assertEqual(len(instance.records), 1)
        self.assertTrue(first_manager.config_path.is_file())
        self.assertEqual(len(list(instance.directory.iterdir())), 1)
        self.assert_original_owner()


if __name__ == "__main__":
    unittest.main()
