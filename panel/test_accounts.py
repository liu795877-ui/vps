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
from panel import subscriptions, telemetry


class AccountsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="panel-accounts-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        # Production's administrator entrance is 443; 8443 is the management
        # website and the legacy installer default, not a fourth quota port.
        with mock.patch.object(server.base, "PORT", 443):
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

    def test_nickname_changes_only_display_name_and_survives_reload(self):
        member = self.create()
        other = self.create("member_b")
        manager = self.accounts.manager(member["id"])
        before = copy.deepcopy(self.accounts.records)
        files = {path: path.read_bytes() for path in
                 (manager.config_path, manager.state_path, self.auth_path)}
        updated = self.accounts.update_nickname({"id": member["id"], "display_name": "  小张 · 办公电脑  "})
        expected = copy.deepcopy(before)
        expected[0]["display_name"] = "小张 · 办公电脑"
        self.assertEqual(self.accounts.records, expected)
        self.assertEqual(updated["username"], member["username"])
        self.assertEqual(updated["display_name"], "小张 · 办公电脑")
        for path, value in files.items():
            self.assertEqual(path.read_bytes(), value)
        reloaded = accounts.Accounts(self.owner, self.auth_path, demo=True)
        self.assertEqual(reloaded.get(member["id"])["display_name"], "小张 · 办公电脑")
        self.assertEqual(reloaded.authenticate(member["username"], "member-password-2026")["id"], member["id"])
        self.assertEqual(reloaded.get(other["id"])["display_name"], other["display_name"])
        self.assert_original_owner()

    def test_nickname_rejects_invalid_input_owner_and_missing_member(self):
        member = self.create()
        original = self.accounts.users_path.read_bytes()
        for value in (None, 123, "", "   ", "名" * 49, "小张\n电脑", "小张\x7f", "\ud800"):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(server.PanelError):
                    self.accounts.update_nickname({"id": member["id"], "display_name": value})
        for request in ({"id": member["id"]}, {"id": member["id"], "display_name": "小张", "username": "other"},
                        {"id": "admin", "display_name": "小张"}, {"id": "0" * 16, "display_name": "小张"}):
            with self.assertRaises(server.PanelError):
                self.accounts.update_nickname(request)
        self.assertEqual(self.accounts.users_path.read_bytes(), original)

    def test_nickname_save_failure_preserves_registry_and_memory(self):
        member = self.create()
        records = copy.deepcopy(self.accounts.records)
        original = self.accounts.users_path.read_bytes()
        with mock.patch.object(server, "atomic_write", side_effect=OSError("synthetic storage failure")):
            with self.assertRaises(OSError):
                self.accounts.update_nickname({"id": member["id"], "display_name": "新昵称"})
        self.assertEqual(self.accounts.records, records)
        self.assertEqual(self.accounts.users_path.read_bytes(), original)

    def test_nickname_can_change_disabled_member_without_enabling_services(self):
        member = self.create()
        self.accounts.set_enabled(member["id"], False)
        with mock.patch.object(self.accounts, "_start", side_effect=AssertionError("must not start")), \
                mock.patch.object(self.accounts, "_stop", side_effect=AssertionError("must not stop")):
            result = self.accounts.update_nickname({"id": member["id"], "display_name": "暂停使用的成员"})
        self.assertFalse(result["enabled"])
        self.assertFalse(self.accounts._record(member["id"])["enabled"])

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
        calls = [call.args[0] for call in command.call_args_list]
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
        calls = [call.args[0] for call in command.call_args_list]
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
        calls = [call.args[0] for call in command.call_args_list]
        self.assertFalse(any(first_manager.service_name in call for call in calls))
        self.assertEqual(instance.users_path.read_bytes(), registry)
        self.assertEqual(len(instance.records), 1)
        self.assertTrue(first_manager.config_path.is_file())
        self.assertEqual(len(list(instance.directory.iterdir())), 1)
        self.assert_original_owner()

    def test_delete_releases_only_member_slot_and_port(self):
        first, second = self.create(), self.create("member_b")
        first_manager = self.accounts.manager(first["id"])
        second_manager = self.accounts.manager(second["id"])
        second_state = copy.deepcopy(second_manager.state)
        second_config = second_manager.config_path.read_bytes()
        token = first_manager.state["rule_token"]
        result = self.accounts.delete_user(first["id"])
        self.assertEqual(result, {"id": first["id"], "deleted": True, "cleanup_pending": False})
        self.assertFalse(first_manager.directory.exists())
        self.assertTrue(first_manager.disabled)
        self.assertNotIn(first["id"], self.accounts._managers)
        with self.assertRaises(server.PanelError) as caught:
            self.accounts.get(first["id"])
        self.assertEqual(caught.exception.status, 404)
        with self.assertRaises(server.PanelError):
            self.accounts.rule_snapshot(token, "direct")
        replacement = self.create("member_c")
        self.assertEqual(replacement["port"], first["port"])
        self.assertNotEqual(replacement["id"], first["id"])
        self.assertEqual(second_manager.state, second_state)
        self.assertEqual(second_manager.config_path.read_bytes(), second_config)
        self.assert_original_owner()

    def test_delete_rejects_admin_and_busy_member(self):
        member = self.create()
        manager = self.accounts.manager(member["id"])
        with self.assertRaises(server.PanelError) as caught:
            self.accounts.delete_user("admin")
        self.assertEqual(caught.exception.status, 403)
        manager.operation.acquire()
        try:
            with self.assertRaises(server.PanelError) as caught:
                self.accounts.delete_user(member["id"])
            self.assertEqual(caught.exception.status, 409)
        finally:
            manager.operation.release()
        self.assertTrue(manager.config_path.is_file())
        self.assertEqual(len(self.accounts.records), 1)
        self.assert_original_owner()

    def test_delete_registry_failure_even_after_write_restores_files_runtime_and_other_member(self):
        instance, command = self.production_fixture()
        first = instance.create_user({"username": "member_a", "password": "member-password-2026"})
        second = instance.create_user({"username": "member_b", "password": "member-password-2026"})
        first_manager = instance.manager(first["id"])
        second_manager = instance.manager(second["id"])
        registry = instance.users_path.read_bytes()
        state_bytes = first_manager.state_path.read_bytes()
        config_bytes = first_manager.config_path.read_bytes()
        original_save = instance._save

        def fail_after_save(records):
            original_save(records)
            raise OSError("simulated post-write failure")

        command.reset_mock()
        with mock.patch.object(instance, "_save", side_effect=fail_after_save):
            with self.assertRaises(server.PanelError):
                instance.delete_user(first["id"])
        self.assertEqual(instance.users_path.read_bytes(), registry)
        self.assertEqual(first_manager.state_path.read_bytes(), state_bytes)
        self.assertEqual(first_manager.config_path.read_bytes(), config_bytes)
        self.assertFalse(first_manager.disabled)
        self.assertEqual(len(instance.records), 2)
        self.assertTrue(second_manager.config_path.is_file())
        calls = [call.args[0] for call in command.call_args_list]
        self.assertIn(["systemctl", "stop", first_manager.service_name], calls)
        self.assertIn(["systemctl", "start", first_manager.service_name], calls)
        self.assertFalse(any(second_manager.service_name in call or "xray.service" in call for call in calls))
        self.assert_original_owner()

    def test_delete_second_directory_move_failure_restores_first_directory(self):
        instance, command = self.production_fixture()
        member = instance.create_user({"username": "member_a", "password": "member-password-2026"})
        manager = instance.manager(member["id"])
        registry = instance.users_path.read_bytes()
        original_replace = accounts.os.replace

        def fail_config_move(source, destination):
            if Path(source) == manager.config_path.parent:
                raise OSError("simulated second directory failure")
            return original_replace(source, destination)

        with mock.patch.object(accounts.os, "replace", side_effect=fail_config_move):
            with self.assertRaises(server.PanelError):
                instance.delete_user(member["id"])
        self.assertEqual(instance.users_path.read_bytes(), registry)
        self.assertTrue(manager.config_path.is_file())
        self.assertTrue(manager.state_path.is_file())
        self.assertFalse(manager.disabled)
        self.assertEqual(len(list(instance.directory.iterdir())), 1)
        self.assert_original_owner()

    def test_delete_cleanup_failure_cannot_resurrect_credentials(self):
        member = self.create()
        with mock.patch.object(accounts.shutil, "rmtree", side_effect=OSError("simulated cleanup failure")):
            result = self.accounts.delete_user(member["id"])
        self.assertTrue(result["deleted"])
        self.assertTrue(result["cleanup_pending"])
        self.assertEqual(self.accounts.records, [])
        self.assertIsNone(self.accounts.authenticate("member_a", "member-password-2026"))
        replacement = self.create("member_c")
        self.assertEqual(replacement["port"], member["port"])
        self.assert_original_owner()

    def test_delete_stop_failure_preserves_account_and_disabled_delete_does_not_start_it(self):
        member = self.create()
        manager = self.accounts.manager(member["id"])
        with mock.patch.object(self.accounts, "_stop", side_effect=OSError("stop failed")), \
                mock.patch.object(self.accounts, "_start") as start:
            with self.assertRaises(server.PanelError):
                self.accounts.delete_user(member["id"])
            start.assert_called_once()
        self.assertTrue(manager.config_path.is_file())
        self.assertTrue(self.accounts.get(member["id"])["enabled"])
        self.accounts.set_enabled(member["id"], False)
        with mock.patch.object(self.accounts, "_start") as start:
            self.accounts.delete_user(member["id"])
            start.assert_not_called()
        self.assert_original_owner()

    def subscription_fixture(self):
        # Modern Manager init performs this migration as well. This explicit
        # step keeps account-only tests meaningful before server integration.
        self.accounts.profile_metadata("admin")
        self.initial_state = copy.deepcopy(self.owner.state)

    def test_subscription_is_account_scoped_stable_read_only_and_disabled_returns_404(self):
        self.subscription_fixture()
        first, second = self.create(), self.create("member_b")
        a, b = self.accounts.manager(first["id"]), self.accounts.manager(second["id"])
        old = copy.deepcopy(a.state)
        info = self.accounts.profile_metadata(first["id"])
        self.assertTrue(info["download_ready"])
        for _ in range(2):
            self.assertEqual(self.accounts.subscription_profile(a.state["profile_token"]), a.state["profile"])
        self.assertEqual(a.state, old)
        self.assertNotEqual(a.state["profile_token"], b.state["profile_token"])
        for token in ("A" * 43, "../bad", "\ud800", a.state["rule_token"]):
            with self.assertRaises(server.PanelError) as caught:
                self.accounts.subscription_profile(token)
            self.assertEqual(caught.exception.status, 404)
        token = a.state["profile_token"]
        self.accounts.set_enabled(first["id"], False)
        with self.assertRaises(server.PanelError) as caught:
            self.accounts.subscription_profile(token)
        self.assertEqual(caught.exception.status, 404)
        self.assertEqual(self.accounts.subscription_profile(b.state["profile_token"]), b.state["profile"])
        self.accounts.set_enabled(first["id"], True)
        self.assertEqual(self.accounts.subscription_profile(token), a.state["profile"])
        self.assert_original_owner()

    def test_rotating_subscription_revokes_only_link_and_preserves_all_proxy_credentials(self):
        self.subscription_fixture()
        member = self.create()
        manager = self.accounts.manager(member["id"])
        before = copy.deepcopy(manager.state)
        config = manager.config_path.read_bytes()
        auth = self.accounts.records[0]["auth"].copy()
        info = self.accounts.rotate_subscription_token(member["id"])
        self.assertNotEqual(manager.state["profile_token"], before["profile_token"])
        for key in before:
            if key != "profile_token":
                self.assertEqual(manager.state[key], before[key])
        self.assertEqual(manager.config_path.read_bytes(), config)
        self.assertEqual(self.accounts.records[0]["auth"], auth)
        self.assertEqual(info["version"], before["profile_version"])
        with self.assertRaises(server.PanelError) as caught:
            self.accounts.subscription_profile(before["profile_token"])
        self.assertEqual(caught.exception.status, 404)
        self.assertEqual(self.accounts.subscription_profile(manager.state["profile_token"]), manager.state["profile"])
        self.assert_original_owner()

    def test_rotating_proxy_credentials_revokes_all_identities_history_and_capabilities_only_for_one_user(self):
        self.subscription_fixture()
        first, second = self.create(), self.create("member_b")
        manager = self.accounts.manager(first["id"])
        other = self.accounts.manager(second["id"])
        request = {"name": "Own exit", "address": "verified.example", "port": 1080,
                   "auth": "credentials", "username": "upstream-user", "password": "upstream-pass"}
        exit_id = manager.edit_exit(request)["id"]
        manager.jobs["setup"] = {}
        manager.apply("setup", exit_id)
        manager.set_routing(["proxy.example"], "smart", ["direct.example"])
        # An unverified draft edit must remain a draft during revocation.
        manager.edit_exit(dict(request, id=exit_id, address="unverified.example"))
        draft_id = manager.edit_exit(dict(request, name="Draft only", address="draft.example"))["id"]
        before = copy.deepcopy(manager.state)
        other_state = copy.deepcopy(other.state)
        other_config = other.config_path.read_bytes()
        registry = self.accounts.users_path.read_bytes()
        result = self.accounts.rotate_credentials(first["id"])
        after = manager.state
        self.assertTrue(result["credentials_rotated"])
        self.assertEqual(after["history"], [])
        self.assertEqual(after["active_id"], exit_id)
        self.assertEqual(after["profile_version"], before["profile_version"] + 1)
        for field in ("auto_id", "rule_token", "profile_token"):
            self.assertNotEqual(after[field], before[field])
        self.assertNotEqual(after["base"]["inbounds"][0]["settings"]["clients"][0]["id"],
                            before["base"]["inbounds"][0]["settings"]["clients"][0]["id"])
        for field in ("public", "short", "domains", "direct_domains", "routing_mode"):
            self.assertEqual(after[field], before[field])
        old_ids = {before["auto_id"], before["base"]["inbounds"][0]["settings"]["clients"][0]["id"]}
        old_ids.update(item["client_id"] for item in before["exits"])
        raw = manager.config_path.read_text(encoding="utf-8") + after["profile"]
        for old_id in old_ids:
            self.assertNotIn(old_id, raw)
        draft = next(item for item in after["exits"] if item["id"] == exit_id)
        applied = next(item for item in after["applied_exits"] if item["id"] == exit_id)
        self.assertEqual(draft["address"], "unverified.example")
        self.assertEqual(applied["address"], "verified.example")
        self.assertEqual(draft["client_id"], applied["client_id"])
        self.assertNotIn("unverified.example", manager.config_path.read_text(encoding="utf-8"))
        self.assertFalse(any(item["id"] == draft_id for item in after["applied_exits"]))
        for method, token, args in ((self.accounts.rule_snapshot, before["rule_token"], ("direct",)),
                                    (self.accounts.subscription_profile, before["profile_token"], ())):
            with self.assertRaises(server.PanelError) as caught:
                method(token, *args)
            self.assertEqual(caught.exception.status, 404)
        self.assertEqual(other.state, other_state)
        self.assertEqual(other.config_path.read_bytes(), other_config)
        self.assertEqual(self.accounts.users_path.read_bytes(), registry)
        self.assertIsNotNone(self.accounts.authenticate("member_a", "member-password-2026"))
        # A cache reload must accept the exact replacement identities.
        reloaded = accounts.Accounts(self.owner, self.auth_path, demo=True)
        self.assertEqual(reloaded.manager(first["id"]).state, after)
        self.assert_original_owner()

    def test_rotate_credentials_save_failure_restores_private_state_and_running_config(self):
        self.subscription_fixture()
        member = self.create()
        manager = self.accounts.manager(member["id"])
        original_state = copy.deepcopy(manager.state)
        original_file = manager.state_path.read_bytes()
        original_config = manager.config_path.read_bytes()
        original_save = manager.save

        def fail_after_save(state):
            original_save(state)
            raise OSError("simulated disk failure after state write")

        with mock.patch.object(manager, "save", side_effect=fail_after_save):
            with self.assertRaises(server.PanelError):
                self.accounts.rotate_credentials(member["id"])
        self.assertEqual(manager.state, original_state)
        self.assertEqual(manager.state_path.read_bytes(), original_file)
        self.assertEqual(manager.config_path.read_bytes(), original_config)
        self.assertFalse(manager.operation.locked())
        self.assert_original_owner()

    def test_disabled_member_rotation_validates_offline_without_restarting_it(self):
        instance, command = self.production_fixture()
        member = instance.create_user({"username": "member_a", "password": "member-password-2026"})
        manager = instance.manager(member["id"])
        instance.set_enabled(member["id"], False)
        before = copy.deepcopy(manager.state)
        command.reset_mock()
        with mock.patch.object(manager, "install") as install:
            instance.rotate_credentials(member["id"])
            install.assert_not_called()
        calls = [call.args[0] for call in command.call_args_list]
        self.assertTrue(any(call[1:4] == ["run", "-test", "-config"] for call in calls))
        self.assertFalse(any(call[:2] in (["systemctl", "start"], ["systemctl", "restart"]) for call in calls))
        self.assertFalse(instance.get(member["id"])["enabled"])
        self.assertTrue(manager.disabled)
        self.assertNotEqual(manager.state["auto_id"], before["auto_id"])
        self.assertIsNone(instance.authenticate("member_a", "member-password-2026"))
        self.assert_original_owner()

    def test_admin_rotation_and_busy_member_are_isolated(self):
        self.subscription_fixture()
        member = self.create()
        manager = self.accounts.manager(member["id"])
        member_state = copy.deepcopy(manager.state)
        member_config = manager.config_path.read_bytes()
        original_auth = self.auth_path.read_bytes()
        old_uuid = self.owner.state["auto_id"]
        self.accounts.rotate_credentials("admin")
        self.assertNotEqual(self.owner.state["auto_id"], old_uuid)
        self.assertEqual(self.auth_path.read_bytes(), original_auth)
        self.assertEqual(manager.state, member_state)
        self.assertEqual(manager.config_path.read_bytes(), member_config)
        manager.operation.acquire()
        try:
            for method in (self.accounts.rotate_credentials, self.accounts.rotate_subscription_token):
                with self.assertRaises(server.PanelError) as caught:
                    method(member["id"])
                self.assertEqual(caught.exception.status, 409)
        finally:
            manager.operation.release()

    def test_member_validator_accepts_only_loopback_stats_api_and_reality_identity(self):
        member = self.create()
        manager = self.accounts.manager(member["id"])
        state = copy.deepcopy(manager.state)
        config = json.loads(manager.config_path.read_text(encoding="utf-8"))
        allowed = telemetry.augment_config(config)
        payload = server.json_bytes(allowed)
        state["managed_hash"] = server.digest(payload)
        server.atomic_write(manager.state_path, server.json_bytes(state))
        server.atomic_write(manager.config_path, payload)
        reloaded = accounts.Accounts(self.owner, self.auth_path, demo=True)
        self.assertEqual(reloaded.manager(member["id"]).state["auto_id"], state["auto_id"])
        for kind in ("public-api", "write-api", "foreign-inbound", "changed-reality", "foreign-uuid"):
            candidate = copy.deepcopy(allowed)
            if kind == "public-api":
                candidate["api"]["listen"] = "0.0.0.0:16443"
            elif kind == "write-api":
                candidate["api"]["services"].append("HandlerService")
            elif kind == "foreign-inbound":
                candidate["inbounds"].append({"port": 10000, "protocol": "socks"})
            elif kind == "changed-reality":
                candidate["inbounds"][0]["streamSettings"]["realitySettings"]["privateKey"] = "Z" * 43
            else:
                candidate["inbounds"][0]["settings"]["clients"][0]["id"] = "11111111-1111-4111-8111-111111111111"
            payload = server.json_bytes(candidate)
            state["managed_hash"] = server.digest(payload)
            server.atomic_write(manager.state_path, server.json_bytes(state))
            server.atomic_write(manager.config_path, payload)
            reloaded = accounts.Accounts(self.owner, self.auth_path, demo=True)
            with self.subTest(kind=kind):
                with self.assertRaises(server.PanelError) as caught:
                    reloaded.manager(member["id"])
                self.assertEqual(caught.exception.status, 409)
        self.assert_original_owner()


if __name__ == "__main__":
    unittest.main()
