"""Deadline, dual-protocol shutdown, renewal and web authorization regressions.

All accounts/files are temporary. Network controls, counters and systemd are
injected; HTTP requests use a loopback demo only.
"""
import copy
import json
from types import SimpleNamespace
import unittest
from unittest import mock

from panel import accounts, backups, membership, server, telemetry
from panel import test_operations as fixtures
from panel import test_multiuser_http as http_fixtures


class MembershipTests(fixtures.Fixture):
    def setUp(self):
        super().setUp()
        self.accounts.clock = self.clock
        self.controls = fixtures.Controls()
        self.traffic = telemetry.Telemetry(self.accounts, controls=self.controls,
            runner=http_fixtures.isolated_telemetry_runner, clock=self.clock)
        self.accounts.telemetry = self.traffic
        self.members = membership.Memberships(self.accounts, self.traffic)
        self.accounts.memberships = self.members
        self.user_id = self.member["id"]

    def change(self, expires_at, **extra):
        value = self.accounts.get(self.user_id)["membership"]
        request = dict(id=self.user_id, revision=value["revision"], plan="月度订阅",
                       expires_at=expires_at, note="联系管理员续费")
        request.update(extra)
        return self.members.update(self.user_id, request)

    def test_new_member_has_30_days_legacy_and_owner_do_not_expire(self):
        current = self.accounts.records[0]
        self.assertAlmostEqual(current["membership"]["expires_at"] - current["membership"]["updated_at"], 30*86400)
        legacy = copy.deepcopy(current)
        del legacy["membership"]
        self.assertFalse(membership.expired(legacy, membership.MAX_TIME))
        self.assertEqual(self.members.snapshot(legacy)["status"], "unlimited")
        self.assertEqual(self.accounts.get("admin")["membership"]["status"], "admin")
        with self.assertRaises(server.PanelError):
            self.members.update("admin", dict(plan="admin", expires_at=1, revision=0))

    def test_exact_deadline_blocks_and_stops_without_deleting_identity(self):
        manager = self.accounts.manager(self.user_id)
        before = manager.config_path.read_bytes(), manager.state_path.read_bytes()
        deadline = int(self.clock_value) + 1
        self.change(deadline)
        self.assertFalse(self.accounts.get(self.user_id)["membership"]["expired"])
        self.clock_value = deadline
        with mock.patch.object(self.accounts, "_stop", wraps=self.accounts._stop) as stop:
            self.members.tick()
            stop.assert_called_once()
            self.members.tick()
            stop.assert_called_once()
        self.assertIn(self.member["port"], self.controls.calls[-1][0])
        self.assertFalse(self.accounts.get(self.user_id)["proxy_enabled"])
        self.assertTrue(self.accounts.get(self.user_id)["enabled"])
        self.assertIsNotNone(self.accounts.authenticate("member_a", "member-password-2026"))
        with self.assertRaises(server.PanelError):
            self.accounts.manager(self.user_id)
        with self.assertRaises(server.PanelError):
            manager.install(before[0], before[0], "unused")
        self.assertEqual(before, (manager.config_path.read_bytes(), manager.state_path.read_bytes()))

    def test_expiry_stops_tcp_and_hy2_even_when_kernel_update_fails(self):
        self.change(int(self.clock_value) + 1)
        self.clock_value += 1
        acceleration = SimpleNamespace(enabled=True, stop=mock.Mock())
        self.accounts.acceleration = acceleration
        self.accounts.demo = False
        try:
            with mock.patch.object(self.traffic.controls, "apply", side_effect=RuntimeError("iptables failed")), \
                    mock.patch.object(server.base, "command") as command:
                self.members.tick()
                acceleration.stop.assert_called_once()
                commands = [call[0][0] for call in command.call_args_list]
                self.assertIn(["systemctl", "stop", self.accounts._service(self.member)], commands)
                self.assertIn(["systemctl", "disable", self.accounts._service(self.member)], commands)
        finally:
            self.accounts.demo = True
            del self.accounts.acceleration
        self.assertIsNotNone(self.members.snapshot(self.accounts._record(self.user_id))["enforcement_error"])
        self.members.tick()
        self.assertIsNone(self.members.snapshot(self.accounts._record(self.user_id))["enforcement_error"])

    def test_renewal_restores_original_identity_and_respects_quota(self):
        manager = self.accounts.manager(self.user_id)
        before = manager.config_path.read_bytes(), manager.state_path.read_bytes()
        self.change(int(self.clock_value))
        self.members.request_renewal(self.user_id, {"message": "续费30天"})
        self.traffic.set_limits(self.user_id, 1, 0)
        entry = self.traffic._entry(self.user_id)
        entry["months"][self.traffic._month()] = {"up_bytes": 1, "down_bytes": 0}
        with mock.patch.object(self.accounts, "_start", wraps=self.accounts._start) as start:
            renewed = self.change(int(self.clock_value) + 86400, resolve_renewal=True)
            start.assert_called_once()
        self.assertTrue(renewed["proxy_enabled"])
        self.assertFalse(renewed["membership"]["renewal_pending"])
        self.assertIn(self.member["port"], self.controls.calls[-1][0])
        self.traffic.set_limits(self.user_id, 0, 0)
        self.assertNotIn(self.member["port"], self.controls.calls[-1][0])
        self.assertEqual(before, (manager.config_path.read_bytes(), manager.state_path.read_bytes()))

    def test_renewal_never_enables_a_manually_disabled_account(self):
        self.change(int(self.clock_value))
        self.accounts.set_enabled(self.user_id, False)
        with mock.patch.object(self.accounts, "_start") as start:
            value = self.change(None)
            start.assert_not_called()
        self.assertFalse(value["enabled"])
        self.assertFalse(value["proxy_enabled"])

    def test_resumption_failure_is_persisted_and_retried(self):
        self.change(int(self.clock_value))
        with mock.patch.object(self.accounts, "_start", side_effect=RuntimeError("service unavailable")):
            with self.assertRaises(server.PanelError):
                self.change(int(self.clock_value) + 86400)
        self.assertTrue(self.accounts._record(self.user_id)["membership"]["suspended"])
        reloaded = accounts.Accounts(self.owner, self.auth_path, demo=True)
        reloaded.clock = self.clock
        reloaded.telemetry = telemetry.Telemetry(reloaded, controls=self.controls,
            runner=http_fixtures.isolated_telemetry_runner, clock=self.clock)
        control = membership.Memberships(reloaded, reloaded.telemetry)
        with mock.patch.object(reloaded, "_start", wraps=reloaded._start) as start:
            control.tick()
            start.assert_called_once()
        self.assertFalse(reloaded._record(self.user_id)["membership"]["suspended"])

    def test_enable_does_not_bypass_expiry_and_token_profiles_are_revoked(self):
        metadata = self.accounts.profile_metadata(self.user_id)
        token = self.accounts.manager(self.user_id).state["profile_token"]
        self.assertTrue(self.accounts.subscription_profile(token))
        self.change(int(self.clock_value))
        with self.assertRaises(server.PanelError):
            self.accounts.subscription_profile(token)
        self.accounts.set_enabled(self.user_id, False)
        self.accounts.set_enabled(self.user_id, True)
        self.assertFalse(self.accounts.get(self.user_id)["proxy_enabled"])
        self.assertTrue(self.accounts.profile_metadata(self.user_id))

    def test_requests_are_idempotent_and_stale_admin_edits_are_rejected(self):
        previous = self.accounts.get(self.user_id)["membership"]
        first = self.members.request_renewal(self.user_id, {"message": "30天"})
        self.clock_value += 100
        repeated = self.members.request_renewal(self.user_id, {"message": "90天"})
        self.assertEqual(first["renewal_requested_at"], repeated["renewal_requested_at"])
        self.assertEqual(repeated["renewal_message"], "30天")
        with self.assertRaises(server.PanelError) as error:
            self.change(None, revision=previous["revision"])
        self.assertEqual(error.exception.status, 409)
        for field, value in (("expires_at", True), ("expires_at", float("nan")),
                             ("plan", ""), ("note", "x\ny"), ("expires_at", membership.MAX_TIME+1)):
            with self.subTest(field=field), self.assertRaises(server.PanelError):
                self.change(None, **{field: value}) if field != "expires_at" else self.change(value)

    def test_backup_restore_preserves_expired_terms_and_requests(self):
        self.change(int(self.clock_value))
        self.members.request_renewal(self.user_id, {"message": "需要续费"})
        backup = backups.BackupManager(self.accounts)
        created = backup.create("membership")
        # Decode the actual encrypted snapshot through the supported preview path.
        exported = backup.export(created["id"], "temporary-export-password")
        payload, unused = backup.download(exported["download_token"])
        import base64
        preview = backup.preview(base64.b64encode(payload).decode("ascii"), "temporary-export-password")
        self.change(None, resolve_renewal=True)
        # A real edit after preview intentionally invalidates it; obtain a fresh one.
        preview = backup.preview(base64.b64encode(payload).decode("ascii"), "temporary-export-password")
        backup.restore(preview["preview_token"], "RESTORE")
        self.members.stopped.clear()
        self.members.tick()
        value = self.accounts.get(self.user_id)["membership"]
        self.assertTrue(value["expired"])
        self.assertTrue(value["renewal_pending"])
        self.assertIn(self.member["port"], self.controls.calls[-1][0])


class MembershipHttpTests(unittest.TestCase):
    setUp = http_fixtures.MultiuserHttpTests.setUp
    request = http_fixtures.MultiuserHttpTests.request
    login = http_fixtures.MultiuserHttpTests.login

    def change(self, user, expires):
        latest = self.app.accounts.get(user["id"])["membership"]
        self.app.telemetry.controls = fixtures.Controls()
        return self.request("/api/users/membership", dict(id=user["id"], revision=latest["revision"],
            plan="测试订阅", expires_at=expires, note="联系管理员"), self.admin)

    def test_expired_web_login_and_request_work_but_proxy_actions_do_not(self):
        user, session = self.users[0], self.sessions[0]
        self.assertEqual(self.change(user, 1)[0], 200)
        self.assertEqual(self.request("/api/state", session=session)[0], 200)
        self.assertEqual(self.request("/api/profile", session=session)[0], 403)
        for path in ("apply", "health/check", "credentials/rotate", "subscription/rotate"):
            self.assertEqual(self.request("/api/"+path, {"id":"server"}, session)[0], 403)
        status, _, body = self.request("/api/membership/renewal", {"message": "续费30天"}, session)
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["membership"]["renewal_pending"])
        self.login(user["username"], user["username"] + "-test-password-2026")
        self.assertEqual(self.change(user, None)[0], 200)
        self.assertEqual(self.request("/api/profile", session=session)[0], 200)

    def test_members_cannot_edit_terms_or_request_for_other_users(self):
        self.assertEqual(self.request("/api/users/membership", {"id": self.users[1]["id"]}, self.sessions[0])[0], 403)
        self.assertEqual(self.request("/api/membership/renewal", {"id": self.users[1]["id"]}, self.sessions[0])[0], 400)
        self.assertEqual(self.request("/api/membership/renewal", {}, self.admin)[0], 403)
        wrong_csrf = dict(self.sessions[0], csrf="wrong")
        self.assertEqual(self.request("/api/membership/renewal", {}, wrong_csrf)[0], 403)
        self.assertEqual(self.request("/api/membership/renewal", {})[0], 401)
        self.assertFalse(self.app.accounts.get(self.users[1]["id"])["membership"]["renewal_pending"])


if __name__ == "__main__":
    unittest.main()
