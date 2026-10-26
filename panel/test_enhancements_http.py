"""Verify the new features through authenticated HTTP with isolated demo data."""

import base64
import copy
import http.client
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest import mock
from urllib.parse import urlsplit

from panel import server


def isolated_telemetry_runner(args, check=True, timeout=12):
    """Return synthetic counter probes; never read the host's services."""
    if args[:2] == ["systemctl", "show"]:
        return SimpleNamespace(stdout=b"MainPID=1\nExecMainStartTimestampMonotonic=1\n")
    if "statsquery" in args:
        return SimpleNamespace(stdout=b'{"stat":[]}')
    if args and args[0] == "ss":
        return SimpleNamespace(stdout=b"")
    raise AssertionError("unexpected telemetry command: " + " ".join(args))


class Controls:
    def __init__(self):
        self.calls = []

    def apply(self, blocked, rates):
        self.calls.append((set(blocked), dict(rates)))


class EnhancementHttpTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="panel-enhancements-http-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.owner = server.Manager(self.directory, "8.8.8.8", self.directory / "config.json", demo=True)
        self.httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        self.origin = "http://127.0.0.1:" + str(self.httpd.server_address[1])
        self.app = server.Application(self.owner, self.origin, "/", demo=True)
        self.app.telemetry.runner = isolated_telemetry_runner
        self.app.telemetry.controls = Controls()
        # A complete restore rebuilds Telemetry. Keep that replacement inside
        # the same synthetic runner/controls boundary as the initial fixture.
        initialize_operations = self.app._initialize_operations
        def initialize_for_fixture():
            initialize_operations()
            self.app.telemetry.runner = isolated_telemetry_runner
            self.app.telemetry.controls = Controls()
        self.app._initialize_operations = initialize_for_fixture
        self.httpd.application = self.app
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)
        self.admin = self.login("admin", "demo-password-2026")
        self.users, self.sessions = [], []
        for username in ("member-a", "member-b"):
            status, _, payload = self.request("/api/users/create", {
                "username": username, "password": username + "-test-password-2026",
                "display_name": username}, self.admin)
            self.assertEqual(status, 200)
            self.users.append(json.loads(payload)["user"])
            self.sessions.append(self.login(username, username + "-test-password-2026"))

    def request(self, path, data=None, session=None):
        headers = {"Origin": self.origin}
        if session:
            headers.update({"Cookie": session["cookie"], "X-CSRF-Token": session["csrf"]})
        if data is not None:
            headers["Content-Type"] = "application/json"
        connection = http.client.HTTPConnection("127.0.0.1", self.httpd.server_address[1], timeout=15)
        try:
            connection.request("POST" if data is not None else "GET", path,
                               json.dumps(data) if data is not None else None, headers)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def login(self, username, password):
        status, headers, payload = self.request("/api/login", {"username": username, "password": password})
        self.assertEqual(status, 200)
        return dict(json.loads(payload), cookie=headers["Set-Cookie"].split(";", 1)[0])

    def subscription(self, session):
        status, _, payload = self.request("/api/subscription", session=session)
        self.assertEqual(status, 200)
        return json.loads(payload)

    def test_only_admin_can_change_nickname_without_revoking_member_session(self):
        target = self.users[0]
        request = {"id": target["id"], "display_name": "小张 · 办公电脑"}
        path = "/api/users/nickname"
        self.assertEqual(self.request(path, request)[0], 401)
        for session in self.sessions:
            self.assertEqual(self.request(path, request, session)[0], 403)
        bad_csrf = dict(self.admin, csrf="invalid-csrf-token")
        self.assertEqual(self.request(path, request, bad_csrf)[0], 403)
        status, headers, payload = self.request(path, request, self.admin)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload)["user"]["display_name"], request["display_name"])
        member = json.loads(self.request("/api/session", session=self.sessions[0])[2])
        self.assertTrue(member["authenticated"])
        self.assertEqual(member["user"]["display_name"], request["display_name"])
        self.assertEqual(self.request("/api/state", session=self.sessions[0])[0], 200)
        users = json.loads(self.request("/api/users", session=self.admin)[2])["users"]
        self.assertEqual(next(user for user in users if user["id"] == target["id"])["display_name"], request["display_name"])
        self.assertEqual(next(user for user in users if user["id"] == self.users[1]["id"])["display_name"], self.users[1]["display_name"])
        self.assertEqual(self.request(path, {"id": "admin", "display_name": "管理员别名"}, self.admin)[0], 403)
        self.assertEqual(self.request(path, dict(request, password="unexpected-secret"), self.admin)[0], 400)
        for unused in range(50):
            events = json.loads(self.request("/api/audit", session=self.sessions[0])[2])["events"]
            if any(event["action"] == "user.nickname" and event["status"] == "success" for event in events):
                break
            time.sleep(.01)
        self.assertTrue(any(event["action"] == "user.nickname" and event["status"] == "success" for event in events))

    def subscription_path(self, subscription):
        # Caddy strips the public base path before forwarding to this handler.
        return "/subscription/" + urlsplit(subscription["url"]).path.rsplit("/", 1)[1]

    def test_subscription_revocation_keeps_other_profiles_and_proxy_identity(self):
        a, b = self.sessions
        manager = self.app.accounts.manager(self.users[0]["id"])
        original = copy.deepcopy(manager.state)
        old_a, old_b = self.subscription(a), self.subscription(b)
        path_a, path_b = self.subscription_path(old_a), self.subscription_path(old_b)
        self.assertEqual(self.request(path_a)[0], 200)
        other_profile = self.request(path_b)[2]
        status, _, payload = self.request("/api/subscription/rotate", {}, a)
        self.assertEqual(status, 200)
        self.assertNotEqual(old_a["url"], json.loads(payload)["url"])
        self.assertEqual(self.request(path_a)[0], 404)
        self.assertEqual(self.request(path_b)[2], other_profile)
        for key in ("base", "auto_id", "rule_token", "exits", "profile"):
            self.assertEqual(manager.state[key], original[key])
        self.assertEqual(self.subscription(b), old_b)

    def test_credentials_revoke_old_config_and_rules_only_for_confirmed_target(self):
        a, b = self.sessions
        user = self.users[0]
        manager = self.app.accounts.manager(user["id"])
        old_state = copy.deepcopy(manager.state)
        old_subscription = self.subscription_path(self.subscription(a))
        old_rules = "/rules/custom/" + manager.state["rule_token"] + "/direct.yaml"
        other = self.app.accounts.manager(self.users[1]["id"])
        other_state = copy.deepcopy(other.state)
        path = "/api/users/rotate-credentials"
        self.assertEqual(self.request(path, {"id": user["id"], "confirm_username": "wrong"}, self.admin)[0], 400)
        self.assertEqual(self.request(path, {"id": user["id"], "confirm_username": user["username"]}, b)[0], 403)
        self.assertEqual(self.request(path, {"id": user["id"], "confirm_username": user["username"]}, self.admin)[0], 200)
        self.assertNotEqual(manager.state["auto_id"], old_state["auto_id"])
        self.assertNotEqual(manager.state["base"]["inbounds"][0]["settings"]["clients"][0]["id"],
                            old_state["base"]["inbounds"][0]["settings"]["clients"][0]["id"])
        self.assertEqual(self.request(old_rules)[0], 404)
        self.assertEqual(self.request(old_subscription)[0], 404)
        self.assertEqual(other.state, other_state)
        self.assertEqual(self.request("/api/state", session=a)[0], 200)
        self.assertEqual(self.request("/api/state", session=b)[0], 200)

    def test_delete_releases_slot_and_revokes_session_bearers_without_touching_other(self):
        a, b = self.sessions
        user = self.users[0]
        old_subscription = self.subscription_path(self.subscription(a))
        manager = self.app.accounts.manager(user["id"])
        rule_path = "/rules/custom/" + manager.state["rule_token"] + "/direct.yaml"
        path = "/api/users/delete"
        self.assertEqual(self.request(path, {"id": "admin", "confirm_username": "admin"}, self.admin)[0], 403)
        self.assertEqual(self.request(path, {"id": user["id"], "confirm_username": user["username"]}, self.admin)[0], 200)
        for revoked in (old_subscription, rule_path):
            self.assertEqual(self.request(revoked)[0], 404)
        self.assertEqual(self.request("/api/state", session=a)[0], 401)
        self.assertEqual(self.request("/api/state", session=b)[0], 200)
        self.assertEqual(self.request("/api/users/create", {"username": "member-c", "password": "replacement-password-2026"}, self.admin)[0], 200)

    def test_diagnostic_strips_private_url_and_member_audit_includes_admin_target_action(self):
        a, b = self.sessions
        self.assertEqual(self.request("/api/routing", {"mode": "smart", "domains": [], "direct_domains": ["mooc1.chaoxing.com"]}, a)[0], 200)
        private_url = "https://mooc1.chaoxing.com/mycourse/studentstudy?enc=private-course-token&chapterId=123"
        with mock.patch("urllib.request.urlopen", side_effect=AssertionError("User URL must not be fetched")):
            status, _, payload = self.request("/api/diagnostics", {"url": private_url}, a)
        self.assertEqual(status, 200)
        diagnostic = json.loads(payload)
        self.assertEqual((diagnostic["domain"], diagnostic["decision"], diagnostic["client_verified"]),
                         ("mooc1.chaoxing.com", "direct", False))
        self.assertNotIn("private-course-token", payload.decode())
        target = self.users[0]
        self.request("/api/users/rotate-credentials", {"id": target["id"], "confirm_username": target["username"]}, self.admin)
        events_a = json.loads(self.request("/api/audit", session=a)[2])["events"]
        events_b = json.loads(self.request("/api/audit", session=b)[2])["events"]
        self.assertTrue(any(event["actor"] == "admin" and event["action"] == "user.credentials" for event in events_a))
        self.assertFalse(any(event["action"] == "user.credentials" for event in events_b))
        audit = self.app.audit.path.read_text(encoding="utf-8")
        self.assertNotIn("private-course-token", audit)
        self.assertNotIn("test-password-2026", audit)
        self.assertEqual(self.request("/api/login", {"username": "admin", "password": "secret-wrong-password"})[0], 401)
        for unused in range(50):
            audit = self.app.audit.path.read_text(encoding="utf-8")
            if "用户名或密码不正确" in audit:
                break
            time.sleep(.01)
        self.assertIn("用户名或密码不正确", audit)
        self.assertNotIn("secret-wrong-password", audit)

    def test_limits_and_health_are_isolated_and_permissions_are_enforced(self):
        a, b = self.sessions
        target = self.users[0]
        limits = {"id": target["id"], "quota_bytes": 1000000, "rate_bps": 1000000}
        self.assertEqual(self.request("/api/traffic/limits", limits, a)[0], 403)
        self.assertEqual(self.request("/api/traffic/limits", limits, self.admin)[0], 200)
        own = json.loads(self.request("/api/traffic?user_id=admin", session=a)[2])
        other = json.loads(self.request("/api/traffic", session=b)[2])
        self.assertEqual(own["quota_bytes"], 1000000)
        self.assertEqual(other["quota_bytes"], 0)
        self.assertNotIn("users", own)
        self.assertEqual(len(json.loads(self.request("/api/traffic", session=self.admin)[2])["users"]), 3)
        users = json.loads(self.request("/api/users", session=self.admin)[2])["users"]
        self.assertEqual(next(item for item in users if item["id"] == target["id"])["traffic"]["rate_bps"], 1000000)
        self.assertTrue(all("connections" in item["traffic"] for item in users))
        self.assertEqual(self.app.telemetry.controls.calls[-1], (set(), {target["port"]: 1000000}))
        self.assertEqual(self.request("/api/health/settings", {"mode": "auto", "fallback_exit_id": "server"}, a)[0], 400)
        settings = {"mode": "manual", "interval_seconds": 60, "threshold": 2, "fallback_exit_id": None}
        self.assertEqual(self.request("/api/health/settings", settings, a)[0], 200)
        self.assertEqual(json.loads(self.request("/api/state", session=b)[2])["health"]["interval_seconds"], 300)
        with mock.patch.object(self.app.health, "_probe_server", side_effect=RuntimeError("Secret proxy password")):
            self.assertEqual(self.request("/api/health/check", {}, a)[0], 200)
            for unused in range(100):
                health = self.app.health.snapshot(target["id"])
                if not health["checking"]:
                    break
                time.sleep(.01)
            self.assertEqual(health["status"], "failed")
            self.assertNotIn("Secret", json.dumps(health))
        self.assertEqual(self.app.accounts.manager(target["id"]).state["active_id"], "server")

    def test_encrypted_backup_roundtrip_http_restore_clears_all_sessions(self):
        a, b = self.sessions
        for path, data in (("/api/backups", None), ("/api/backups/create", {}),
                           ("/api/backups/restore", {"confirmation": "RESTORE"}),
                           ("/api/backups/download?token=invalid", None)):
            self.assertEqual(self.request(path, data, a)[0], 403)
        status, _, payload = self.request("/api/backups/create", {"name": "Integration checkpoint"}, self.admin)
        self.assertEqual(status, 200)
        backup_id = json.loads(payload)["id"]
        password = "fixture-portable-password-2026"
        status, _, payload = self.request("/api/backups/export", {"id": backup_id, "password": password}, self.admin)
        self.assertEqual(status, 200)
        token = json.loads(payload)["download_token"]
        status, headers, archive = self.request("/api/backups/download?token=" + token, session=self.admin)
        self.assertEqual(status, 200)
        self.assertIn(".nvbackup", headers["Content-Disposition"])
        self.assertNotIn(b"test-password", archive)
        manager = self.app.accounts.manager(self.users[0]["id"])
        original_domains = list(manager.state["direct_domains"])
        self.request("/api/routing", {"mode": "smart", "domains": [], "direct_domains": ["new.example.cn"]}, a)
        status, _, payload = self.request("/api/backups/preview", {"data": base64.b64encode(archive).decode(), "password": password}, self.admin)
        self.assertEqual(status, 200)
        preview = json.loads(payload)
        previous_health = self.app.health
        self.assertEqual(self.request("/api/backups/restore", {"preview_token": preview["preview_token"], "confirmation": "wrong"}, self.admin)[0], 400)
        status, _, payload = self.request("/api/backups/restore", {"preview_token": preview["preview_token"], "confirmation": "RESTORE"}, self.admin)
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(payload)["restored"])
        self.assertTrue(previous_health.closed)
        self.assertFalse(previous_health.check_async(self.users[0]["id"])["accepted"])
        self.assertEqual(self.app.accounts.manager(self.users[0]["id"]).state["direct_domains"], original_domains)
        for session in (self.admin, a, b):
            self.assertEqual(self.request("/api/state", session=session)[0], 401)
        self.login("member-a", "member-a-test-password-2026")

    def test_automatic_failover_requires_saved_explicit_backup_and_failure_threshold(self):
        user, session = self.users[0], self.sessions[0]
        manager = self.app.accounts.manager(user["id"])
        status, _, payload = self.request("/api/exits/save", {
            "name": "Explicit backup", "address": "backup.example.com", "port": 1080,
            "auth": "none", "username": "", "password": "", "expected_ip": ""}, session)
        self.assertEqual(status, 200)
        exit_id = json.loads(payload)["id"]
        with mock.patch.object(self.app.health, "_probe_server", side_effect=RuntimeError("Disconnected")), \
                mock.patch.object(manager, "start_job", return_value={"job_id": "synthetic"}) as start:
            for unused in range(3):
                self.app.health.check(user["id"])
            start.assert_not_called()
            self.assertEqual(self.request("/api/health/settings", {
                "mode": "auto", "fallback_exit_id": "foreign-exit", "threshold": 2}, session)[0], 400)
            self.assertEqual(self.request("/api/health/settings", {
                "mode": "auto", "fallback_exit_id": exit_id, "threshold": 5,
                "interval_seconds": 300}, session)[0], 200)
            self.app.health.check(user["id"])
            start.assert_not_called()
            self.app.health.check(user["id"])
            start.assert_called_once_with("apply", exit_id)
        self.assertEqual(manager.state["active_id"], "server")


if __name__ == "__main__":
    unittest.main()
