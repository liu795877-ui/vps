"""Exercise account boundaries through the real HTTP handlers."""

import http.client
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest import mock

from panel import server


class MultiuserHttpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="panel-users-http-")
        self.addCleanup(self.temp.cleanup)
        directory = Path(self.temp.name)
        self.owner = server.Manager(directory, "8.8.8.8", directory / "config.json", demo=True)
        self.httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        self.port = self.httpd.server_address[1]
        self.origin = "http://127.0.0.1:" + str(self.port)
        self.app = server.Application(self.owner, self.origin, "/", True)
        self.httpd.application = self.app
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)
        self.admin = self.login("admin", "demo-password-2026")
        self.users = []
        self.sessions = []
        for username in ("user-a", "user-b"):
            status, _, body = self.request("/api/users/create", {
                "username": username, "password": username + "-test-password-2026",
                "display_name": username,
            }, self.admin)
            self.assertEqual(status, 200)
            self.users.append(json.loads(body)["user"])
            self.sessions.append(self.login(username, username + "-test-password-2026"))

    def request(self, path, data=None, session=None):
        headers = {"Origin": self.origin}
        if session:
            headers.update(Cookie=session["cookie"], **{"X-CSRF-Token": session["csrf"]})
        if data is not None:
            headers["Content-Type"] = "application/json"
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.request("POST" if data is not None else "GET", path,
                               json.dumps(data) if data is not None else None, headers)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def login(self, username, password):
        status, headers, body = self.request("/api/login", {"username": username, "password": password})
        self.assertEqual(status, 200)
        return dict(json.loads(body), cookie=headers["Set-Cookie"].split(";", 1)[0])

    def test_state_profile_and_management_permissions_are_scoped_to_login(self):
        accounts = json.loads(self.request("/api/users", session=self.admin)[2])["users"]
        self.assertEqual(len(accounts), 3)
        self.assertEqual([user["port"] for user in self.users], [1443, 2443])
        profiles = []
        for user, session in zip(self.users, self.sessions):
            state = json.loads(self.request("/api/state?user_id=admin", session=session)[2])
            self.assertEqual(state["user"]["id"], user["id"])
            self.assertEqual(state["exits"], [])
            profile = self.request("/api/profile?user_id=admin", session=session)
            self.assertEqual(profile[0], 200)
            self.assertIn(("port: " + str(user["port"])).encode(), profile[2])
            profiles.append(profile[2])
            self.assertEqual(self.request("/api/users", session=session)[0], 403)
            for path, data in (("create", {"username": "intruder", "password": "test-password-2026"}),
                               ("reset-password", {"id": "admin", "password": "test-password-2026"}),
                               ("set-enabled", {"id": "admin", "enabled": False})):
                self.assertEqual(self.request("/api/users/" + path, data, session)[0], 403)
        self.assertNotEqual(profiles[0], profiles[1])
        public = json.dumps(accounts)
        for user in self.users:
            manager = self.app.accounts.manager(user["id"])
            for key in ("auto_id", "rule_token", "public"):
                self.assertNotIn(manager.state[key], public)

    def test_foreign_exit_and_job_ids_cannot_be_used_and_switch_preserves_other_users(self):
        a, b = self.sessions
        original_owner = self.owner.state_path.read_bytes(), self.owner.config_path.read_bytes()
        other = self.app.accounts.manager(self.users[1]["id"])
        original_other = other.state_path.read_bytes(), other.config_path.read_bytes()
        status, _, body = self.request("/api/exits/save", {
            "name": "Only A", "address": "proxy.example.com", "port": 1080,
            "auth": "none", "username": "", "password": "", "expected_ip": "",
        }, a)
        self.assertEqual(status, 200)
        exit_id = json.loads(body)["id"]
        self.assertEqual(self.request("/api/exits/delete", {"id": exit_id}, b)[0], 404)
        self.assertEqual(self.request("/api/exits/save", {
            "id": exit_id, "name": "Stolen", "address": "proxy.example.com", "port": 1080,
            "auth": "none", "username": "", "password": "", "expected_ip": "",
        }, b)[0], 404)
        status, _, body = self.request("/api/apply", {"id": exit_id}, a)
        self.assertEqual(status, 202)
        job_id = json.loads(body)["job_id"]
        for _ in range(100):
            result = json.loads(self.request("/api/jobs/" + job_id, session=a)[2])
            if result["status"] != "running":
                break
            time.sleep(.03)
        self.assertEqual(result["status"], "success")
        self.assertEqual(self.request("/api/jobs/" + job_id, session=b)[0], 404)
        self.assertEqual(original_owner, (self.owner.state_path.read_bytes(), self.owner.config_path.read_bytes()))
        self.assertEqual(original_other, (other.state_path.read_bytes(), other.config_path.read_bytes()))

    def test_password_reset_and_self_change_invalidate_only_target_sessions(self):
        a, b = self.sessions
        a2 = self.login("user-a", "user-a-test-password-2026")
        status = self.request("/api/password", {
            "current": "user-a-test-password-2026", "new": "new-a-test-password-2026",
        }, a)[0]
        self.assertEqual(status, 200)
        for session in (a, a2):
            self.assertEqual(self.request("/api/state", session=session)[0], 401)
        for session in (b, self.admin):
            self.assertEqual(self.request("/api/state", session=session)[0], 200)
        a = self.login("user-a", "new-a-test-password-2026")
        self.assertEqual(self.request("/api/users/reset-password", {
            "id": self.users[1]["id"], "password": "new-b-test-password-2026",
        }, self.admin)[0], 200)
        self.assertEqual(self.request("/api/state", session=b)[0], 401)
        self.assertEqual(self.request("/api/state", session=a)[0], 200)
        self.assertEqual(self.request("/api/state", session=self.admin)[0], 200)
        self.login("user-b", "new-b-test-password-2026")

    def test_disable_blocks_sessions_profiles_and_rules_and_enable_keeps_identity(self):
        a, b = self.sessions
        manager = self.app.accounts.manager(self.users[0]["id"])
        profile = manager.state["profile"]
        path = "/rules/custom/" + manager.state["rule_token"] + "/direct.yaml"
        self.assertEqual(self.request("/api/routing", {
            "mode": "smart", "domains": [], "direct_domains": ["a.example.cn"],
        }, a)[0], 200)
        self.assertIn(b"a.example.cn", self.request(path)[2])
        self.assertEqual(self.request("/api/users/set-enabled", {
            "id": self.users[0]["id"], "enabled": False,
        }, self.admin)[0], 200)
        self.assertEqual(self.request("/api/profile", session=a)[0], 401)
        self.assertEqual(self.request(path)[0], 404)
        self.assertEqual(self.request("/api/login", {
            "username": "user-a", "password": "user-a-test-password-2026",
        })[0], 401)
        self.assertEqual(self.request("/api/state", session=b)[0], 200)
        self.assertEqual(self.request("/api/users/set-enabled", {
            "id": self.users[0]["id"], "enabled": True,
        }, self.admin)[0], 200)
        self.login("user-a", "user-a-test-password-2026")
        self.assertEqual(manager.state["profile"], profile)
        self.assertIn(b"a.example.cn", self.request(path)[2])

    def test_password_reset_revokes_a_login_already_authenticating(self):
        authenticated = threading.Event()
        release_login = threading.Event()
        reset_started = threading.Event()
        reset_done = threading.Event()
        outcome = {}
        original = self.app.accounts.authenticate

        def held_authenticate(username, password):
            user = original(username, password)
            authenticated.set()
            if not release_login.wait(3):
                raise RuntimeError("Timed out coordinating authentication")
            return user

        def login():
            outcome["login"] = self.app.login("user-a", "user-a-test-password-2026", "test-race")

        def reset():
            reset_started.set()
            self.app.accounts.reset_password(self.users[0]["id"], "reset-a-password-2026")
            self.app.invalidate_user(self.users[0]["id"])
            reset_done.set()

        with mock.patch.object(self.app.accounts, "authenticate", side_effect=held_authenticate):
            login_thread = threading.Thread(target=login)
            reset_thread = threading.Thread(target=reset)
            login_thread.start()
            try:
                self.assertTrue(authenticated.wait(3))
                reset_thread.start()
                self.assertTrue(reset_started.wait(3))
                self.assertFalse(reset_done.wait(.15))
            finally:
                release_login.set()
                login_thread.join(3)
                if reset_thread.ident is not None:
                    reset_thread.join(3)
        self.assertTrue(reset_done.is_set())
        self.assertIsNone(self.app.session(outcome["login"][0]))
        self.assertEqual(self.request("/api/state", session=self.sessions[1])[0], 200)


if __name__ == "__main__":
    unittest.main()
