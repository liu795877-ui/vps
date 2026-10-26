"""Exercise member preparation through real HTTP and isolated account storage."""

import copy
import http.client
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest import mock

from panel import server, provisioning


class PreparationHttpTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="panel-preparation-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.owner = server.Manager(self.directory, "8.8.8.8", self.directory / "config.json", demo=True)
        self.httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        self.port = self.httpd.server_address[1]
        self.origin = "http://127.0.0.1:" + str(self.port)
        self.app = server.Application(self.owner, self.origin, "/", True)
        self.httpd.application = self.app
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)
        self.addCleanup(self.app.member_preparation.wait)
        self.admin = self.login("admin", "demo-password-2026")
        self.initial_owner = self.owner.state_path.read_bytes(), self.owner.config_path.read_bytes(), self.app.auth_path.read_bytes()

    def request(self, path, data=None, session=None):
        headers = {"Origin": self.origin}
        if session:
            headers.update({"Cookie": session["cookie"], "X-CSRF-Token": session["csrf"]})
        if data is not None:
            headers["Content-Type"] = "application/json"
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            connection.request("POST" if data is not None else "GET", path,
                               json.dumps(data) if data is not None else None, headers)
            response = connection.getresponse()
            body = response.read()
            return response.status, dict(response.getheaders()), json.loads(body)
        finally:
            connection.close()

    def login(self, username, password):
        status, headers, body = self.request("/api/login", {"username": username, "password": password})
        self.assertEqual(status, 200)
        return dict(body, cookie=headers["Set-Cookie"].split(";", 1)[0])

    def payload(self):
        return {"username": "member_a", "display_name": "成员 A", "password": "synthetic-member-password-2026",
                "request_id": "synthetic-request-key-20261012"}

    def finish(self, task):
        self.app.member_preparation.wait(5)
        status, _, body = self.request("/api/users/provision?id=" + task["id"], session=self.admin)
        self.assertEqual(status, 200)
        return body["task"]

    def test_preparation_is_idempotent_and_never_persists_passwords(self):
        payload = self.payload()
        status, _, body = self.request("/api/users/provision", payload, self.admin)
        self.assertEqual(status, 202)
        task = self.finish(body["task"])
        self.assertEqual(task["status"], "succeeded")
        self.assertEqual(task["public_verification"], "not_checked")
        self.assertTrue(all(step["status"] == "complete" for step in task["steps"]))
        status, _, repeated = self.request("/api/users/provision", payload, self.admin)
        self.assertEqual(status, 202)
        self.assertEqual(repeated["task"]["id"], task["id"])
        self.assertEqual(len(self.app.accounts.records), 1)
        stored = self.app.member_preparation.path.read_text(encoding="utf-8")
        self.assertNotIn(payload["password"], stored)
        self.assertNotIn('"password"', stored)
        self.assertNotIn("request_id", json.dumps(task))
        self.assertNotIn("actor", json.dumps(task))
        self.assertEqual(self.initial_owner, (self.owner.state_path.read_bytes(), self.owner.config_path.read_bytes(), self.app.auth_path.read_bytes()))
        reloaded = provisioning.MemberPreparation(self.app)
        self.assertEqual(reloaded.get(task["id"])["status"], "succeeded")
        self.assertEqual(reloaded.submit(payload, self.admin["user"])["id"], task["id"])

    def test_progress_is_observable_during_real_work_and_failure_is_sanitized(self):
        started, release = threading.Event(), threading.Event()

        def failed(request, progress=None):
            # Real preparation holds this lock through configuration and
            # service startup. Polling must still return the current stage.
            with self.app.accounts.lock:
                progress("configuration", "正在校验成员配置。")
                started.set()
                if not release.wait(5):
                    raise RuntimeError("synthetic timeout")
                raise RuntimeError("synthetic-secret-from-core-error")

        with mock.patch.object(self.app.accounts, "create_user", side_effect=failed):
            status, _, body = self.request("/api/users/provision", self.payload(), self.admin)
            self.assertEqual(status, 202)
            try:
                self.assertTrue(started.wait(3))
                status, _, progress = self.request("/api/users/provision?id=" + body["task"]["id"], session=self.admin)
                self.assertEqual(status, 200)
                self.assertEqual(progress["task"]["stage"], "configuration")
                self.assertEqual(progress["task"]["status"], "running")
            finally:
                release.set()
            task = self.finish(body["task"])
        self.assertEqual(task["status"], "failed")
        self.assertNotIn("synthetic-secret", json.dumps(task))
        self.assertEqual(self.app.accounts.records, [])

    def test_real_creation_reports_progress_while_account_lock_is_held(self):
        started, release = threading.Event(), threading.Event()
        original_start = self.app.accounts._start

        def held_start(record):
            started.set()
            if not release.wait(5):
                raise RuntimeError("synthetic startup timeout")
            return original_start(record)

        with mock.patch.object(self.app.accounts, "_start", side_effect=held_start):
            status, _, body = self.request("/api/users/provision", self.payload(), self.admin)
            self.assertEqual(status, 202)
            try:
                self.assertTrue(started.wait(3))
                status, _, progress = self.request("/api/users/provision", session=self.admin)
                self.assertEqual(status, 200)
                self.assertEqual(progress["tasks"][0]["stage"], "services")
                self.assertEqual(progress["tasks"][0]["status"], "running")
            finally:
                release.set()
            task = self.finish(body["task"])
        self.assertEqual(task["status"], "succeeded")
        self.assertEqual(len(self.app.accounts.records), 1)

    def test_task_read_still_rejects_expired_and_revoked_admin_sessions(self):
        token = self.admin["cookie"].split("=", 1)[1]
        with self.app.lock:
            self.app.sessions[token]["expires"] = time.time() - 1
        self.assertEqual(self.request("/api/users/provision", session=self.admin)[0], 401)
        self.admin = self.login("admin", "demo-password-2026")
        self.app.invalidate_user("admin")
        self.assertEqual(self.request("/api/users/provision", session=self.admin)[0], 401)

    def test_members_cannot_read_tasks_or_configure_entrances_and_csrf_is_required(self):
        member = self.app.accounts.create_user({"username": "member_b", "password": "member-b-password-2026"})
        session = self.login("member_b", "member-b-password-2026")
        for path in ("/api/entrances", "/api/users/provision", "/api/users/provision?id=unknown"):
            self.assertEqual(self.request(path, session=session)[0], 403)
            self.assertEqual(self.request(path)[0], 401)
        self.assertEqual(self.request("/api/users/provision", self.payload(), session)[0], 403)
        self.assertEqual(self.request("/api/entrances/configure", {"member_ports": [1443, 2443, 3444], "cloud_confirmed": True}, session)[0], 403)
        invalid = dict(self.admin, csrf="invalid")
        self.assertEqual(self.request("/api/users/provision", self.payload(), invalid)[0], 403)
        self.assertEqual(self.request("/api/entrances/configure", {"member_ports": [1443, 2443, 3444], "cloud_confirmed": False}, self.admin)[0], 409)
        self.assertEqual(self.app.accounts.get(member["id"])["port"], 1443)

    def test_capacity_expansion_and_async_third_member_preserve_existing_accounts(self):
        for username in ("member_b", "member_c"):
            self.app.accounts.create_user({"username": username, "password": username + "-password-2026"})
        original = copy.deepcopy(self.app.accounts.records)
        self.assertEqual(self.request("/api/users/provision", self.payload(), self.admin)[0], 409)
        status, _, summary = self.request("/api/entrances/configure", {"member_ports": [1443, 2443, 3444], "cloud_confirmed": True}, self.admin)
        self.assertEqual(status, 200)
        self.assertEqual(summary["entrances"]["capacity"], 4)
        status, _, body = self.request("/api/users/provision", self.payload(), self.admin)
        self.assertEqual(status, 202)
        task = self.finish(body["task"])
        self.assertEqual(task["status"], "succeeded")
        self.assertEqual(task["user"]["port"], 3444)
        self.assertEqual(self.app.accounts.records[:2], original)
        status, _, body = self.request("/api/users", session=self.admin)
        self.assertEqual(status, 200)
        self.assertEqual(body["entrances"]["available_count"], 0)

    def test_restart_marks_unfinished_tasks_for_review_without_replaying_credentials(self):
        item = {"id": "f" * 32, "request_id": "synthetic-interrupted-request", "username": "member_x",
                "display_name": "成员 X", "status": "running", "stage": "services", "message": "正在启动",
                "created_at": server.now(), "password": "must-never-be-replayed"}
        server.atomic_write(self.app.member_preparation.path, server.json_bytes({"version": 1, "tasks": [item]}))
        recovered = provisioning.MemberPreparation(self.app)
        task = recovered.get(item["id"])
        self.assertEqual(task["status"], "failed")
        self.assertIn("重启", task["error"])
        self.assertFalse(recovered.has_active())
        self.assertEqual(self.app.accounts.records, [])
        self.assertNotIn("password", recovered.path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
