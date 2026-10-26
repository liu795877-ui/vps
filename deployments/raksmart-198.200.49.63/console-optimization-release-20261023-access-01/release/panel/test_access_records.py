"""Security, collection continuity, filtering and retention of member metadata."""

import copy
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest import mock

from panel import access_records as access
from panel.server import PanelError
from panel import test_enhancements_http as http_fixture


NOW = 1800000000
A, B = "0123456789abcdef", "fedcba9876543210"


def record(identity=A, username="alice"):
    return {"id": identity, "role": "member", "username": username, "display_name": username}


def entry(cursor="first", identity=A, target="Example.COM.:443", protocol="hy2", at=NOW):
    tag = "panel-hy2-socks" if protocol == "hy2" else "reality-in"
    return {"__CURSOR": cursor, "__REALTIME_TIMESTAMP": str(int(at * 1000000)),
            "_SYSTEMD_UNIT": "xray-panel@" + identity + ".service",
            "MESSAGE": "2026/10/23 10:00:00 from tcp:203.0.113.88:12345 accepted tcp:" + target +
                       " [" + tag + " -> direct] email: private-identity@exits.invalid"}


class AccessRecordTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="member-access-tests-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.accounts = SimpleNamespace(owner_manager=SimpleNamespace(directory=self.root),
            records=[record(), record(B, "bob")], lock=threading.RLock(), demo=False)
        self.reader = mock.Mock(return_value=([entry()], False))
        self.logs = access.AccessRecords(self.accounts, self.reader, lambda: NOW)

    def test_only_normalized_member_destinations_are_persisted(self):
        self.logs.tick()
        result = self.logs.query({})
        self.assertEqual(result["summary"], {"connections": 1, "members": 1, "destinations": 1})
        row = result["records"][0]
        self.assertEqual((row["host"], row["port"], row["protocol"], row["exit_kind"]),
                         ("example.com", 443, "hy2", "server"))
        with self.logs._db() as db:
            schema = [r[1] for r in db.execute("PRAGMA table_info(connections)")]
        self.assertNotIn("message", schema)
        self.assertNotIn("source_ip", schema)
        content = self.logs.path.read_bytes()
        for secret in (b"203.0.113.88", b"private-identity", b"accepted tcp"):
            self.assertNotIn(secret, content)

    def test_admin_dns_unknown_units_and_private_url_text_are_not_records(self):
        admin = entry("admin");admin["_SYSTEMD_UNIT"] = "xray.service"
        self.reader.return_value = ([admin, entry("badurl", target="example.com/private?token=secret:443"),
            dict(entry("dns"), MESSAGE="from DNS accepted https://1.1.1.1/dns-query [local]"),
            dict(entry("outside"), _SYSTEMD_UNIT="unrelated.service")], False)
        self.logs.tick()
        self.assertEqual(self.logs.query({})["summary"]["connections"], 0)
        self.assertNotIn(b"secret", self.logs.path.read_bytes())
        for unit in self.reader.call_args[0][0]:
            self.assertTrue(unit.startswith("xray-panel@"))

    def test_replay_and_restart_do_not_duplicate_connections(self):
        self.logs.tick();self.logs.tick()
        other = access.AccessRecords(self.accounts, self.reader, lambda: NOW)
        other.tick()
        self.assertEqual(other.query({})["summary"]["connections"], 1)
        self.assertEqual(self.reader.call_args[0][1], "first")

    def test_rotated_cursor_falls_back_to_time_with_deduplication(self):
        self.logs.tick()
        self.reader.side_effect = [OSError("rotated"), ([entry(), entry("second")], False)]
        self.logs.tick()
        self.assertEqual(self.reader.call_args[0][1], "")
        self.assertEqual(self.logs.query({})["summary"]["connections"], 2)

    def test_systemd_status_messages_advance_cursor_without_becoming_visits(self):
        status = {"UNIT": "xray-panel@" + A + ".service", "__CURSOR": "status-cursor",
                  "__REALTIME_TIMESTAMP": str(NOW * 1000000), "MESSAGE": "Stopped service"}
        self.reader.return_value = ([status], False)
        self.logs.tick();self.logs.tick()
        self.assertEqual(self.reader.call_args[0][1], "status-cursor")
        self.assertFalse(self.logs.query({})["records"])

    def test_filters_and_pagination_share_the_same_summary(self):
        rows = [entry("a-" + str(i), at=NOW-i, protocol="reality") for i in range(56)]
        rows += [entry("bob", B, "other.example:8443", at=NOW-7200)]
        self.reader.return_value = (rows, False);self.logs.tick()
        filters = {"member": [A], "q": ["example.com"], "protocol": ["reality"], "page": ["2"]}
        value = self.logs.query(filters)
        self.assertEqual((len(value["records"]), value["summary"]["connections"], value["pages"]), (6, 56, 2))
        self.assertEqual(self.logs.query({"hours": ["1"]})["summary"]["members"], 1)
        self.assertEqual(self.logs.query({})["summary"]["members"], 2)
        self.assertEqual(value["top_destinations"][0]["connections"], 56)
        self.assertEqual(self.logs.query({"page": ["4000"]})["page"], 2)

    def test_retention_and_capacity_keep_newer_records(self):
        self.reader.return_value = ([entry("old", at=NOW-8*86400)] +
                                   [entry(str(i), at=NOW-i) for i in range(5)], False)
        with mock.patch.object(access, "MAX_ROWS", 3):
            self.logs.tick()
        result = self.logs.query({"hours": ["168"]})
        self.assertEqual(result["summary"]["connections"], 3)
        self.assertTrue(result["status"]["capacity_limited"])
        self.logs.clock = lambda: NOW + 8*86400
        self.reader.return_value = ([], False);self.logs.tick()
        with self.logs._db() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM connections").fetchone()[0], 0)

    def test_ip_literals_are_kept_as_ips_without_website_inference(self):
        self.reader.return_value = ([entry("v4", target="1.1.1.1:443"),
                                    entry("v6", target="[2606:4700:4700::1111]:443")], False)
        self.logs.tick()
        self.assertTrue(all(r["host_kind"] == "ip" for r in self.logs.query({})["records"]))

    def test_invalid_search_and_admin_filter_are_rejected(self):
        for query in ({"member": ["admin"]}, {"q": ["%'"]}, {"page": ["0"]},
                      {"hours": ["999"]}, {"protocol": ["other"]}, {"member": [A, B]}, {"sql": ["SELECT"]}):
            with self.assertRaises(PanelError):
                self.logs.query(query)

    def test_journal_failure_is_visible_and_does_not_reset_existing_records(self):
        self.logs.tick();self.reader.side_effect = OSError("private raw journal diagnostic")
        self.logs.tick()
        result = self.logs.query({})
        self.assertEqual(result["summary"]["connections"], 1)
        self.assertTrue(result["status"]["error"])
        self.assertNotIn("private raw", json.dumps(result))

    def test_journal_since_uses_explicit_utc_environment_for_old_systemd(self):
        process = mock.Mock()
        process.stdout = io.BytesIO((json.dumps(entry()) + "\n").encode("utf-8"))
        process.poll.return_value = 0
        process.wait.return_value = 0
        with mock.patch.object(access.subprocess, "Popen", return_value=process) as spawn:
            entries, limited = access.read_journal(self.logs._members(), "", NOW)
        args, options = spawn.call_args
        self.assertEqual(options["env"]["TZ"], "UTC")
        self.assertEqual(args[0][args[0].index("--since") + 1], "2027-01-15 08:00:00")
        self.assertEqual(entries[0]["__CURSOR"], "first")
        self.assertFalse(limited)

    def test_deleted_member_history_remains_identifiable_and_owner_is_excluded(self):
        self.logs.tick();self.accounts.records = []
        result = self.logs.query({})
        self.assertEqual(result["members"][0]["id"], A)
        self.assertTrue(result["members"][0]["deleted"])


class AccessRecordHttpTests(http_fixture.EnhancementHttpTests):
    # Inherit the existing authenticated fixture, without rerunning unrelated cases.
    def test_access_records_require_admin_session_and_never_include_owner(self):
        rows = [entry("member", self.users[0]["id"], at=self.app.access_records.clock())]
        self.app.access_records.reader = mock.Mock(return_value=(rows, False))
        self.app.accounts.demo = False
        try:
            self.app.access_records.tick()
        finally:
            self.app.accounts.demo = True
        status, headers, payload = self.request("/api/access-records", session=self.admin)
        self.assertEqual(status, 200)
        data = json.loads(payload)
        self.assertEqual(data["summary"]["connections"], 1)
        self.assertNotIn("admin", [row["username"] for row in data["records"]])
        self.assertEqual(self.request("/api/access-records")[0], 401)
        for session in self.sessions:
            self.assertEqual(self.request("/api/access-records", session=session)[0], 403)
        self.assertEqual(self.request("/api/access-records?member=admin", session=self.admin)[0], 400)
        self.assertEqual(self.request("/api/access-records?hours=24&hours=168", session=self.admin)[0], 400)
        self.assertEqual(self.request("/api/access-records?member=" + self.users[1]["id"], session=self.admin)[0], 200)


# Only the new HTTP case belongs to this module; the base module runs its cases.
for _name in list(vars(http_fixture.EnhancementHttpTests)):
    if _name.startswith("test_") and _name not in vars(AccessRecordHttpTests):
        setattr(AccessRecordHttpTests, _name, None)


if __name__ == "__main__":
    unittest.main()
