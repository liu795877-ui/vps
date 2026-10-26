"""Administrator-only member connection metadata from existing Xray journals.

No proxy configuration is changed. Journal cursors are deduplicated in SQLite;
only normalized destinations and account metadata are retained, never messages,
client addresses, credentials, URL paths, or administrator connections.
"""

from contextlib import contextmanager
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import threading
import time


RETENTION_DAYS = 7
MAX_ROWS = 100000
BATCH_LINES = 2000
MEMBER_ID = re.compile(r"[a-f0-9]{16}\Z")
ACCESS = re.compile(
    r"\bfrom (\S+) accepted (tcp|udp):(\S+) "
    r"\[([A-Za-z0-9_-]+) -> ([A-Za-z0-9_-]+)\](?:\s+email: \S+)?\s*$")


def destination(value):
    """Accept only a hostname or literal IP followed by a valid destination port."""
    if not isinstance(value, str) or len(value) > 320:
        return None
    host, separator, port = value.rpartition(":")
    if not separator or not port.isdigit() or not 1 <= int(port) <= 65535:
        return None
    host = host.strip("[]").rstrip(".").lower()
    if not host or any(char in host for char in "/\\@?#%\x00"):
        return None
    try:
        host = str(ipaddress.ip_address(host))
        kind = "ip"
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return None
        if len(host) > 253 or any(not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in host.split(".")):
            return None
        kind = "domain"
    return host, int(port), kind


def parse_entry(entry, members, now):
    """Use the exact member service as identity; message emails are untrusted."""
    record = members.get(entry.get("_SYSTEMD_UNIT"))
    if not record or record.get("id") == "admin" or record.get("role") != "member":
        return None
    message, cursor = entry.get("MESSAGE"), entry.get("__CURSOR")
    if not isinstance(message, str) or len(message) > 4096:
        return None
    if not isinstance(cursor, str) or not 1 <= len(cursor) <= 2048:
        return None
    match = ACCESS.search(message)
    if not match:
        return None
    source, network, address, inbound, outbound = match.groups()
    if source == "DNS" or inbound not in ("panel-hy2-socks", "reality-in", "in"):
        return None
    target = destination(address)
    if target is None:
        return None
    try:
        at_us = int(entry["__REALTIME_TIMESTAMP"])
    except (KeyError, ValueError, TypeError):
        return None
    if not (now - RETENTION_DAYS * 86400) * 1000000 <= at_us <= (now + 60) * 1000000:
        return None
    host, port, kind = target
    return (cursor, at_us, record["id"], record["username"], record["display_name"],
            host, kind, port, network, "hy2" if inbound == "panel-hy2-socks" else "reality",
            "server" if outbound == "direct" else "static" if outbound.startswith("static-") else "other")


def read_journal(members, cursor, since):
    args = ["journalctl", "--no-pager", "--no-tail", "--output=json", "--utc"]
    for unit in sorted(members):
        args += ["--unit", unit]
    if cursor:
        args += ["--after-cursor", cursor]
    else:
        # CentOS 7 systemd does not accept a trailing UTC timezone name.
        args += ["--since", datetime.fromtimestamp(since, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")]
    environment = dict(os.environ, TZ="UTC")
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               env=environment)
    timer = threading.Timer(4, process.kill)
    timer.daemon = True
    timer.start()
    entries, size, limited = [], 0, False
    try:
        for unused in range(BATCH_LINES):
            line = process.stdout.readline(16385)
            if not line:
                break
            size += len(line)
            if len(line) > 16384 or size > 4 * 1024 * 1024:
                limited = True
                break
            try:
                entry = json.loads(line.decode("utf-8"))
            except (UnicodeError, ValueError):
                continue
            if isinstance(entry, dict):
                entries.append(entry)
        else:
            limited = True
        if limited and process.poll() is None:
            process.terminate()
        code = process.wait(timeout=2)
        if code and not limited:
            raise OSError("Member journal read failed")
        return entries, limited
    finally:
        timer.cancel()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=2)
        process.stdout.close()


class AccessRecords:
    def __init__(self, accounts, reader=None, clock=None):
        self.accounts = accounts
        self.path = Path(accounts.owner_manager.directory) / "member-access.private.sqlite3"
        self.reader = reader or read_journal
        self.clock = clock or time.time
        self.lock = threading.RLock()
        self.error = None
        self.scanned_at = None
        self.backlog = False
        with self._db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS connections (
                    id INTEGER PRIMARY KEY, source_cursor TEXT NOT NULL UNIQUE,
                    at_us INTEGER NOT NULL, member_id TEXT NOT NULL, username TEXT NOT NULL,
                    display_name TEXT NOT NULL, host TEXT NOT NULL, host_kind TEXT NOT NULL,
                    port INTEGER NOT NULL, network TEXT NOT NULL, protocol TEXT NOT NULL,
                    exit_kind TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS access_time ON connections(at_us DESC, id DESC);
                CREATE INDEX IF NOT EXISTS access_member_time ON connections(member_id, at_us DESC);
            """)

    @contextmanager
    def _db(self):
        if any(path.is_symlink() for path in [self.path] + list(self.path.parents)):
            raise OSError("Linked access record storage rejected")
        if not self.path.exists():
            descriptor = os.open(str(self.path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
        if os.name == "posix":
            os.chmod(str(self.path), 0o600)
        db = sqlite3.connect(str(self.path), timeout=3)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def _members(self):
        with self.accounts.lock:
            return {"xray-panel@" + record["id"] + ".service": {
                key: record[key] for key in ("id", "username", "display_name", "role")}
                for record in self.accounts.records if record.get("role") == "member"
                and MEMBER_ID.fullmatch(record.get("id", ""))}

    @staticmethod
    def _meta(db, key, default=""):
        row = db.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
        return row[0] if row else default

    @staticmethod
    def _set_meta(db, key, value):
        db.execute("INSERT OR REPLACE INTO metadata(key,value) VALUES(?,?)", (key, str(value)))

    def _prune(self, db, now):
        db.execute("DELETE FROM connections WHERE at_us < ?", (int((now - RETENTION_DAYS * 86400) * 1000000),))
        threshold = db.execute("SELECT id FROM connections ORDER BY at_us DESC,id DESC LIMIT 1 OFFSET ?",
                               (MAX_ROWS,)).fetchone()
        if threshold:
            db.execute("DELETE FROM connections WHERE id IN (SELECT id FROM connections "
                       "ORDER BY at_us DESC,id DESC LIMIT -1 OFFSET ?)", (MAX_ROWS,))
            self._set_meta(db, "capacity_limited", 1)

    def tick(self):
        members, now = self._members(), self.clock()
        with self.lock, self._db() as db:
            self._prune(db, now)
            cursor = self._meta(db, "cursor")
            since = max(now - RETENTION_DAYS * 86400,
                        float(self._meta(db, "source_time", str((now - RETENTION_DAYS * 86400) * 1000000))) / 1000000 - 2)
            try:
                if self.accounts.demo or not members:
                    entries, limited = [], False
                else:
                    try:
                        entries, limited = self.reader(members, cursor, since)
                    except OSError:
                        if not cursor:
                            raise
                        # Journals may have rotated or the server may have rebooted.
                        entries, limited = self.reader(members, "", since)
                last_time = 0
                for entry in entries:
                    value = parse_entry(entry, members, now)
                    if value:
                        db.execute("INSERT OR IGNORE INTO connections(source_cursor,at_us,member_id,username,"
                                   "display_name,host,host_kind,port,network,protocol,exit_kind) "
                                   "VALUES(?,?,?,?,?,?,?,?,?,?,?)", value)
                    # Never advance past a different service or an invalid cursor.
                    if ((entry.get("_SYSTEMD_UNIT") or entry.get("UNIT")) in members and isinstance(entry.get("__CURSOR"), str)
                            and 0 < len(entry["__CURSOR"]) <= 2048):
                        self._set_meta(db, "cursor", entry["__CURSOR"])
                        try:
                            last_time = max(last_time, int(entry["__REALTIME_TIMESTAMP"]))
                        except (KeyError, ValueError, TypeError):
                            pass
                if last_time:
                    self._set_meta(db, "source_time", last_time)
                self._prune(db, now)
                self._set_meta(db, "scanned_at", now)
                self.backlog, self.error, self.scanned_at = limited, None, now
            except (OSError, sqlite3.Error, ValueError, subprocess.SubprocessError):
                self.error = "读取成员连接日志暂未完成，将自动重试。"

    def query(self, query):
        from panel.server import PanelError
        allowed = {"hours", "member", "q", "protocol", "page"}
        if set(query) - allowed or any(len(values) != 1 for values in query.values()):
            raise PanelError("访问记录筛选条件无效。")
        def field(name, default=""):
            return query.get(name, [default])[0]
        try:
            hours, page = int(field("hours", "24")), int(field("page", "1"))
        except (TypeError, ValueError):
            raise PanelError("访问记录时间或页码无效。")
        if hours not in (1, 24, 168) or not 1 <= page <= 4000:
            raise PanelError("请选择最近 1 小时、24 小时或 7 天。")
        member, protocol, term = field("member"), field("protocol"), field("q").strip().lower()
        if member and not MEMBER_ID.fullmatch(member):
            raise PanelError("请选择成员账号；管理员访问不在记录范围。")
        if protocol not in ("", "hy2", "reality") or len(term) > 253 or any(
                char not in "abcdefghijklmnopqrstuvwxyz0123456789.-:[]" for char in term):
            raise PanelError("请使用域名或 IP 搜索访问记录。")
        now = self.clock()
        conditions, values = ["at_us >= ?", "at_us <= ?", "member_id <> 'admin'"], [
            int((now - hours * 3600) * 1000000), int(now * 1000000)]
        for column, value in (("member_id", member), ("protocol", protocol)):
            if value:
                conditions.append(column + " = ?")
                values.append(value)
        if term:
            conditions.append("instr(host, ?) > 0")
            values.append(term)
        where = " AND ".join(conditions)
        members = list(self._members().values())
        with self.lock, self._db() as db:
            summary = dict(db.execute("SELECT count(*) AS connections,count(DISTINCT member_id) AS members,"
                                      "count(DISTINCT host) AS destinations FROM connections WHERE " + where,
                                      values).fetchone())
            pages = max(1, (summary["connections"] + 49) // 50)
            page = min(page, pages)
            rows = [dict(row) for row in db.execute(
                "SELECT id,at_us,member_id,username,display_name,host,host_kind,port,network,protocol,exit_kind "
                "FROM connections WHERE " + where + " ORDER BY at_us DESC,id DESC LIMIT 50 OFFSET ?",
                values + [(page - 1) * 50])]
            top = [dict(row) for row in db.execute(
                "SELECT host,host_kind,count(*) AS connections,count(DISTINCT member_id) AS members,max(at_us) AS last_us "
                "FROM connections WHERE " + where + " GROUP BY host,host_kind ORDER BY connections DESC,host LIMIT 12", values)]
            existing = {item["id"] for item in members}
            for row in db.execute("SELECT member_id,username,display_name FROM connections GROUP BY member_id"):
                if row["member_id"] not in existing and MEMBER_ID.fullmatch(row["member_id"]):
                    members.append({"id": row["member_id"], "username": row["username"],
                                    "display_name": row["display_name"], "deleted": True})
            status = {"last_scan": float(self._meta(db, "scanned_at", "0")) or None,
                      "error": self.error, "catching_up": self.backlog,
                      "capacity_limited": self._meta(db, "capacity_limited") == "1",
                      "retention_days": RETENTION_DAYS, "max_records": MAX_ROWS}
        for row in rows:
            row["at"] = row.pop("at_us") / 1000000
        for row in top:
            row["last_at"] = row.pop("last_us") / 1000000
        return {"records": rows, "top_destinations": top, "summary": summary,
                "members": sorted(members, key=lambda item: item["username"]), "page": page,
                "pages": pages, "status": status}
