"""Persistent, scoped activity records containing no submitted secrets."""

import json
import os
from pathlib import Path
import secrets
import threading
from datetime import datetime, timezone


class AuditLog:
    def __init__(self, directory, maximum=4000):
        self.path = Path(directory) / "activity.private.jsonl"
        self.lock = threading.RLock()
        self.maximum = maximum
        if self.path.is_symlink():
            raise RuntimeError("Activity storage must not be a symbolic link")

    def record(self, actor, action, status="success", summary="", target_id=None):
        # Callers supply fixed summaries, never raw form bodies, URLs or exceptions.
        entry = {"id": secrets.token_hex(12),
                 "at": datetime.now(timezone.utc).isoformat(),
                 "actor_id": str(actor.get("id", "visitor")),
                 "actor": str(actor.get("username", "访客"))[:24],
                 "action": str(action)[:80], "status": str(status)[:20],
                 "summary": str(summary)[:240]}
        if target_id is not None:
            entry["target_id"] = str(target_id)[:32]
        with self.lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(descriptor, "a", encoding="utf-8") as stream:
                stream.write(json.dumps(entry, ensure_ascii=False) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            if self.path.stat().st_size > 1500000:
                lines = self.path.read_text(encoding="utf-8").splitlines()[-self.maximum:]
                from panel.server import atomic_write
                atomic_write(self.path, ("\n".join(lines) + "\n").encode("utf-8"))
        return entry

    def query(self, user, limit=50):
        limit = min(200, max(1, int(limit)))
        with self.lock:
            lines = self.path.read_text(encoding="utf-8").splitlines() if self.path.exists() else []
        events = []
        for line in reversed(lines):
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if user.get("role") != "admin" and entry.get("actor_id") != user["id"] and entry.get("target_id") != user["id"]:
                continue
            events.append({key: entry[key] for key in ("id", "at", "actor", "action", "status", "summary")})
            if len(events) >= limit:
                break
        return {"events": events, "scope": "all" if user.get("role") == "admin" else "own"}
