"""Account-scoped monitoring with explicitly chosen, disabled-by-default failover."""

import copy
import ipaddress
import json
from pathlib import Path
import threading
import time
from datetime import datetime, timezone


def timestamp():
    return datetime.now(timezone.utc).isoformat()


class HealthMonitor:
    def __init__(self, accounts, audit=None, operation_lock=None):
        self.accounts = accounts
        self.audit = audit
        self.operation_lock = operation_lock or threading.RLock()
        self.closed = False
        self.path = accounts.owner_manager.directory / "health.private.json"
        self.lock = threading.RLock()
        self.pending = set()
        if self.path.is_symlink():
            raise RuntimeError("Health storage must not be a symbolic link")
        self.records = json.loads(self.path.read_text(encoding="utf-8")) if self.path.is_file() else {}

    def snapshot(self, user_id):
        with self.lock:
            result = copy.deepcopy(self.records.get(user_id, {}))
        defaults = {"status": "unknown", "last_checked_at": None, "last_success_at": None,
                    "last_failure_at": None, "consecutive_failures": 0,
                    "message": "尚未完成后台检测", "mode": "manual", "fallback_exit_id": None,
                    "interval_seconds": 300, "threshold": 3, "observed_ip": None,
                    "checking": user_id in self.pending}
        defaults.update(result)
        defaults.pop("next_check", None)
        return defaults

    def _save(self):
        from panel.server import atomic_write, json_bytes
        atomic_write(self.path, json_bytes(self.records))

    def settings(self, user_id, request):
        from panel.server import PanelError
        mode = request.get("mode", "manual")
        interval = request.get("interval_seconds", 300)
        threshold = request.get("threshold", 3)
        if mode not in ("manual", "auto") or type(interval) is not int or not 60 <= interval <= 3600 or type(threshold) is not int or not 2 <= threshold <= 10:
            raise PanelError("检测间隔需为 60–3600 秒，连续失败阈值为 2–10 次。")
        target = request.get("fallback_exit_id") or None
        manager = self.accounts.manager(user_id)
        with manager.lock:
            available = {item["id"] for item in manager.state["exits"]} | {"server"}
            active = manager.state.get("active_id") or "server"
        if mode == "auto" and (target not in available or target == active):
            raise PanelError("请指定与当前出口不同的备用出口；切换会改变出网 IP。")
        with self.lock:
            record = self.records.setdefault(user_id, {})
            record.update(mode=mode, fallback_exit_id=target, interval_seconds=interval, threshold=threshold)
            self._save()
        return self.snapshot(user_id)

    def check_async(self, user_id):
        with self.lock:
            if self.closed or user_id in self.pending:
                return {"accepted": False, "health": self.snapshot(user_id)}
            self.pending.add(user_id)

        def run():
            try:
                self.check(user_id)
            finally:
                with self.lock:
                    self.pending.discard(user_id)
        threading.Thread(target=run, daemon=True).start()
        return {"accepted": True, "health": self.snapshot(user_id)}

    def close(self):
        with self.lock:
            self.closed = True

    @staticmethod
    def _probe_server(manager):
        import shutil
        import subprocess
        if manager.demo:
            return manager.public_ip
        curl = shutil.which("curl")
        if not curl:
            raise RuntimeError("Probe dependency missing")
        for endpoint in ("https://api.ipify.org", "https://icanhazip.com"):
            result = subprocess.run([curl, "--disable", "--noproxy", "*", "--fail", "--silent", "--connect-timeout", "5", "--max-time", "10", endpoint], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=12)
            if result.returncode == 0:
                try:
                    address = ipaddress.ip_address(result.stdout.strip())
                    if address.is_global:
                        return str(address)
                except ValueError:
                    pass
        raise RuntimeError("Server external connectivity failed")

    def check(self, user_id):
        from panel.server import PanelError
        manager = self.accounts.manager(user_id)
        if not manager.operation.acquire(blocking=False):
            return self.snapshot(user_id)
        active = None
        try:
            with manager.lock:
                active = manager.state.get("active_id") or "server"
                state_hash = manager.state["managed_hash"]
                item = copy.deepcopy(next((item for item in manager.state["applied_exits"] if item["id"] == active), None))
            checked = timestamp()
            try:
                observed = self._probe_server(manager) if active == "server" else manager.probe(item) if item else None
                if not observed:
                    raise PanelError("当前出口资料不可用。")
                with self.lock:
                    record = self.records.setdefault(user_id, {})
                    record.update(status="healthy", last_checked_at=checked, last_success_at=checked,
                                  consecutive_failures=0, message="出口连接正常", observed_ip=observed,
                                  checked_exit_id=active, next_check=time.time() + record.get("interval_seconds", 300))
                    self._save()
            except Exception as error:
                message = str(error) if isinstance(error, PanelError) else "出口连接失败，请检查代理资料、白名单或服务商状态。"
                with self.lock:
                    record = self.records.setdefault(user_id, {})
                    failures = record.get("consecutive_failures", 0) + 1 if record.get("checked_exit_id") == active else 1
                    record.update(status="failed", last_checked_at=checked, last_failure_at=checked,
                                  consecutive_failures=failures, message=message, checked_exit_id=active,
                                  next_check=time.time() + record.get("interval_seconds", 300))
                    self._save()
            setting = self.snapshot(user_id)
        finally:
            manager.operation.release()
        if setting["status"] == "failed" and setting["mode"] == "auto" and setting["consecutive_failures"] >= setting["threshold"]:
            target = setting["fallback_exit_id"]
            # Restore replaces cached member managers and monitor settings.
            # Serialize the final queue operation with restore, then use the
            # current manager so a finished old probe cannot overwrite rules.
            with self.operation_lock, self.accounts.lock:
                if self.closed:
                    return self.snapshot(user_id)
                try:
                    manager = self.accounts.manager(user_id)
                    with manager.lock:
                        unchanged = manager.state["managed_hash"] == state_hash and (manager.state.get("active_id") or "server") == active
                        exists = target == "server" or any(item["id"] == target for item in manager.state["exits"])
                    if unchanged and exists and target != active:
                        manager.start_job("apply", target)
                        with self.lock:
                            self.records[user_id].update(message="连续失败，正在检测并应用你指定的备用出口。", next_check=time.time() + 60)
                            self._save()
                        if self.audit:
                            self.audit.record(self.accounts.get(user_id), "health.failover", "started", "连续失败后应用用户指定的备用出口", user_id)
                except PanelError:
                    pass
        return self.snapshot(user_id)

    def tick(self):
        users = self.accounts.list_users()
        for user in users:
            if not user.get("proxy_enabled", user["enabled"]):
                continue
            with self.lock:
                due = self.records.get(user["id"], {}).get("next_check", 0) <= time.time()
            if due:
                self.check_async(user["id"])
