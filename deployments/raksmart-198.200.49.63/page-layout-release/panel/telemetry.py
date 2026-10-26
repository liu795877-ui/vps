"""Real Xray counters and isolated per-entrance quotas / bandwidth controls.

Only proxy traffic reaches these counters. DIRECT traffic on a client cannot be
measured by this server. Limits default to zero. Linux controls are restricted
to the console's three entrance ports and to chains/qdiscs owned by this module.
"""

import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import threading
import time


PORTS = (443, 1443, 2443)
IDENTITY = re.compile(r"admin|[a-f0-9]{16}\Z")
CHAIN_IN = "VPS_PANEL_QUOTA_IN"
CHAIN_OUT = "VPS_PANEL_QUOTA_OUT"


def _server():
    from panel import server
    return server


def _json_output(output):
    begin, end = output.find("{"), output.rfind("}")
    if begin < 0 or end < begin:
        raise ValueError("Xray did not return statistics JSON")
    return json.loads(output[begin:end + 1])


def augment_config(config, proxy_port=None):
    """Return an independent copy, retaining every identity and routing email."""
    result = copy.deepcopy(config)
    if len(result.get("inbounds", [])) != 1:
        raise ValueError("Expected one independent proxy entrance")
    inbound = result["inbounds"][0]
    port = inbound.get("port") if proxy_port is None else proxy_port
    if type(port) is not int or not 1 <= port <= 50535 or inbound.get("port") != port:
        raise ValueError("Unsupported statistics entrance")
    previous = result.get("api")
    if previous and previous.get("tag") != "panel-stats-api":
        raise ValueError("An independently managed Xray API already exists")
    result["api"] = {"tag": "panel-stats-api", "listen": "127.0.0.1:" + str(15000 + port),
                     "services": ["StatsService"]}
    result["stats"] = {}
    levels = result.setdefault("policy", {}).setdefault("levels", {})
    clients = inbound.get("settings", {}).get("clients", [])
    for index, client in enumerate(clients):
        if not client.get("email"):
            client["email"] = ("panel-primary@stats.invalid" if index == 0 else
                               "panel-client-" + str(index) + "@stats.invalid")
        level = levels.setdefault(str(client.get("level", 0)), {})
        level.update(statsUserUplink=True, statsUserDownlink=True, statsUserOnline=True)
    return result


def validate_augmentation(config, allow_legacy=True):
    """Reject public or independently extended API access in managed configs."""
    api = config.get("api")
    if api is None and allow_legacy:
        return True
    inbounds = config.get("inbounds", [])
    port = inbounds[0].get("port") if len(inbounds) == 1 else None
    if (type(port) is not int or not 1 <= port <= 50535 or api != {"tag": "panel-stats-api",
            "listen": "127.0.0.1:" + str(15000 + port), "services": ["StatsService"]}):
        raise ValueError("Managed statistics API must be private and read only")
    return True


def validate_store(data):
    if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("users"), dict):
        raise ValueError("Invalid traffic store")
    if len(data["users"]) > 100:
        raise ValueError("Too many traffic entries")
    for identity, item in data["users"].items():
        if not IDENTITY.fullmatch(identity) or not isinstance(item, dict):
            raise ValueError("Invalid traffic identity")
        for key, maximum in (("quota_bytes", 10 ** 16), ("rate_bps", 10 ** 10)):
            if type(item.get(key)) is not int or not 0 <= item[key] <= maximum:
                raise ValueError("Invalid traffic limits")
        if item["rate_bps"] and item["rate_bps"] < 100000:
            raise ValueError("Invalid bandwidth limit")
        if (not isinstance(item.get("months"), dict) or len(item["months"]) > 36
                or not isinstance(item.get("counters"), dict) or len(item["counters"]) > 64):
            raise ValueError("Invalid counters")
        for month, counts in item["months"].items():
            if not re.fullmatch(r"\d{4}-(0[1-9]|1[0-2])", month) or not isinstance(counts, dict):
                raise ValueError("Invalid month")
            if any(type(counts.get(key)) is not int or not 0 <= counts[key] < 10 ** 20
                   for key in ("up_bytes", "down_bytes")):
                raise ValueError("Invalid monthly totals")
        for name, value in item["counters"].items():
            if (not isinstance(name, str) or len(name) > 500 or type(value) is not int
                    or not 0 <= value < 10 ** 20):
                raise ValueError("Invalid counter value")
        if item.get("sample_time") is not None and (type(item["sample_time"]) not in (int, float)
                or not 0 <= item["sample_time"] < 10 ** 11):
            raise ValueError("Invalid sample timestamp")
    return True


class LinuxControls:
    """Own only named quota chains and the 7a00 / ffff qdiscs we install."""
    def __init__(self, directory, runner=None):
        self.path = Path(directory) / "traffic-controls.private.json"
        self.runner = runner or self._run
        self.lock = threading.RLock()
        self.state = json.loads(self.path.read_text(encoding="utf-8")) if self.path.exists() else {}

    @staticmethod
    def _run(args, check=True):
        result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=12)
        if check and result.returncode:
            raise _server().PanelError("流量限制执行失败，请检查服务器网络权限。", 500)
        return result

    def _text(self, args):
        result = self.runner(args)
        return result.stdout.decode("utf-8", "replace")

    def _interface(self):
        match = re.search(r"\bdev ([A-Za-z0-9_.:-]+)", self._text(["ip", "route", "show", "default"]))
        if not match:
            raise _server().PanelError("未找到服务器出口网卡。", 500)
        return match.group(1)

    def quota(self, blocked):
        for chain, parent, direction in ((CHAIN_IN, "INPUT", "--dport"),
                                          (CHAIN_OUT, "OUTPUT", "--sport")):
            self.runner(["iptables", "-w", "-N", chain], check=False)
            exists = self.runner(["iptables", "-w", "-C", parent, "-j", chain], check=False)
            if exists.returncode:
                self.runner(["iptables", "-w", "-I", parent, "1", "-j", chain])
            self.runner(["iptables", "-w", "-F", chain])
            self.runner(["iptables", "-w", "-A", chain, "-i" if parent == "INPUT" else "-o",
                         "lo", "-j", "RETURN"])
            if parent == "OUTPUT":
                # INPUT rejects emit a reset from the entrance port. Permit
                # those termination packets so OUTPUT cannot reject the reset
                # and leave existing clients waiting for a TCP timeout.
                self.runner(["iptables", "-w", "-A", chain, "-p", "tcp",
                             "--tcp-flags", "RST", "RST", "-j", "RETURN"])
            for port in sorted(blocked):
                if port not in PORTS:
                    raise ValueError("Quota may only block a managed proxy entrance")
                self.runner(["iptables", "-w", "-A", chain, "-p", "tcp", direction,
                             str(port), "-j", "REJECT", "--reject-with", "tcp-reset"])

    def rates(self, rates):
        rates = {int(port): int(rate) for port, rate in rates.items() if rate}
        if any(port not in PORTS or rate < 100000 or rate > 10000000000
               for port, rate in rates.items()):
            raise ValueError("Invalid managed port rate")
        if not rates and not self.state.get("owned"):
            return
        interface = self.state.get("interface") or self._interface()
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", interface):
            raise ValueError("Invalid network interface")
        qdiscs = self._text(["tc", "qdisc", "show", "dev", interface])
        root = next((line for line in qdiscs.splitlines() if " root " in line), "")
        ingress = next((line for line in qdiscs.splitlines() if line.startswith("qdisc ingress ")), "")
        if self.state.get("owned"):
            if root and not (root.startswith("qdisc htb 7a00:") or
                             root.startswith("qdisc pfifo_fast ") or root.startswith("qdisc noqueue ")):
                raise _server().PanelError("服务器带宽设置被外部修改，已停止覆盖。", 409)
            if ingress and not ingress.startswith("qdisc ingress ffff:"):
                raise _server().PanelError("服务器入站带宽设置被外部修改，已停止覆盖。", 409)
        elif root and not (root.startswith("qdisc pfifo_fast ") or root.startswith("qdisc noqueue ")):
            raise _server().PanelError("服务器已有自定义带宽设置，请先协调现有策略。", 409)
        elif ingress:
            raise _server().PanelError("服务器已有入站带宽设置，请先协调现有策略。", 409)
        if not rates:
            if root.startswith("qdisc htb 7a00:"):
                self.runner(["tc", "qdisc", "del", "dev", interface, "root"])
            if ingress.startswith("qdisc ingress ffff:"):
                self.runner(["tc", "qdisc", "del", "dev", interface, "ingress"])
            self.state = {"quota_owned": self.state.get("quota_owned", False)}
            _server().atomic_write(self.path, _server().json_bytes(self.state))
            return
        # Record ownership before making the first change, so a partial failure
        # can be reconciled and removed without touching an unrelated qdisc.
        self.state.update(owned=True, interface=interface)
        _server().atomic_write(self.path, _server().json_bytes(self.state))
        self.runner(["tc", "qdisc", "replace", "dev", interface, "root", "handle", "7a00:",
                     "htb", "default", "1"])
        self.runner(["tc", "class", "replace", "dev", interface, "parent", "7a00:",
                     "classid", "7a00:1", "htb", "rate", "10000mbit", "ceil", "10000mbit"])
        self.runner(["tc", "filter", "del", "dev", interface, "parent", "7a00:"], check=False)
        if ingress:
            self.runner(["tc", "qdisc", "del", "dev", interface, "ingress"])
        self.runner(["tc", "qdisc", "add", "dev", interface, "handle", "ffff:", "ingress"])
        for index, (port, rate) in enumerate(sorted(rates.items()), 10):
            class_id = "7a00:" + str(index)
            self.runner(["tc", "class", "replace", "dev", interface, "parent", "7a00:",
                         "classid", class_id, "htb", "rate", str(rate) + "bit",
                         "ceil", str(rate) + "bit"])
            self.runner(["tc", "filter", "add", "dev", interface, "parent", "7a00:",
                         "protocol", "ip", "prio", str(index), "u32", "match", "ip", "protocol", "6", "0xff",
                         "match", "ip", "sport",
                         str(port), "0xffff", "flowid", class_id])
            burst = max(16000, min(2000000, rate // 8 // 10))
            self.runner(["tc", "filter", "add", "dev", interface, "parent", "ffff:",
                         "protocol", "ip", "prio", str(index), "u32", "match", "ip", "protocol", "6", "0xff",
                         "match", "ip", "dport",
                         str(port), "0xffff", "police", "rate", str(rate) + "bit", "burst",
                         str(burst), "drop", "flowid", ":1"])

    def apply(self, blocked, rates):
        with self.lock:
            # Default unlimited deployment has no netfilter or tc mutations.
            if blocked or self.state.get("quota_owned"):
                # Mark ownership before mutations, including a partial chain
                # update that fails and must subsequently be rolled back.
                self.state["quota_owned"] = True
                _server().atomic_write(self.path, _server().json_bytes(self.state))
                self.quota(blocked)
                self.state["quota_owned"] = bool(blocked)
                _server().atomic_write(self.path, _server().json_bytes(self.state))
            self.rates(rates)


class Telemetry:
    def __init__(self, accounts, controls=None, runner=None, clock=None):
        self.accounts = accounts
        self.path = accounts.owner_manager.directory / "traffic.private.json"
        self.lock = threading.RLock()
        self.runner = runner or LinuxControls._run
        self.clock = clock or time.time
        self.controls = controls or LinuxControls(accounts.owner_manager.directory)
        self.data = json.loads(self.path.read_text(encoding="utf-8")) if self.path.exists() else {
            "version": 1, "users": {}}
        try:
            validate_store(self.data)
        except ValueError as error:
            raise _server().PanelError("流量记录需要检查。", 500) from error
        self.live = {}
        self.enforcement_error = None
        self.last_enforced = None

    def _record(self, user_id):
        if not isinstance(user_id, str) or not IDENTITY.fullmatch(user_id):
            raise _server().PanelError("没有找到这个用户。", 404)
        return self.accounts._record(user_id)

    def _entry(self, user_id):
        return self.data["users"].setdefault(user_id, {
            "quota_bytes": 0, "rate_bps": 0, "months": {}, "counters": {}, "sample_time": None})

    def _month(self):
        return datetime.fromtimestamp(self.clock(), timezone.utc).strftime("%Y-%m")

    def _save(self):
        _server().atomic_write(self.path, _server().json_bytes(self.data))

    def _query(self, record):
        port = record["port"]
        service = "xray.service" if record["id"] == "admin" else "xray-panel@" + record["id"] + ".service"
        epoch_result = self.runner(["systemctl", "show", service, "--property=MainPID",
                                   "--property=ExecMainStartTimestampMonotonic"])
        epoch = epoch_result.stdout.decode("utf-8", "replace").strip()
        result = self.runner([str(_server().base.XRAY), "api", "statsquery",
                              "--server=127.0.0.1:" + str(15000 + port), "-timeout", "3",
                              "-pattern", "user>>>"])
        data = _json_output(result.stdout.decode("utf-8", "replace"))
        counters = {}
        for stat in data.get("stat", []):
            name = stat.get("name", "")
            if re.fullmatch(r"user>>>[^\r\n]+>>>traffic>>>(uplink|downlink)", name):
                value = int(stat.get("value", 0))
                if value < 0:
                    raise ValueError("Negative Xray counter")
                counters[name] = value
        # A newly configured, unused instance legitimately returns no counters.
        result = self.runner(["ss", "-Hnt", "state", "established", "( sport = :" + str(port) + " )"])
        connections = len([line for line in result.stdout.decode("utf-8", "replace").splitlines()
                           if line.strip()])
        return counters, connections, epoch

    def tick(self):
        with self.accounts.lock, self.lock:
            records = [self.accounts._record("admin")] + list(self.accounts.records)
            sampled = self.clock()
            for record in records:
                user_id = record["id"]
                entry = self._entry(user_id)
                month = entry["months"].setdefault(self._month(), {"up_bytes": 0, "down_bytes": 0})
                if not record["enabled"]:
                    self.live[user_id] = {"available": False, "reason": "账号已停用", "connections": 0,
                                          "up_rate": 0, "down_rate": 0}
                    continue
                try:
                    counters, connections, epoch = self._query(record)
                    restarted = entry.get("epoch") is not None and entry["epoch"] != epoch
                    deltas = {"up_bytes": 0, "down_bytes": 0}
                    for name, current in counters.items():
                        previous = entry["counters"].get(name)
                        delta = current if restarted or previous is None or current < previous else current - previous
                        key = "up_bytes" if name.endswith(">>>uplink") else "down_bytes"
                        deltas[key] += delta
                        month[key] += delta
                    elapsed = sampled - entry["sample_time"] if entry.get("sample_time") else 0
                    self.live[user_id] = {"available": True, "reason": None, "connections": connections,
                        "up_rate": int(deltas["up_bytes"] / elapsed) if elapsed > 0 else 0,
                        "down_rate": int(deltas["down_bytes"] / elapsed) if elapsed > 0 else 0,
                        "sampled_at": datetime.fromtimestamp(sampled, timezone.utc).isoformat()}
                    entry["counters"] = counters
                    entry["epoch"] = epoch
                    entry["sample_time"] = sampled
                    entry["months"] = dict(sorted(entry["months"].items())[-12:])
                except Exception:
                    self.live[user_id] = {"available": False, "reason": "无法读取节点实时统计",
                                          "up_rate": None, "down_rate": None, "connections": None}
            self._save()
            self.apply_enforcement()

    def _plan(self):
        blocked, rates = set(), {}
        for record in [self.accounts._record("admin")] + list(self.accounts.records):
            entry = self._entry(record["id"])
            month = entry["months"].get(self._month(), {})
            total = month.get("up_bytes", 0) + month.get("down_bytes", 0)
            if entry["quota_bytes"] and total >= entry["quota_bytes"]:
                blocked.add(record["port"])
            if entry["rate_bps"]:
                rates[record["port"]] = entry["rate_bps"]
        return blocked, rates

    def apply_enforcement(self, force=False):
        with self.accounts.lock, self.lock:
            blocked, rates = self._plan()
            plan = (tuple(sorted(blocked)), tuple(sorted(rates.items())))
            if not force and plan == self.last_enforced:
                return
            try:
                self.controls.apply(blocked, rates)
                self.last_enforced = plan
                self.enforcement_error = None
            except Exception:
                self.enforcement_error = "限额或限速未能执行，请联系管理员检查服务器网络权限"
                raise

    def set_limits(self, user_id, quota_bytes, rate_bps):
        for name, value, upper in (("月额度", quota_bytes, 10 ** 16), ("带宽", rate_bps, 10 ** 10)):
            if type(value) is not int or value < 0 or value > upper:
                raise _server().PanelError(name + "需要有效的非负整数，0 表示不限。")
        if rate_bps and rate_bps < 100000:
            raise _server().PanelError("带宽至少需要 0.1 Mbps，0 表示不限。")
        with self.accounts.lock, self.lock:
            self._record(user_id)
            previous = copy.deepcopy(self.data)
            entry = self._entry(user_id)
            entry.update(quota_bytes=quota_bytes, rate_bps=rate_bps)
            try:
                self.apply_enforcement(force=True)
                self._save()
            except Exception as error:
                self.data = previous
                try:
                    self.apply_enforcement(force=True)
                except Exception:
                    raise _server().PanelError("流量设置失败，旧限制的恢复需要管理员检查。", 500) from error
                if isinstance(error, _server().PanelError):
                    raise
                raise _server().PanelError("流量设置失败，已保留原限制。", 500) from error
            return self.snapshot(user_id)

    def snapshot(self, user_id):
        with self.accounts.lock, self.lock:
            record = self._record(user_id)
            entry = self._entry(user_id)
            month = entry["months"].get(self._month(), {"up_bytes": 0, "down_bytes": 0})
            result = dict(self.live.get(user_id, {"available": False, "reason": "正在等待首次流量采样",
                                                 "up_rate": None, "down_rate": None, "connections": None}))
            total = month["up_bytes"] + month["down_bytes"]
            over = bool(entry["quota_bytes"] and total >= entry["quota_bytes"])
            result.update(month=self._month(), up_bytes=month["up_bytes"], down_bytes=month["down_bytes"],
                          total_bytes=total, quota_bytes=entry["quota_bytes"], rate_bps=entry["rate_bps"],
                          over_quota=over, quota_enforced=bool(over and not self.enforcement_error
                              and self.last_enforced is not None and record["port"] in self.last_enforced[0]),
                          rate_enforced=bool(entry["rate_bps"] and not self.enforcement_error
                              and self.last_enforced is not None and (record["port"], entry["rate_bps"])
                              in self.last_enforced[1]),
                          enforcement_error=self.enforcement_error, period_timezone="UTC",
                          notice=("本月额度已用完，代理入口暂停" if over else
                              "本月流量已使用 80%" if entry["quota_bytes"] and total >= entry["quota_bytes"] * .8
                              else None),
                          scope="仅统计经过本服务器的代理流量；本机 DIRECT 流量不计入",
                          sampling_seconds=10)
            return result

    def snapshots(self):
        with self.accounts.lock:
            return [dict(self.snapshot(record["id"]), id=record["id"], username=record["username"],
                         display_name=record["display_name"], enabled=record["enabled"])
                    for record in [self.accounts._record("admin")] + self.accounts.records]

    def forget_user(self, user_id):
        with self.accounts.lock, self.lock:
            self.data["users"].pop(user_id, None)
            self.live.pop(user_id, None)
            self._save()
            self.apply_enforcement(force=True)

    def reload(self):
        with self.lock:
            candidate = json.loads(self.path.read_text(encoding="utf-8")) if self.path.exists() else {
                "version": 1, "users": {}}
            validate_store(candidate)
            self.data = candidate
            self.live.clear()
            self.last_enforced = None
