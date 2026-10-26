"""Official per-account HY2 entrances, routed through private Xray SOCKS.

The optional private registry enables integration only on an adopted host.
Public credentials, statistics secrets and loopback credentials are independent.
No client-side DIRECT traffic reaches this service or its counters.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import time
from urllib.request import Request, ProxyHandler, build_opener

from panel import ports as entrances

PORTS = entrances.SUPPORTED_PUBLIC_PORTS
IDENTITY = re.compile(r"admin|[a-f0-9]{16}\Z")
TOKEN = re.compile(r"[A-Za-z0-9_-]{43,128}\Z")
RUNTIME = Path("/usr/local/etc/raksmart-hy2/accounts")
BINARY = "/usr/local/bin/raksmart-hysteria2"


def _server():
    from panel import server
    return server


def validate_registry(data):
    if (not isinstance(data, dict) or set(data) != {"version", "enabled", "certificate_sha256", "sni", "accounts"}
            or data.get("version") != 1 or type(data.get("enabled")) is not bool
            or not re.fullmatch(r"[a-f0-9]{64}", data.get("certificate_sha256", ""))
            or data.get("sni") != "raksmart-hy2.local" or not isinstance(data.get("accounts"), dict)
            or len(data["accounts"]) > len(PORTS)):
        raise ValueError("Invalid HY2 registry")
    ports = set()
    for identity, item in data["accounts"].items():
        if (not isinstance(identity, str) or not IDENTITY.fullmatch(identity)
                or not isinstance(item, dict) or set(item) != {"port", "password", "api_secret", "socks_password"}
                or type(item.get("port")) is not int or item["port"] not in PORTS or item["port"] in ports
                or any(not isinstance(item.get(key), str) or not TOKEN.fullmatch(item[key])
                       for key in ("password", "api_secret", "socks_password"))):
            raise ValueError("Invalid HY2 account")
        ports.add(item["port"])
    entrances.validate_topology(sorted(ports))
    return True


def _entry(port):
    return {"port": port, "password": secrets.token_urlsafe(32),
            "api_secret": secrets.token_urlsafe(32), "socks_password": secrets.token_urlsafe(32)}


class Integration:
    def __init__(self, accounts, runner=None, api=None):
        self.accounts = accounts
        self.path = accounts.owner_manager.directory / "hy2.private.json"
        self.runner = runner or _server().base.command
        self.api = api or self._api
        self.runtime = accounts.owner_manager.directory / "hy2-runtime" if accounts.demo else RUNTIME
        self.data = None
        self.reload()
        if self.enabled and not accounts.demo:
            # Manager initialization tightens its data directory to 0700.
            # Restore certificate traversal for the dedicated HY2 service
            # before it accepts new handshakes after any panel restart.
            self.validate_tls()
        accounts.owner_manager.acceleration = self
        for manager in accounts._managers.values():
            manager.acceleration = self

    @property
    def enabled(self):
        return bool(self.data and self.data["enabled"])

    def reload(self):
        if self.path.exists():
            if self.path.is_symlink():
                raise _server().PanelError("加速入口文件需要检查。", 500)
            candidate = json.loads(self.path.read_text(encoding="utf-8"))
            validate_registry(candidate)
            self._validate_allocations(candidate)
            self.data = candidate
        else:
            self.data = None

    def _save(self):
        validate_registry(self.data)
        self._validate_allocations(self.data)
        _server().atomic_write(self.path, _server().json_bytes(self.data))

    def _validate_allocations(self, data):
        allowed = {self.accounts._owner_port()} | set(self.accounts.member_ports)
        if any(item["port"] not in allowed for item in data["accounts"].values()):
            raise ValueError("HY2 entrance is outside the configured account pool")

    def has_record(self, record):
        item = self.data["accounts"].get(record["id"]) if self.enabled else None
        return bool(item and item["port"] == record["port"])

    def by_port(self, port):
        if not self.enabled:
            return None
        items = [item for item in self.data["accounts"].values() if item["port"] == port]
        if len(items) != 1:
            raise _server().PanelError("这个账号的加速入口需要检查。", 500)
        return items[0]

    def prepare(self, record):
        if not self.enabled:
            return False
        if (not IDENTITY.fullmatch(record["id"]) or record["port"] not in PORTS
                or record["port"] not in (self.accounts._owner_port(),) + self.accounts.member_ports):
            raise ValueError("Invalid HY2 identity")
        existing = self.data["accounts"].get(record["id"])
        if existing:
            if existing["port"] != record["port"]:
                raise ValueError("HY2 entrance identity changed")
            return False
        if any(item["port"] == record["port"] for item in self.data["accounts"].values()):
            raise ValueError("HY2 port already assigned")
        if not self.accounts.demo:
            for kind, address, port in ((socket.SOCK_DGRAM, "0.0.0.0", record["port"]),
                    (socket.SOCK_STREAM, "127.0.0.1", entrances.private_port(record["port"], "hy2_socks")),
                    (socket.SOCK_STREAM, "127.0.0.1", entrances.private_port(record["port"], "hy2_stats"))):
                with socket.socket(socket.AF_INET, kind) as probe:
                    probe.bind((address, port))
        previous = copy.deepcopy(self.data)
        self.data["accounts"][record["id"]] = _entry(record["port"])
        try:
            self._save()
            self.write_config(record)
        except Exception:
            self.data = previous
            self._save()
            raise
        return True

    def compose(self, config, profile, port, public_ip):
        item = self.by_port(port)
        if item is None:
            return config, profile
        result = copy.deepcopy(config)
        # Historical configurations can already contain this managed bridge.
        from panel.telemetry import validate_augmentation
        validate_augmentation(result)
        result["inbounds"] = [result["inbounds"][0]]
        result["routing"]["rules"] = [rule for rule in result["routing"]["rules"]
            if rule.get("inboundTag") != ["panel-hy2-socks"]]
        result["inbounds"].append({"tag": "panel-hy2-socks", "listen": "127.0.0.1",
            "port": entrances.private_port(port, "hy2_socks"), "protocol": "socks", "settings": {
                "auth": "password", "accounts": [{"user": "panel-hy2", "pass": item["socks_password"]}], "udp": False}})
        auto = next(rule for rule in result["routing"]["rules"] if rule.get("user") == ["panel-auto@exits.invalid"]
                    and rule.get("network") == "tcp")
        # Retain the existing private-destination rejection ahead of routing.
        position = result["routing"]["rules"].index(auto)
        result["routing"]["rules"].insert(position, {"type": "field", "inboundTag": ["panel-hy2-socks"],
            "network": "tcp", "outboundTag": auto["outboundTag"]})
        from panel.accelerated_client import compose
        profile = compose(profile, public_ip, port, item["password"], self.data["certificate_sha256"], self.data["sni"])
        return result, profile

    def public_metadata(self, port):
        if not self.enabled:
            return {"enabled": False}
        self.by_port(port)
        return {"enabled": True, "protocols": ["hysteria2", "vless"], "hy2_port": port,
                "initial_update_required": True,
                "description": "首次刷新完整配置订阅或导入新配置一次；保持 AUTO，优先 HY2，TCP 兼容备用。实际协议以客户端连接记录为准。"}

    def validate_running(self, record, config):
        from panel.telemetry import validate_augmentation
        validate_augmentation(config, allow_legacy=False)
        item = self.by_port(record["port"])
        if (not self.has_record(record) or len(config["inbounds"]) != 2
                or config["inbounds"][1]["settings"]["accounts"][0]["pass"] != item["socks_password"]):
            raise ValueError("HY2 account configuration mismatch")

    def validate_tls(self):
        directory = self.accounts.owner_manager.directory
        certificate, key = directory / "hy2-server.crt.pem", directory / "hy2-server.key.pem"
        if any(path.is_symlink() or not path.is_file() for path in (certificate, key)):
            raise ValueError("HY2 certificate files are unavailable")
        der = ssl.PEM_cert_to_DER_cert(certificate.read_text(encoding="ascii"))
        if hashlib.sha256(der).hexdigest() != self.data["certificate_sha256"]:
            raise ValueError("HY2 certificate pin mismatch")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.load_cert_chain(str(certificate), str(key))
        if not self.accounts.demo:
            import grp
            group = grp.getgrnam("hy2").gr_gid
            os.chown(str(directory), 0, group)
            os.chmod(str(directory), 0o710)
            for path in (certificate, key):
                os.chown(str(path), 0, group)
                os.chmod(str(path), 0o640)

    @staticmethod
    def service(record):
        if record["port"] not in PORTS:
            raise ValueError("Unsupported HY2 service")
        return "raksmart-hy2@" + str(record["port"]) + ".service"

    def config(self, record):
        item = self.by_port(record["port"])
        return {"listen": "0.0.0.0:" + str(record["port"]),
            "tls": {"cert": str(self.accounts.owner_manager.directory / "hy2-server.crt.pem"),
                    "key": str(self.accounts.owner_manager.directory / "hy2-server.key.pem")},
            "auth": {"type": "password", "password": item["password"]},
            "congestion": {"type": "bbr", "bbrProfile": "standard"}, "ignoreClientBandwidth": True,
            "disableUDP": True,
            "outbounds": [{"name": "account-auto", "type": "socks5", "socks5": {
                "addr": "127.0.0.1:" + str(entrances.private_port(record["port"], "hy2_socks")), "username": "panel-hy2",
                "password": item["socks_password"]}}],
            "trafficStats": {"listen": "127.0.0.1:" + str(entrances.private_port(record["port"], "hy2_stats")), "secret": item["api_secret"]},
            "masquerade": {"type": "string", "string": {"content": "Not Found\n", "statusCode": 404,
                            "headers": {"Content-Type": "text/plain"}}}}

    def write_config(self, record):
        if not self.enabled:
            return
        if self.runtime.is_symlink():
            raise _server().PanelError("加速入口目录需要检查。", 500)
        path = self.runtime / (str(record["port"]) + ".yaml")
        if path.is_symlink():
            raise _server().PanelError("加速入口配置需要检查。", 500)
        _server().atomic_write(path, _server().json_bytes(self.config(record)))
        if not self.accounts.demo:
            import grp
            group = grp.getgrnam("hy2").gr_gid
            os.chown(str(self.runtime), 0, group)
            os.chmod(str(self.runtime), 0o750)
            os.chown(str(path), 0, group)
            os.chmod(str(path), 0o640)

    def _api(self, record, resource):
        if resource not in ("traffic", "online"):
            raise ValueError("Unsupported HY2 read-only API")
        item = self.by_port(record["port"])
        request = Request("http://127.0.0.1:" + str(entrances.private_port(record["port"], "hy2_stats")) + "/" + resource,
                          headers={"Authorization": item["api_secret"]})
        with build_opener(ProxyHandler({})).open(request, timeout=2) as response:
            return json.loads(response.read().decode("utf-8"))

    def query(self, record):
        if not self.has_record(record):
            raise ValueError("Unmanaged HY2 entrance")
        result = self.runner(["systemctl", "show", self.service(record), "--property=MainPID",
                              "--property=ExecMainStartTimestampMonotonic"])
        epoch = (result.stdout.decode("utf-8", "replace") if isinstance(result.stdout, bytes) else result.stdout).strip()
        data, online = self.api(record, "traffic"), self.api(record, "online")
        if not isinstance(data, dict) or set(data) - {"user"} or not isinstance(online, dict) or set(online) - {"user"}:
            raise ValueError("Unexpected HY2 counter identity")
        item = data.get("user", {"tx": 0, "rx": 0})
        if (not isinstance(item, dict) or any(type(item.get(key)) is not int or item[key] < 0 for key in ("tx", "rx"))
                or type(online.get("user", 0)) is not int or online.get("user", 0) < 0):
            raise ValueError("Invalid HY2 counters")
        return ({"hy2>>>traffic>>>uplink": item["tx"], "hy2>>>traffic>>>downlink": item["rx"]},
                online.get("user", 0), epoch)

    def start(self, record):
        if not self.enabled or not self.has_record(record):
            return
        if not record["enabled"]:
            self.stop(record)
            return
        self.write_config(record)
        if self.accounts.demo:
            return
        self.validate_tls()
        self.runner(["systemctl", "enable", self.service(record)])
        self.runner(["systemctl", "start", self.service(record)])
        for attempt in range(12):
            try:
                self.query(record)
                return
            except Exception:
                time.sleep(.2)
        raise _server().PanelError("这个账号的 HY2 加速入口未能启动。", 500)

    def stop(self, record):
        if not self.enabled or not self.has_record(record) or self.accounts.demo:
            return
        self.runner(["systemctl", "stop", self.service(record)])
        self.runner(["systemctl", "disable", self.service(record)])

    def enforce(self, blocked, rates):
        # Per-account TCP and UDP share the kernel classes / meters. Keeping
        # HY2 alive during a quota block retains final counters for sampling.
        if not self.enabled or self.accounts.demo:
            return
        for record in [self.accounts._record("admin")] + self.accounts.records:
            if record["enabled"] and self.has_record(record):
                self.runner(["systemctl", "is-active", "--quiet", self.service(record)])

    def snapshot_registry(self):
        return copy.deepcopy(self.data)

    def restore_registry(self, data, records=None):
        if data is None:
            return
        self.data = copy.deepcopy(data)
        self._save()
        # Remove only managed files for entrances removed by this rollback.
        for port in PORTS:
            if not any(item["port"] == port for item in self.data["accounts"].values()):
                self.remove_runtime({"port": port})
        for record in records or []:
            if self.has_record(record):
                self.write_config(record)

    def rotate(self, record):
        if not self.enabled or not self.has_record(record):
            return
        previous = copy.deepcopy(self.data)
        item = _entry(record["port"])
        # Keep API identity stable; service epoch distinguishes counter resets.
        item["api_secret"] = previous["accounts"][record["id"]]["api_secret"]
        self.data["accounts"][record["id"]] = item
        try:
            self._save()
            self.write_config(record)
        except Exception:
            self.restore_registry(previous, [record])
            raise

    def forget(self, record):
        if not self.enabled or not self.has_record(record):
            return
        self.stop(record)
        previous = copy.deepcopy(self.data)
        del self.data["accounts"][record["id"]]
        try:
            self._save()
        except Exception:
            self.data = previous
            raise
        self.remove_runtime(record)

    def remove_runtime(self, record):
        if record["port"] not in PORTS:
            raise ValueError("Unsupported HY2 runtime")
        path = self.runtime / (str(record["port"]) + ".yaml")
        if path.is_symlink():
            raise _server().PanelError("加速入口配置清理需要检查。", 500)
        if path.exists():
            path.unlink()
