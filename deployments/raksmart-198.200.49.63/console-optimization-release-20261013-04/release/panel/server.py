"""Authenticated, loopback-only management API for the existing Xray node."""

import argparse
import base64
import copy
import hashlib
import hmac
from http import cookies
from http.server import BaseHTTPRequestHandler, HTTPServer
try:
    from http.server import ThreadingHTTPServer
except ImportError:
    from socketserver import ThreadingMixIn

    class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
        daemon_threads = True
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import sys
import threading
import time
import unicodedata
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "vendor"))
import configure_reality as base
import configure_static_exits as static
from panel import routing
from panel.node_info import NodeInfo, protocol_label

WEB = Path(__file__).parent / "web"
ITERATIONS = 600000
MAX_BODY = 65536
SERVER_EXIT_ID = "server"


class PanelError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def password_record(password):
    salt = secrets.token_hex(24)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), ITERATIONS)
    return {"username": "admin", "salt": salt, "iterations": ITERATIONS, "hash": hashed.hex()}


def password_matches(password, record):
    hashed = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes.fromhex(record["salt"]), record["iterations"]
    ).hex()
    return hmac.compare_digest(hashed, record["hash"])


def atomic_write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name("." + path.name + "." + secrets.token_hex(8))
    try:
        with temporary.open("xb") as stream:
            if os.name == "posix":
                os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        _compat_unlink_if_exists(temporary)


def json_bytes(value):
    return json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"


def clean_name(value):
    if not isinstance(value, str) or not 1 <= len(value.strip()) <= 32:
        raise PanelError("出口名称需要 1 至 32 个字符。")
    value = value.strip()
    if any(ord(character) < 32 for character in value):
        raise PanelError("出口名称包含不支持的字符。")
    try:
        value.encode("utf-8")
    except UnicodeError as error:
        raise PanelError("出口名称包含不支持的字符。") from error
    return value


def routing_domain(value):
    """Extract one exact hostname without retaining private URL parameters."""
    if any(character.isspace() or unicodedata.category(character) in ("Cc", "Cf")
           for character in value) or "\\" in value:
        raise PanelError("域名或网站链接包含不支持的字符。")
    explicit_url = re.match(r"https?://", value, re.IGNORECASE)
    if re.match(r"[a-z][a-z0-9+.-]*://", value, re.IGNORECASE) and not explicit_url:
        raise PanelError("网站链接仅支持 http:// 或 https://。")
    try:
        parsed = urlsplit(value if explicit_url or value.startswith("//") else "//" + value)
        if (not parsed.netloc or "@" in parsed.netloc or "[" in parsed.netloc or "]" in parsed.netloc
                or not parsed.hostname):
            raise ValueError("Invalid authority")
        # urlsplit permits an empty port, so validate its spelling as well.
        if ":" in parsed.netloc:
            if not re.search(r":[0-9]+$", parsed.netloc) or not 1 <= parsed.port <= 65535:
                raise ValueError("Invalid port")
        domain = parsed.hostname.encode("idna").decode("ascii").lower()
        if domain.endswith("."):
            domain = domain[:-1]
    except (UnicodeError, ValueError, TypeError) as error:
        raise PanelError("请填写有效域名或 HTTP(S) 网站链接，例如 example.com。") from error
    if len(domain) > 253 or "." not in domain or domain.endswith(".localhost") or not all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
        for part in domain.split(".")
    ):
        raise PanelError("请填写有效域名或 HTTP(S) 网站链接，例如 example.com。")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        # Browsers also accept shortened, padded and hexadecimal IPv4 forms.
        if not all(re.fullmatch(r"(?:[0-9]+|0x[0-9a-f]+)", part) for part in domain.split(".")):
            return domain
    raise PanelError("分流规则需要网站域名，不能填写 IP 地址。")


def clean_domains(values, omit_ip_check=True):
    if not isinstance(values, list) or len(values) > 100:
        raise PanelError("最多可以设置 100 个网站域名。")
    result = []
    for value in values:
        if not isinstance(value, str):
            raise PanelError("请每行填写一个域名或网站链接。")
        value = value.strip(" ")
        if not value:
            continue
        value = routing_domain(value)
        if value not in result and (not omit_ip_check or value != "api.ipify.org"):
            result.append(value)
    return result


def domain_overlaps(first, second):
    return first == second or first.endswith("." + second) or second.endswith("." + first)


def validate_routing_domains(proxy_domains, direct_domains):
    for direct in direct_domains:
        if domain_overlaps(direct, "api.ipify.org"):
            raise PanelError("api.ipify.org 用于检测当前出口，必须经过代理，不能加入强制直连。")
        for proxy in proxy_domains:
            if domain_overlaps(direct, proxy):
                raise PanelError("强制直连与强制代理存在重叠域名：" + direct + " 和 " + proxy +
                                 "。请只保留一种走向；子域名与所属主域名也不能分别设置。")


def client_node_names(exits):
    """Keep fixed node names unique when a different exit still has an old name."""
    result = {}
    used = set()
    for item in exits:
        preferred = "出口 · " + item["name"]
        name = preferred
        suffix = 0
        while name.casefold() in used:
            suffix += 1
            name = preferred + " · " + item["id"] + ("-" + str(suffix) if suffix > 1 else "")
        result[item["id"]] = name
        used.add(name.casefold())
    return result


class Manager:
    def __init__(self, directory, public_ip, config_path=base.CONFIG,
                 source_profile=None, demo=False, *, origin="https://api.aiuzh.icu", base_path="/node-console/",
                 service_name="xray.service"):
        if not re.fullmatch(r"xray\.service|xray-panel@[0-9a-f]{16}\.service", service_name):
            raise PanelError("代理实例名称无效。")
        self.service_name = service_name
        self.disabled = False
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            os.chmod(self.directory, 0o700)
        self.state_path = self.directory / "state.private.json"
        self.config_path = Path(config_path)
        self.public_ip = public_ip
        self.demo = demo
        self.node_info = NodeInfo(public_ip, self.directory / "node-info.json", enabled=not demo)
        self.origin = origin.rstrip("/")
        self.base_path = base_path
        self.lock = threading.RLock()
        self.operation = threading.Lock()
        self.jobs = {}
        self.current_job = None
        if not self.state_path.exists():
            if demo:
                private = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
                public = base64.urlsafe_b64encode(bytes(range(32, 64))).decode().rstrip("=")
                identifier = str(uuid.uuid4())
                short_id = "0123456789abcdef"
                config = base.server_config(identifier, private, short_id)
                original = json_bytes(config)
                atomic_write(self.config_path, original)
            else:
                if self.config_path.is_symlink() or not source_profile:
                    raise PanelError("基础节点配置需要检查，管理页没有修改现有配置。")
                original = self.config_path.read_bytes()
                config = json.loads(original)
                public, short_id = static.inspect_base(
                    config, Path(source_profile).read_text(), public_ip
                )
            state = {
                "base": config, "public": public, "short": short_id,
                "managed_hash": digest(original), "auto_id": str(uuid.uuid4()),
                "exits": [], "applied_exits": [], "active_id": None,
                "domains": ["github.com", "githubusercontent.com", "githubassets.com"],
                "applied_domains": [], "profile": None, "history": [], "updated": None,
                "direct_domains": [], "applied_direct_domains": [],
                "rule_token": secrets.token_urlsafe(32),
                "routing_mode": "manual", "applied_routing_mode": "manual",
            }
            atomic_write(self.state_path, json_bytes(state))
        self.state = json.loads(self.state_path.read_text(encoding="utf-8"))
        from panel.subscriptions import ensure_metadata
        migrated = ensure_metadata(self.state)
        defaults = {"direct_domains": [], "applied_direct_domains": [],
                    "routing_mode": "manual", "applied_routing_mode": "manual"}
        for key, value in defaults.items():
            if key not in self.state:
                self.state[key] = copy.deepcopy(value)
                migrated = True
        if not self.state.get("rule_token"):
            self.state["rule_token"] = secrets.token_urlsafe(32)
            migrated = True
        for previous in self.state["history"]:
            if "direct_domains" not in previous:
                previous["direct_domains"] = []
                migrated = True
            if "rule_token" not in previous:
                previous["rule_token"] = self.state["rule_token"]
                migrated = True
        if migrated:
            self.save(self.state)

    def save(self, state):
        from panel.subscriptions import update_metadata
        update_metadata(state, self.state)
        atomic_write(self.state_path, json_bytes(state))
        self.state = state

    def require_idle(self):
        if self.disabled:
            raise PanelError("此账号已停用。", 403)
        if self.operation.locked():
            raise PanelError("正在测试或应用配置，请稍等片刻。", 409)

    def public_state(self):
        with self.lock:
            state = self.state
            active = next((item for item in state["applied_exits"]
                           if item["id"] == state["active_id"]), None)
            def public_exit(item):
                applied = next((value for value in state["applied_exits"] if value["id"] == item["id"]), None)
                result = {key: item.get(key) for key in (
                    "id", "name", "address", "port", "expected_ip", "observed_ip", "tested_at"
                )}
                result.update(authenticated=bool(item.get("username")),
                              active=item["id"] == state["active_id"],
                              pending=not applied or configured([item]) != configured([applied]))
                return result
            def configured(items):
                return [{key: value for key, value in item.items()
                         if key not in ("observed_ip", "tested_at")} for item in items]
            exits_changed = configured(state["exits"]) != configured(state["applied_exits"])
            dirty = exits_changed or state["domains"] != state["applied_domains"]
            dirty = dirty or state["direct_domains"] != state["applied_direct_domains"]
            dirty = dirty or state.get("routing_mode", "manual") != state.get("applied_routing_mode", "manual")
            if active:
                draft = next((item for item in state["exits"] if item["id"] == active["id"]), None)
                if draft and configured([draft]) == configured([active]) and draft["tested_at"]:
                    active = dict(active, observed_ip=draft["observed_ip"], tested_at=draft["tested_at"])
            job = copy.deepcopy(self.jobs.get(self.current_job))
            server_active = state["active_id"] in (None, SERVER_EXIT_ID)
            fixed_names = client_node_names(state["applied_exits"])
            data = {
                "server_ip": self.public_ip,
                "server_port": state["base"]["inbounds"][0].get("port", base.PORT),
                "server_protocol": protocol_label(state["base"]["inbounds"][0]),
                "server_location": self.node_info.snapshot(), "demo": self.demo,
                "exits": [public_exit(item) for item in state["exits"]],
                "active": public_exit(active) if active else None,
                "active_target": "server" if server_active else "static",
                "server_exit": {"id": SERVER_EXIT_ID, "name": "服务器自身出口",
                                "observed_ip": self.public_ip, "active": server_active},
                "domains": state["domains"], "direct_domains": state["direct_domains"],
                "dirty": dirty, "updated": state["updated"],
                "routing_mode": state.get("routing_mode", "manual"),
                "routing_subscription": {
                    "enabled": state.get("routing_mode", "manual") == "smart",
                    "interval": 300,
                    "initial_config_update_required": True,
                    "description": "首次启用或切换分流方案后更新客户端配置一次；智能分流中的自定义域名每 5 分钟自动同步。",
                },
                "download_ready": bool(state["profile"]), "rollback_ready": bool(state["history"]),
                "client_config": {
                    "group": "STATIC-SELECT", "auto_node": "AUTO · 网页切换",
                    "exit_count": len(state["applied_exits"]),
                    "nodes": [fixed_names[item["id"]] for item in state["applied_exits"]],
                    "refresh_required": False,
                    "fixed_nodes_refresh_required": exits_changed,
                },
                "job": job,
            }
            acceleration = getattr(self, "acceleration", None)
            data["transport"] = (acceleration.public_metadata(data["server_port"])
                                 if acceleration else {"enabled": False})
        if self.demo:
            data["service_active"] = True
        else:
            data["service_active"] = base.command(
                ["systemctl", "is-active", "--quiet", self.service_name], check=False
            ).returncode == 0
        return data

    def edit_exit(self, request):
        with self.lock:
            self.require_idle()
            state = copy.deepcopy(self.state)
            identity = request.get("id")
            previous = next((item for item in state["exits"] if item["id"] == identity), None)
            if identity and not previous:
                raise PanelError("没有找到这个出口。", 404)
            if not previous and len(state["exits"]) >= 8:
                raise PanelError("最多可以添加 8 个静态出口。")
            name = clean_name(request.get("name"))
            if any(item["name"].casefold() == name.casefold() and item["id"] != identity
                   for item in state["exits"]):
                raise PanelError("出口名称已存在，请换一个名称。")
            address = request.get("address", "")
            port = request.get("port")
            if not isinstance(address, str):
                raise PanelError("请填写代理服务器地址。")
            try:
                address = static.validate_endpoint(address, port) if not self.demo else address.strip()
            except (ValueError, OSError) as error:
                raise PanelError("代理地址或端口有误。需要可解析的公网地址和 1 至 65535 的端口。") from error
            if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
                raise PanelError("端口需要是 1 至 65535 的整数。")
            auth = request.get("auth", "credentials")
            if auth not in ("credentials", "none"):
                raise PanelError("认证方式有误。")
            username = request.get("username", "")
            password = request.get("password", "")
            if not isinstance(username, str) or not isinstance(password, str):
                raise PanelError("代理账号或密码格式有误。")
            if auth == "none":
                username = password = ""
            elif previous:
                username = username or previous["username"]
                password = password or previous["password"]
            if auth == "credentials" and (not username or not password):
                raise PanelError("请填写代理账号和密码。编辑已保存出口时，留空可以保留原值。")
            try:
                static.validate_credentials(username, password)
            except ValueError as error:
                raise PanelError("代理账号或密码包含不支持的字符，或长度超过 255 字节。") from error
            expected = request.get("expected_ip", "")
            if not isinstance(expected, str):
                raise PanelError("预期出口 IP 格式有误。")
            expected = expected.strip()
            if expected:
                try:
                    parsed = ipaddress.ip_address(expected)
                    if not parsed.is_global:
                        raise ValueError
                    expected = str(parsed)
                except ValueError as error:
                    raise PanelError("预期出口 IP 需要是公网 IP；不知道时可以留空。") from error
            item = {"id": identity or secrets.token_hex(8), "name": name,
                    "address": address, "port": port, "username": username, "password": password,
                    "expected_ip": expected, "observed_ip": None, "tested_at": None,
                    "client_id": previous["client_id"] if previous else str(uuid.uuid4())}
            if previous:
                state["exits"][state["exits"].index(previous)] = item
            else:
                state["exits"].append(item)
            self.save(state)
            return {"id": item["id"]}

    def delete_exit(self, identity):
        with self.lock:
            self.require_idle()
            state = copy.deepcopy(self.state)
            if not any(item["id"] == identity for item in state["exits"]):
                raise PanelError("没有找到这个出口。", 404)
            state["exits"] = [item for item in state["exits"] if item["id"] != identity]
            self.save(state)

    def set_domains(self, domains):
        with self.lock:
            return self.set_routing(domains, self.state.get("routing_mode", "manual"))

    def set_routing(self, domains, mode, direct_domains=None):
        domains = clean_domains(domains)
        if mode not in routing.MODES:
            raise PanelError("请选择一个有效的分流方案。")
        with self.lock:
            self.require_idle()
            state = copy.deepcopy(self.state)
            direct_domains = (clean_domains(direct_domains, omit_ip_check=False)
                              if direct_domains is not None else list(state["direct_domains"]))
            validate_routing_domains(domains, direct_domains)
            state.update(domains=domains, direct_domains=direct_domains, routing_mode=mode)
            if state["profile"]:
                if digest(self.config_path.read_bytes()) != state["managed_hash"]:
                    raise PanelError("服务器节点配置已被其他操作修改，生成配置已停止。", 409)
                applied = copy.deepcopy(state)
                applied["exits"] = applied["applied_exits"]
                _, profile = self.build(applied, applied["active_id"])
                state.update(profile=profile, applied_domains=list(domains),
                             applied_direct_domains=list(direct_domains), applied_routing_mode=mode)
            self.save(state)
            return {"download_ready": bool(state["profile"])}

    def rule_snapshot(self, token, direction):
        with self.lock:
            expected = self.state["rule_token"]
            # Compare bytes so malformed non-ASCII tokens still produce a plain 404.
            valid = hmac.compare_digest(token.encode("utf-8"), expected.encode("utf-8"))
            if not valid or direction not in ("direct", "proxy"):
                raise PanelError("页面不存在。", 404)
            domains = list(self.state["direct_domains"] if direction == "direct" else self.state["domains"])
        return routing.rule_payload(domains, direction)

    def probe(self, item):
        if self.demo:
            time.sleep(0.2)
            if "fail" in item["address"]:
                raise PanelError("代理连接失败。请检查地址、端口、账号密码及服务商的 IP 白名单。")
            return "203.0.113." + str(10 + int(item["id"][-2:], 16) % 100)
        try:
            static.validate_endpoint(item["address"], item["port"])
            observed = static.probe_exit(item)
        except (ValueError, RuntimeError, OSError) as error:
            raise PanelError("代理连接失败。请检查地址、端口、账号密码及服务商的 IP 白名单。") from error
        if item["expected_ip"] and item["expected_ip"] != observed:
            raise PanelError("实际出口 IP 与填写的预期 IP 不一致，配置没有应用。")
        return observed

    def build(self, state, active_id):
        specs = [dict(item, label="E" + item["id"].upper()) for item in state["exits"]]
        if specs:
            config, nodes = static.extend_config(state["base"], specs)
        else:
            config, nodes = copy.deepcopy(state["base"]), []
        fixed_names = client_node_names(state["exits"])
        for index, (item, node) in enumerate(zip(state["exits"], nodes)):
            config["inbounds"][0]["settings"]["clients"][index + 1]["id"] = item["client_id"]
            node["id"] = item["client_id"]
            node["name"] = fixed_names[item["id"]]
        selected = next((item for item in state["exits"] if item["id"] == active_id), None)
        server_active = active_id in (None, SERVER_EXIT_ID)
        if not server_active and not selected:
            raise PanelError("请先选择要应用的出口。")
        email = "panel-auto@exits.invalid"
        config["inbounds"][0]["settings"]["clients"].append({
            "id": state["auto_id"], "email": email, "flow": "xtls-rprx-vision",
        })
        config["routing"]["rules"].extend([
            {"type": "field", "user": [email], "network": "udp", "outboundTag": "block"},
            {"type": "field", "user": [email], "network": "tcp",
             "outboundTag": "direct" if server_active else "static-E" + selected["id"].upper()},
        ])
        nodes.insert(0, {"name": "AUTO · 网页切换", "id": state["auto_id"]})
        profile = static.client_profile(self.public_ip, state["public"], state["short"], nodes,
                                       server_name=state["base"]["inbounds"][0]["streamSettings"]["realitySettings"]["serverNames"][0],
                                       server_port=state["base"]["inbounds"][0].get("port", base.PORT))
        profile = routing.render(profile, nodes, state["domains"], state.get("routing_mode", "manual"),
                                 self.origin, self.base_path, direct_domains=state.get("direct_domains", []),
                                 rule_token=state["rule_token"])
        from panel.telemetry import augment_config
        config = augment_config(config, state["base"]["inbounds"][0].get("port", base.PORT))
        acceleration = getattr(self, "acceleration", None)
        if acceleration and acceleration.enabled:
            config, profile = acceleration.compose(config, profile,
                state["base"]["inbounds"][0].get("port", base.PORT), self.public_ip)
        return config, profile

    def progress(self, identity, message, percent, *, testing_id=None):
        with self.lock:
            self.jobs[identity].update(message=message, percent=percent, testing_id=testing_id)

    def install(self, original, payload, profile):
        if self.demo:
            atomic_write(self.config_path, payload)
            return
        telemetry_source = getattr(self, "telemetry_source", None)
        if telemetry_source:
            telemetry_source.sample_user(self.account_id)
        temporary_profile = self.directory / ("profile-" + secrets.token_hex(8) + ".private.yaml")
        try:
            static.apply_update(
                self.config_path, original, payload, temporary_profile, profile,
                0, 0, self.config_path.stat().st_gid,
                service_name=self.service_name, port=self.state["base"]["inbounds"][0].get("port", base.PORT),
                config_mode=0o600 if self.service_name != "xray.service" else 0o640,
            )
        finally:
            _compat_unlink_if_exists(temporary_profile)

    def apply(self, identity, active_id):
        with self.lock:
            state = copy.deepcopy(self.state)
        if active_id != SERVER_EXIT_ID and not any(item["id"] == active_id for item in state["exits"]):
            raise PanelError("请先选择一个出口。")
        original = self.config_path.read_bytes()
        if digest(original) != state["managed_hash"]:
            raise PanelError("服务器配置已被其他操作修改，本页停止应用。请先检查现有配置。", 409)
        applied = {item["id"]: item for item in state["applied_exits"]}
        running_exits = []
        for item in state["exits"]:
            if item["id"] == active_id:
                self.progress(identity, "测试出口：" + item["name"], 30, testing_id=item["id"])
                item["observed_ip"] = self.probe(item)
                item["tested_at"] = now()
                running_exits.append(copy.deepcopy(item))
            elif item["id"] in applied:
                # An unrelated draft must not replace its last verified running version.
                running_exits.append(copy.deepcopy(applied[item["id"]]))
        running = copy.deepcopy(state)
        running["exits"] = running_exits
        config, profile = self.build(running, active_id)
        payload = json_bytes(config)
        self.progress(identity, "校验配置并切换出口", 75)
        self.install(original, payload, profile)
        history = {
            "config": json.loads(original), "applied_exits": state["applied_exits"],
            "active_id": state["active_id"], "profile": state["profile"],
            "domains": state["applied_domains"], "updated": state["updated"],
            "direct_domains": state["applied_direct_domains"], "rule_token": state["rule_token"],
            "routing_mode": state.get("applied_routing_mode", "manual"),
        }
        state["history"] = (state["history"] + [history])[-5:]
        state.update(applied_exits=running_exits, active_id=active_id,
                     applied_domains=list(state["domains"]), profile=profile,
                     applied_direct_domains=list(state["direct_domains"]),
                     applied_routing_mode=state.get("routing_mode", "manual"),
                     managed_hash=digest(payload), updated=now())
        try:
            with self.lock:
                self.save(state)
        except Exception:
            self.install(payload, original, "rollback")
            raise
        self.progress(identity, "已切换，新建连接使用服务器自身出口" if active_id == SERVER_EXIT_ID
                      else "已切换，新建连接使用所选出口", 100)

    def rollback(self, identity):
        with self.lock:
            state = copy.deepcopy(self.state)
        if not state["history"]:
            raise PanelError("还没有可恢复的上一份配置。")
        original = self.config_path.read_bytes()
        if digest(original) != state["managed_hash"]:
            raise PanelError("服务器配置已被其他操作修改，恢复已停止。", 409)
        previous = state["history"].pop()
        restored_active = previous["active_id"]
        restored_profile = previous["profile"]
        restored_config = previous["config"]
        restored_domains = list(previous.get("domains", state["domains"]))
        restored_direct_domains = previous.get("direct_domains", [])
        if restored_active is None and not restored_profile:
            # Legacy history can predate AUTO. Keep its stable entry available on rollback.
            restored = copy.deepcopy(state)
            restored.update(exits=copy.deepcopy(previous["applied_exits"]),
                            domains=restored_domains, direct_domains=restored_direct_domains,
                            routing_mode=previous.get("routing_mode", "manual"))
            restored_config, restored_profile = self.build(restored, SERVER_EXIT_ID)
            restored_active = SERVER_EXIT_ID
        from panel.telemetry import augment_config
        restored_config = augment_config(restored_config, state["base"]["inbounds"][0].get("port", base.PORT))
        acceleration = getattr(self, "acceleration", None)
        if acceleration and acceleration.enabled:
            restored_config, restored_profile = acceleration.compose(restored_config, restored_profile,
                state["base"]["inbounds"][0].get("port", base.PORT), self.public_ip)
        payload = json_bytes(restored_config)
        self.progress(identity, "恢复上一份已应用配置", 50)
        self.install(original, payload, restored_profile or "rollback")
        state.update(exits=copy.deepcopy(previous["applied_exits"]),
                     applied_exits=previous["applied_exits"], active_id=restored_active,
                     profile=restored_profile, domains=restored_domains,
                     direct_domains=list(restored_direct_domains), applied_direct_domains=list(restored_direct_domains),
                     applied_domains=restored_domains, managed_hash=digest(payload), updated=now())
        state.update(routing_mode=previous.get("routing_mode", "manual"),
                     applied_routing_mode=previous.get("routing_mode", "manual"))
        try:
            with self.lock:
                self.save(state)
        except Exception:
            self.install(payload, original, "rollback")
            raise
        self.progress(identity, "已恢复上一份配置", 100)

    def start_job(self, kind, exit_id=None, audit_callback=None):
        if not self.operation.acquire(blocking=False):
            raise PanelError("已有任务正在执行，请稍后再试。", 409)
        if self.disabled:
            self.operation.release()
            raise PanelError("此账号已停用。", 403)
        identity = secrets.token_hex(12)
        with self.lock:
            self.current_job = identity
            self.jobs[identity] = {"id": identity, "kind": kind, "status": "running",
                                   "message": "准备开始", "percent": 0, "result": None,
                                   "exit_id": exit_id, "testing_id": None}
            if len(self.jobs) > 20:
                del self.jobs[next(iter(self.jobs))]

        def run():
            final_status = "success"
            final_message = None
            try:
                if kind == "test":
                    with self.lock:
                        item = copy.deepcopy(next((item for item in self.state["exits"]
                                                   if item["id"] == exit_id), None))
                    if not item:
                        raise PanelError("没有找到这个出口。", 404)
                    self.progress(identity, "检测代理实际出口", 30, testing_id=exit_id)
                    observed = self.probe(item)
                    with self.lock:
                        state = copy.deepcopy(self.state)
                        target = next(item for item in state["exits"] if item["id"] == exit_id)
                        target.update(observed_ip=observed, tested_at=now())
                        self.save(state)
                        self.jobs[identity]["result"] = {"observed_ip": observed}
                    self.progress(identity, "连接通过，实际出口：" + observed, 100)
                elif kind == "apply":
                    self.apply(identity, exit_id)
                elif kind == "rollback":
                    self.rollback(identity)
                else:
                    raise PanelError("不支持的操作。")
            except Exception as error:
                final_message = str(error) if isinstance(error, PanelError) else (
                    "操作没有完成。已尝试恢复原配置，请检查服务状态后重试。"
                )
                final_status = "failed"
            finally:
                self.operation.release()
                with self.lock:
                    self.jobs[identity]["status"] = final_status
                    if final_message:
                        self.jobs[identity]["message"] = final_message
                if audit_callback:
                    audit_callback(final_status, final_message)
        threading.Thread(target=run, daemon=True).start()
        return {"job_id": identity}


class Application:
    def __init__(self, manager, origin, base_path="/node-console/", demo=False):
        self.manager = manager
        self.origin = origin.rstrip("/")
        self.base_path = base_path
        self.demo = demo
        self.auth_path = manager.directory / "auth.private.json"
        if demo and not self.auth_path.exists():
            atomic_write(self.auth_path, json_bytes(password_record("demo-password-2026")))
        self.auth = json.loads(self.auth_path.read_text(encoding="utf-8"))
        # The service is launched as a script; reuse its class identities in Accounts.
        sys.modules.setdefault("panel.server", sys.modules[__name__])
        from panel.accounts import Accounts
        self.accounts = Accounts(manager, self.auth_path, demo=demo)
        self.sessions = {}
        self.attempts = {}
        self.lock = threading.Lock()
        self.mutation_lock = threading.RLock()
        self.background_stop = threading.Event()
        self._initialize_operations()
        from panel.provisioning import MemberPreparation
        self.member_preparation = MemberPreparation(self)

    def _initialize_operations(self):
        from panel.audit import AuditLog
        from panel.diagnostics import RuleDiagnostics
        from panel.health import HealthMonitor
        from panel.telemetry import Telemetry
        from panel.hy2 import Integration
        from panel.backups import BackupManager
        previous_health = getattr(self, "health", None)
        if previous_health:
            previous_health.close()
        self.audit = AuditLog(self.manager.directory)
        self.diagnostics = RuleDiagnostics(self.manager.directory)
        self.health = HealthMonitor(self.accounts, self.audit, operation_lock=self.mutation_lock)
        self.acceleration = Integration(self.accounts)
        self.accounts.acceleration = self.acceleration
        self.telemetry = Telemetry(self.accounts, hy2=self.acceleration if self.acceleration.enabled else None)
        self.accounts.telemetry = self.telemetry
        for record in [self.accounts._record("admin")] + self.accounts.records:
            manager = self.accounts._manager(record)
            manager.account_id = record["id"]
            manager.telemetry_source = self.telemetry
        self.backups = BackupManager(self.accounts, self.mutation_lock, runtime=self._backup_runtime)

    def _backup_runtime(self, action, records):
        if self.demo:
            return
        if action not in ("stop", "start"):
            raise PanelError("备份运行控制无效。", 500)
        if action == "start":
            self.acceleration.reload()
            self.telemetry.reload()
            self.telemetry.hy2 = self.acceleration if self.acceleration.enabled else None
        for record in records:
            identity = record["id"]
            service = "xray.service" if identity == "admin" else self.accounts._service(record)
            if action == "stop":
                if identity == "admin" or any(item["id"] == identity for item in self.accounts.records):
                    self.telemetry.sample_user(identity)
                self.acceleration.stop(record)
                base.command(["systemctl", "stop", service])
                if identity != "admin":
                    base.command(["systemctl", "disable", service])
            elif record["enabled"]:
                base.command(["systemctl", "enable", service])
                base.command(["systemctl", "start", service])
                if identity == "admin":
                    base.command(["systemctl", "is-active", "--quiet", service])
                else:
                    self.accounts._wait_ready(record)
                self.acceleration.start(record)
            else:
                base.command(["systemctl", "stop", service])
                base.command(["systemctl", "disable", service])
                self.acceleration.stop(record)
        if action == "start":
            self.telemetry.apply_enforcement(force=True)

    def start_background(self):
        if self.demo:
            return
        def work():
            next_health = 0
            next_rules = 0
            last_failure = {}
            while not self.background_stop.is_set():
                with self.mutation_lock:
                    tasks = [("traffic", self.telemetry.tick), ("backup", self.backups.tick)]
                    if time.time() >= next_health:
                        tasks.append(("health", self.health.tick))
                        next_health = time.time() + 30
                    for name, task in tasks:
                        try:
                            task()
                        except Exception:
                            # A failed counter or kernel update must not prevent
                            # backups or health checks, nor flood the activity log.
                            if time.time() - last_failure.get(name, 0) >= 300:
                                last_failure[name] = time.time()
                                try:
                                    self.audit.record({"id": "system", "username": "系统"},
                                                      "maintenance." + name, "failed",
                                                      "后台检查未完成，请查看维护页状态")
                                except OSError:
                                    pass
                if time.time() >= next_rules:
                    threading.Thread(target=self.diagnostics.refresh, daemon=True).start()
                    next_rules = time.time() + 86400
                self.background_stop.wait(10)
        threading.Thread(target=work, daemon=True).start()

    def reload_after_restore(self):
        # Member preparation history is deliberately outside complete backups:
        # task credentials are never restored, and a restored account registry
        # can point to different member identities. Start with an empty task
        # registry so the UI cannot report a stale successful preparation.
        from panel import provisioning
        previous = getattr(self, "member_preparation", None)
        if previous is not None:
            previous.reset_after_restore()
            self.member_preparation = provisioning.MemberPreparation(self)
        with self.lock:
            self.sessions.clear()
        self.auth = json.loads(self.auth_path.read_text(encoding="utf-8"))
        self._initialize_operations()

    def session(self, token, lightweight_admin=False, logout_only=False):
        with self.lock:
            session = self.sessions.get(token)
            if not session or session["expires"] < time.time():
                self.sessions.pop(token, None)
                return None
            result = session.copy()
        # The owner cannot be disabled or demoted, and password changes and
        # restores revoke its sessions. Task reads must stay available while
        # member creation holds Accounts.lock for configuration and services.
        if logout_only or (lightweight_admin and result["user_id"] == "admin"
                and result.get("user", {}).get("role") == "admin"):
            return result
        try:
            user = self.accounts.get(result["user_id"])
            if not user["enabled"]:
                self.invalidate_user(result["user_id"])
                return None
        except PanelError:
            return None
        result["user"] = user
        return result

    def invalidate_user(self, user_id):
        with self.lock:
            self.sessions = {key:value for key,value in self.sessions.items() if value["user_id"] != user_id}

    def login(self, username, password, peer):
        if not isinstance(username, str) or not isinstance(password, str) or len(password) > 128:
            raise PanelError("用户名或密码不正确。", 401)
        with self.lock:
            failures = [value for value in self.attempts.get(peer, []) if value > time.time() - 600]
            if len(failures) >= 6:
                raise PanelError("尝试次数过多，请 10 分钟后再试。", 429)
        # Password changes must invalidate even logins already authenticating.
        with self.accounts.lock:
            user = self.accounts.authenticate(username, password)
            if not user:
                with self.lock:
                    self.attempts[peer] = failures + [time.time()]
                    if len(self.attempts) > 1024:
                        self.attempts.pop(next(iter(self.attempts)))
                raise PanelError("用户名或密码不正确。", 401)
            token = secrets.token_urlsafe(32)
            session = {"csrf": secrets.token_urlsafe(24), "expires": time.time() + 8 * 3600,
                       "user_id": user["id"], "user": user}
            with self.lock:
                self.attempts.pop(peer, None)
                self.sessions = {key: value for key, value in self.sessions.items()
                                 if value["expires"] > time.time()}
                self.sessions[token] = session
        return token, session


class Handler(BaseHTTPRequestHandler):
    server_version = "NodeConsole"

    @property
    def app(self):
        return self.server.application

    def log_message(self, *args):
        pass

    def setup(self):
        super().setup()
        self.connection.settimeout(20)

    def token(self):
        parsed = cookies.SimpleCookie()
        try:
            parsed.load(self.headers.get("Cookie", ""))
        except cookies.CookieError:
            return ""
        return parsed["vps_panel_session"].value if "vps_panel_session" in parsed else ""

    def cookie(self, token, clear=False):
        secure = "; Secure" if self.app.origin.startswith("https://") else ""
        age = 0 if clear else 8 * 3600
        return (f"vps_panel_session={token}; Path={self.app.base_path}; Max-Age={age}; "
                f"HttpOnly; SameSite=Strict{secure}")

    def send(self, status, body, content_type="application/json; charset=utf-8", extra=None):
        self.response_status = status
        if isinstance(body, (dict, list)):
            body = json_bytes(body)
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; "
                         "style-src 'self'; img-src 'self' data:; connect-src 'self'; "
                         "frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def require_session(self, mutation=False, lightweight_admin=False, logout_only=False):
        session = self.app.session(self.token(), lightweight_admin=lightweight_admin,
                                   logout_only=logout_only)
        if not session:
            raise PanelError("登录已过期，请重新登录。", 401)
        if mutation and not hmac.compare_digest(
            self.headers.get("X-CSRF-Token", ""), session["csrf"]
        ):
            raise PanelError("请求校验失败，请刷新页面重试。", 403)
        return session

    def do_GET(self):
        try:
            path = urlsplit(self.path).path
            assets = {"/": ("index.html", "text/html; charset=utf-8"),
                      "/app.js": ("app.js", "text/javascript; charset=utf-8"),
                      "/style.css": ("style.css", "text/css; charset=utf-8"),
                      "/mark.svg": ("mark.svg", "image/svg+xml")}
            if path in assets:
                filename, content_type = assets[path]
                return self.send(200, (WEB / filename).read_bytes(), content_type)
            if path == "/rules/domestic-dns.yaml":
                return self.send(200, (Path(__file__).parent / "rules" / "domestic-dns.yaml").read_bytes(),
                                 "application/yaml; charset=utf-8")
            if path.startswith("/rules/custom/"):
                match = re.fullmatch(r"/rules/custom/([^/]+)/([^/]+)\.yaml", path)
                if not match:
                    raise PanelError("页面不存在。", 404)
                payload = self.app.accounts.rule_snapshot(match.group(1), match.group(2))
                return self.send(200, payload, "application/yaml; charset=utf-8")
            if path == "/api/session":
                session = self.app.session(self.token())
                return self.send(200, {"authenticated": bool(session),
                                       "csrf": session["csrf"] if session else None,
                                       "user": session["user"] if session else None,
                                       "demo": self.app.demo})
            if path.startswith("/subscription/"):
                match = re.fullmatch(r"/subscription/([A-Za-z0-9_-]{32,128})\.yaml", path)
                if not match:
                    raise PanelError("页面不存在。", 404)
                profile = self.app.accounts.subscription_profile(match.group(1))
                return self.send(200, profile, "application/yaml; charset=utf-8",
                                 {"Content-Disposition": 'attachment; filename="clash-node-console.yaml"',
                                  "profile-update-interval": "1"})
            session = self.require_session(lightweight_admin=path == "/api/users/provision")
            if path == "/api/users":
                if session["user"]["role"] != "admin":
                    raise PanelError("只有管理员可以管理用户。", 403)
                with self.app.accounts.lock:
                    users = self.app.accounts.list_users()
                    for user in users:
                        user["traffic"] = self.app.telemetry.snapshot(user["id"])
                    entrances = self.app.accounts.entrance_summary()
                return self.send(200, {"users": users, "entrances": entrances})
            if path in ("/api/entrances", "/api/users/provision"):
                if session["user"]["role"] != "admin":
                    raise PanelError("只有管理员可以准备成员入口。", 403)
                if path == "/api/entrances":
                    return self.send(200, {"entrances": self.app.accounts.entrance_summary()})
                task_id = parse_qs(urlsplit(self.path).query).get("id", [""])[0]
                return self.send(200, {"task": self.app.member_preparation.get(task_id)} if task_id
                                 else {"tasks": self.app.member_preparation.list()})
            manager = self.app.accounts.manager(session["user_id"])
            if path == "/api/state":
                return self.send(200, dict(manager.public_state(), user=session["user"],
                                          health=self.app.health.snapshot(session["user_id"]),
                                          traffic=self.app.telemetry.snapshot(session["user_id"])))
            if path == "/api/subscription":
                return self.send(200, self.app.accounts.profile_metadata(session["user_id"]))
            if path == "/api/traffic":
                result = self.app.telemetry.snapshot(session["user_id"])
                if session["user"]["role"] == "admin":
                    result["users"] = self.app.telemetry.snapshots()
                return self.send(200, result)
            if path == "/api/audit":
                query = parse_qs(urlsplit(self.path).query)
                try:
                    limit = int(query.get("limit", [50])[0])
                except (TypeError, ValueError):
                    raise PanelError("记录数量无效。")
                return self.send(200, self.app.audit.query(session["user"], limit))
            if path.startswith("/api/backups"):
                if session["user"]["role"] != "admin":
                    raise PanelError("只有管理员可以维护系统备份。", 403)
                if path == "/api/backups":
                    return self.send(200, self.app.backups.list())
                if path == "/api/backups/download":
                    token = parse_qs(urlsplit(self.path).query).get("token", [""])[0]
                    data, filename = self.app.backups.download(token)
                    return self.send(200, data, "application/octet-stream",
                                     {"Content-Disposition": 'attachment; filename="' + filename + '"'})
                raise PanelError("页面不存在。", 404)
            if path == "/api/profile":
                with manager.lock:
                    profile = manager.state["profile"]
                if not profile:
                    raise PanelError("先点击服务器或静态出口应用配置，再下载。", 409)
                return self.send(200, profile, "application/yaml; charset=utf-8",
                                 {"Content-Disposition": 'attachment; filename="clash-node-console.yaml"'})
            if path.startswith("/api/jobs/"):
                with manager.lock:
                    job = copy.deepcopy(manager.jobs.get(path.rsplit("/", 1)[1]))
                if not job:
                    raise PanelError("没有找到这个任务。", 404)
                return self.send(200, job)
            raise PanelError("页面不存在。", 404)
        except PanelError as error:
            self.send(error.status, {"error": str(error)})
        except Exception:
            self.send(500, {"error": "服务暂时不可用，请稍后重试。"})

    def do_POST(self):
        self.audit_actor = {"id": "visitor", "username": "访客"}
        self.audit_target = None
        self.audit_failure = ""
        self.response_status = 500
        # Revoking one's own session touches only the session lock. Keep it
        # responsive while member preparation holds the account mutation lock.
        if urlsplit(self.path).path == "/api/logout":
            self._post()
        else:
            with self.app.mutation_lock:
                self._post()
        actions = {
            "/api/login": ("login", "网页登录"), "/api/logout": ("logout", "退出网页登录"),
            "/api/exits/save": ("exit.save", "保存出口资料"),
            "/api/exits/delete": ("exit.delete", "删除出口草稿"),
            "/api/routing": ("routing.save", "保存分流规则"),
            "/api/domains": ("routing.save", "保存分流规则"),
            "/api/test": ("exit.test", "检测出口"), "/api/apply": ("exit.apply", "应用并切换出口"),
            "/api/rollback": ("config.rollback", "恢复上次配置"),
            "/api/password": ("password.change", "修改网页登录密码"),
            "/api/users/create": ("user.create", "创建独立成员账号"),
            "/api/users/provision": ("user.prepare", "准备独立成员入口"),
            "/api/entrances/configure": ("entrance.configure", "更新成员入口资源池"),
            "/api/users/reset-password": ("user.password", "重置成员网页登录密码"),
            "/api/users/set-enabled": ("user.enabled", "修改成员启用状态"),
            "/api/users/delete": ("user.delete", "删除成员账号并释放名额"),
            "/api/users/rotate-credentials": ("user.credentials", "撤销成员旧代理配置"),
            "/api/credentials/rotate": ("credentials.rotate", "撤销旧代理配置并生成新凭据"),
            "/api/subscription/rotate": ("subscription.rotate", "撤销旧完整配置订阅地址"),
            "/api/health/settings": ("health.settings", "修改出口检测及备用策略"),
            "/api/health/check": ("health.check", "请求后台检测当前出口"),
            "/api/traffic/limits": ("traffic.limits", "修改成员月额度和带宽上限"),
            "/api/backups/create": ("backup.create", "创建加密完整备份"),
            "/api/backups/export": ("backup.export", "导出便携加密备份"),
            "/api/backups/preview": ("backup.preview", "校验导入备份并预览恢复"),
            "/api/backups/restore": ("backup.restore", "恢复完整系统备份"),
            "/api/backups/schedule": ("backup.schedule", "设置每日自动加密备份"),
        }
        item = actions.get(urlsplit(self.path).path)
        if item:
            status = "started" if self.response_status == 202 else "success" if self.response_status < 400 else "failed"
            summary = item[1] + ("：" + self.audit_failure if self.audit_failure else "")
            self.app.audit.record(self.audit_actor, item[0], status, summary, self.audit_target)

    def _post(self):
        try:
            if self.headers.get("Origin") != self.app.origin:
                raise PanelError("请求来源校验失败。", 403)
            if self.headers.get_content_type() != "application/json":
                raise PanelError("请使用页面表单提交。", 415)
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError as error:
                raise PanelError("请求格式有误。") from error
            path = urlsplit(self.path).path
            maximum = 48 * 1024 * 1024 if path == "/api/backups/preview" else MAX_BODY
            if not 0 < length <= maximum:
                raise PanelError("提交内容过大或为空。", 413)
            try:
                request = json.loads(self.rfile.read(length))
            except (ValueError, UnicodeError) as error:
                raise PanelError("请求格式有误。") from error
            if not isinstance(request, dict):
                raise PanelError("请求格式有误。")
            if path == "/api/login":
                peer = self.headers.get("X-Real-IP", self.client_address[0])
                token, session = self.app.login(request.get("username"), request.get("password"), peer)
                self.audit_actor = session["user"]
                return self.send(200, {"csrf": session["csrf"], "user":session["user"]}, extra={"Set-Cookie": self.cookie(token)})
            session = self.require_session(mutation=True, logout_only=path == "/api/logout")
            self.audit_actor = session["user"]
            if path == "/api/logout":
                with self.app.lock:
                    self.app.sessions.pop(self.token(), None)
                return self.send(200, {"ok": True}, extra={"Set-Cookie": self.cookie("", True)})
            if path == "/api/entrances/configure":
                if session["user"]["role"] != "admin":
                    raise PanelError("只有管理员可以准备成员入口。", 403)
                if self.app.member_preparation.has_active():
                    raise PanelError("有成员入口正在准备，请等待任务完成后调整资源池。", 409)
                return self.send(200, {"entrances": self.app.accounts.configure_entrances(request)})
            if path.startswith("/api/users/"):
                if session["user"]["role"] != "admin":
                    raise PanelError("只有管理员可以管理用户。", 403)
                self.audit_target = request.get("id")
                if path == "/api/users/provision":
                    return self.send(202, {"task": self.app.member_preparation.submit(request, session["user"])})
                if path in ("/api/users/delete", "/api/users/rotate-credentials"):
                    target = self.app.accounts.get(request.get("id"))
                    if request.get("confirm_username") != target["username"]:
                        raise PanelError("请输入目标账号名称确认操作。")
                    if path == "/api/users/delete":
                        result = self.app.accounts.delete_user(target["id"])
                        self.app.invalidate_user(target["id"])
                        self.app.telemetry.forget_user(target["id"])
                        return self.send(200, result)
                    result = self.app.accounts.rotate_credentials(target["id"])
                    return self.send(200, result)
                if path == "/api/users/create":
                    if self.app.member_preparation.has_active():
                        raise PanelError("有成员入口正在准备，请等待任务完成后创建其他成员。", 409)
                    return self.send(200, {"user":self.app.accounts.create_user(request)})
                if path == "/api/users/reset-password":
                    user = self.app.accounts.reset_password(request.get("id"), request.get("password"))
                elif path == "/api/users/set-enabled":
                    user = self.app.accounts.set_enabled(request.get("id"), request.get("enabled"))
                else:
                    raise PanelError("操作不存在。", 404)
                self.app.invalidate_user(user["id"])
                return self.send(200, {"user":user})
            manager = self.app.accounts.manager(session["user_id"])
            if path == "/api/subscription/rotate":
                return self.send(200, self.app.accounts.rotate_subscription_token(session["user_id"]))
            if path == "/api/credentials/rotate":
                return self.send(200, self.app.accounts.rotate_credentials(session["user_id"]))
            if path == "/api/diagnostics":
                value = request.get("url")
                if not isinstance(value, str) or not 1 <= len(value) <= 4096:
                    raise PanelError("请填写有效网站域名或完整网址。")
                return self.send(200, self.app.diagnostics.check(manager, value))
            if path == "/api/health/settings":
                return self.send(200, self.app.health.settings(session["user_id"], request))
            if path == "/api/health/check":
                return self.send(200, self.app.health.check_async(session["user_id"]))
            if path == "/api/traffic/limits":
                if session["user"]["role"] != "admin":
                    raise PanelError("只有管理员可以分配流量额度和带宽。", 403)
                self.audit_target = request.get("id")
                return self.send(200, self.app.telemetry.set_limits(request.get("id"), request.get("quota_bytes"), request.get("rate_bps")))
            if path.startswith("/api/backups/"):
                if session["user"]["role"] != "admin":
                    raise PanelError("只有管理员可以维护系统备份。", 403)
                if path == "/api/backups/create":
                    return self.send(200, self.app.backups.create(request.get("name", ""), request.get("password")))
                if path == "/api/backups/export":
                    return self.send(200, self.app.backups.export(request.get("id"), request.get("password")))
                if path == "/api/backups/preview":
                    return self.send(200, self.app.backups.preview(request.get("data"), request.get("password")))
                if path == "/api/backups/schedule":
                    return self.send(200, self.app.backups.schedule(request.get("enabled")))
                if path == "/api/backups/restore":
                    if self.app.member_preparation.has_active():
                        raise PanelError("有成员入口正在准备，请等待任务完成后恢复备份。", 409)
                    result = self.app.backups.restore(request.get("preview_token"), request.get("confirmation"))
                    self.app.reload_after_restore()
                    return self.send(200, result, extra={"Set-Cookie": self.cookie("", True)})
                raise PanelError("操作不存在。", 404)
            if path == "/api/exits/save":
                return self.send(200, manager.edit_exit(request))
            if path == "/api/exits/delete":
                manager.delete_exit(request.get("id"))
                return self.send(200, {"ok": True})
            if path == "/api/domains":
                manager.set_domains(request.get("domains"))
                return self.send(200, {"ok": True})
            if path == "/api/routing":
                return self.send(200, manager.set_routing(request.get("domains"), request.get("mode"),
                                                                 request.get("direct_domains")))
            if path in ("/api/test", "/api/apply", "/api/rollback"):
                action = "exit." + path.rsplit("/", 1)[1]
                actor = session["user"]
                callback = lambda result, message: self.app.audit.record(actor, action, result, "出口任务完成" if result == "success" else "出口任务失败：" + message)
                return self.send(202, manager.start_job(path.rsplit("/", 1)[1], request.get("id"), callback))
            if path == "/api/password":
                old = request.get("current", "")
                new = request.get("new", "")
                if not isinstance(old, str) or not isinstance(new, str) or not 12 <= len(new) <= 128:
                    raise PanelError("新密码需要 12 至 128 个字符。")
                self.app.accounts.change_password(session["user_id"], old, new)
                self.app.invalidate_user(session["user_id"])
                if session["user_id"] == "admin":
                    self.app.auth = json.loads(self.app.auth_path.read_text(encoding="utf-8"))
                return self.send(200, {"ok": True}, extra={"Set-Cookie": self.cookie("", True)})
            raise PanelError("操作不存在。", 404)
        except PanelError as error:
            self.audit_failure = str(error)
            self.send(error.status, {"error": str(error)})
        except Exception:
            self.audit_failure = "内部执行失败，请刷新并检查服务状态。"
            self.send(500, {"error": "操作没有完成，请刷新后重试。"})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", default="/var/lib/vps-panel")
    parser.add_argument("--public-ip", required=True)
    parser.add_argument("--config", default=str(base.CONFIG))
    parser.add_argument("--source-profile")
    parser.add_argument("--origin", required=True)
    parser.add_argument("--base-path", default="/node-console/")
    parser.add_argument("--port", type=int, default=18787)
    parser.add_argument("--demo", action="store_true")
    parser.add_argument("--initialize-only", action="store_true")
    args = parser.parse_args()
    if not args.demo and (os.name != "posix" or os.geteuid() != 0):
        raise RuntimeError("The production worker must run on the VPS with its service account.")
    manager = Manager(args.directory, args.public_ip, Path(args.config), args.source_profile, args.demo,
                      origin=args.origin, base_path=args.base_path)
    if args.initialize_only:
        print("Panel state initialized; Xray configuration unchanged.")
        return
    app = Application(manager, args.origin, args.base_path, args.demo)
    app.start_background()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.daemon_threads = True
    server.application = app
    print("Node Console is listening on its private local port.", flush=True)
    server.serve_forever()




def _compat_unlink_if_exists(path):
    # Path.unlink(missing_ok=True) was introduced after Python 3.6.
    try:
        path.unlink()
    except FileNotFoundError:
        pass


if __name__ == "__main__":
    main()
