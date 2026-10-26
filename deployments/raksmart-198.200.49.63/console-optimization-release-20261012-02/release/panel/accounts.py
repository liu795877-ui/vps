"""Local accounts and isolated Xray instances for the node console.

The existing administrator remains in auth.private.json. Member passwords and
instance metadata live in a separate private registry; no proxy credentials or
rule capabilities are returned by the account API.
"""

import base64
import copy
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import threading
import time
import uuid

from panel import ports as entrances
from panel import subscriptions, telemetry


MAX_USERS = 3
MEMBER_PORTS = entrances.DEFAULT_MEMBER_PORTS
CONFIG_ROOT = Path("/usr/local/etc/xray-members")
MEMBER_ID = re.compile(r"[a-f0-9]{16}\Z")
USERNAME = re.compile(r"[a-z][a-z0-9_-]{2,23}\Z")


def _server():
    # server.Application imports Accounts, so resolve the dependency at runtime.
    from panel import server
    return server


def _private_directory(path):
    path = Path(path)
    if path.is_symlink():
        raise _server().PanelError("用户数据目录需要检查，操作已停止。", 409)
    path.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(path, 0o700)
    return path


def _password(value):
    if (not isinstance(value, str) or not 12 <= len(value) <= 128
            or not value.strip() or any(ord(char) < 32 for char in value)):
        raise _server().PanelError("密码需要 12 至 128 个字符，不能包含控制字符。")
    try:
        value.encode("utf-8")
    except UnicodeError as error:
        raise _server().PanelError("密码包含不支持的字符。") from error
    return value


class Accounts:
    def __init__(self, owner_manager, owner_auth_path, demo=False):
        self.owner_manager = owner_manager
        self.owner_auth_path = Path(owner_auth_path)
        self.users_path = owner_manager.directory / "users.private.json"
        self.entrance_pool_path = owner_manager.directory / "entrance-pool.private.json"
        self.directory = owner_manager.directory / "users"
        self.demo = bool(demo)
        self.lock = threading.RLock()
        self._managers = {"admin": owner_manager}
        if self.owner_auth_path.is_symlink() or self.users_path.is_symlink():
            raise _server().PanelError("用户账号文件需要检查，操作已停止。", 409)
        self.owner_auth = json.loads(self.owner_auth_path.read_text(encoding="utf-8"))
        if not isinstance(self.owner_auth.get("username"), str):
            raise _server().PanelError("管理员账号文件需要检查。", 500)
        self.member_ports = self._load_entrances()
        if self.users_path.exists():
            data = json.loads(self.users_path.read_text(encoding="utf-8"))
        else:
            data = {"version": 1, "users": []}
            _server().atomic_write(self.users_path, _server().json_bytes(data))
        self._validate_registry(data)
        self.records = data["users"]

    def _owner_port(self):
        return self.owner_manager.state["base"]["inbounds"][0]["port"]

    def _load_entrances(self):
        server = _server()
        if self.entrance_pool_path.is_symlink():
            raise server.PanelError("入口资源池文件需要检查。", 409)
        try:
            if self.entrance_pool_path.exists():
                data = json.loads(self.entrance_pool_path.read_text(encoding="utf-8"))
                if (not isinstance(data, dict) or set(data) != {"version", "member_ports"}
                        or data.get("version") != 1):
                    raise ValueError("Invalid entrance pool")
                values = data["member_ports"]
            else:
                values = MEMBER_PORTS
            return entrances.validate_member_ports(values, self._owner_port())
        except (OSError, ValueError, TypeError, KeyError) as error:
            raise server.PanelError("入口资源池记录需要检查。", 500) from error

    def entrance_summary(self):
        """Expose allocation state without secrets or a false reachability claim."""
        with self.lock:
            records = [self._record("admin")] + self.records
            assigned = {record["port"]: record for record in records}
            allocations = []
            for port in (self._owner_port(),) + self.member_ports:
                record = assigned.get(port)
                item = {"port": port, "assigned": record is not None,
                        "status": ("assigned" if record["enabled"] else "disabled")
                        if record is not None else "available"}
                if record is not None:
                    item["username"] = record["username"]
                allocations.append(item)
            return {"capacity": len(self.member_ports) + 1,
                    "total_users": len(records),
                    "available_count": len(self.member_ports) - len(self.records),
                    "member_ports": list(self.member_ports),
                    "supported_member_ports": list(entrances.SUPPORTED_MEMBER_PORTS),
                    "allocations": allocations,
                    "firewall_text": entrances.firewall_text((self._owner_port(),) + self.member_ports),
                    "public_verification": "not_checked"}

    def configure_entrances(self, request):
        server = _server()
        if (not isinstance(request, dict) or set(request) - {"member_ports", "cloud_confirmed"}
                or not isinstance(request.get("member_ports"), list)
                or type(request.get("cloud_confirmed", False)) is not bool):
            raise server.PanelError("请提供成员入口列表和云端放行确认。")
        with self.lock:
            try:
                candidate = entrances.validate_member_ports(request["member_ports"], self._owner_port())
            except ValueError as error:
                raise server.PanelError(str(error), 409) from error
            occupied = {record["port"] for record in self.records}
            if occupied - set(candidate):
                raise server.PanelError("已分配给成员的入口不能移除，请先删除对应成员。", 409)
            added = set(candidate) - set(self.member_ports)
            if added and request.get("cloud_confirmed") is not True:
                raise server.PanelError("请先在云安全组和本机防火墙放行新增 TCP/UDP 入口，再确认扩容。", 409)
            if added and not self.demo:
                try:
                    entrances.probe_available(sorted(added))
                except OSError as error:
                    raise server.PanelError(str(error) + " 未修改入口资源池。", 409) from error
            if self.entrance_pool_path.is_symlink():
                raise server.PanelError("入口资源池文件需要检查，操作已停止。", 409)
            server.atomic_write(self.entrance_pool_path, server.json_bytes(
                {"version": 1, "member_ports": list(candidate)}))
            self.member_ports = candidate
            return self.entrance_summary()

    def _validate_registry(self, data):
        server = _server()
        if (not isinstance(data, dict) or data.get("version") != 1
                or not isinstance(data.get("users"), list)
                or len(data["users"]) > len(self.member_ports)):
            raise server.PanelError("用户账号记录需要检查。", 500)
        ids, ports = set(), set()
        names = {self.owner_auth["username"].casefold()}
        for record in data["users"]:
            if not isinstance(record, dict):
                raise server.PanelError("用户账号记录需要检查。", 500)
            identity = record.get("id")
            username = record.get("username")
            port = record.get("port")
            auth = record.get("auth")
            if (not isinstance(identity, str) or not MEMBER_ID.fullmatch(identity)
                    or identity in ids or not isinstance(username, str)
                    or not USERNAME.fullmatch(username) or username.casefold() in names
                    or type(port) is not int or port not in self.member_ports or port in ports
                    or record.get("role") != "member" or type(record.get("enabled")) is not bool
                    or not isinstance(record.get("display_name"), str)
                    or not 1 <= len(record["display_name"].strip()) <= 48
                    or any(ord(char) < 32 for char in record["display_name"])
                    or not isinstance(auth, dict) or auth.get("username") != username
                    or not isinstance(auth.get("iterations"), int)
                    or not 100000 <= auth["iterations"] <= 2000000
                    or not isinstance(auth.get("salt"), str)
                    or not re.fullmatch(r"[a-f0-9]{48}", auth["salt"])
                    or not isinstance(auth.get("hash"), str)
                    or not re.fullmatch(r"[a-f0-9]{64}", auth["hash"])):
                raise server.PanelError("用户账号记录需要检查。", 500)
            ids.add(identity)
            ports.add(port)
            names.add(username.casefold())

    def _record(self, user_id):
        if user_id == "admin":
            return {"id": "admin", "username": self.owner_auth["username"],
                    "display_name": "管理员", "role": "admin", "enabled": True,
                    "port": self.owner_manager.state["base"]["inbounds"][0]["port"]}
        if not isinstance(user_id, str) or not MEMBER_ID.fullmatch(user_id):
            raise _server().PanelError("没有找到这个用户。", 404)
        record = next((item for item in self.records if item["id"] == user_id), None)
        if record is None:
            raise _server().PanelError("没有找到这个用户。", 404)
        return record

    def _paths(self, record):
        identity = record["id"]
        if not MEMBER_ID.fullmatch(identity):
            raise _server().PanelError("用户标识需要检查。", 500)
        directory = self.directory / identity
        config_directory = directory if self.demo else CONFIG_ROOT / identity
        return directory, config_directory / "config.json"

    @staticmethod
    def _service(record):
        return "xray-panel@" + record["id"] + ".service"

    def _manager(self, record):
        if record["id"] == "admin":
            return self.owner_manager
        identity = record["id"]
        manager = self._managers.get(identity)
        if manager is None:
            directory, config_path = self._paths(record)
            if (directory.is_symlink() or config_path.parent.is_symlink()
                    or config_path.is_symlink() or (directory / "state.private.json").is_symlink()
                    or not (directory / "state.private.json").is_file()
                    or not config_path.is_file()):
                raise _server().PanelError("这个用户的独立节点文件需要检查。", 409)
            self._validate_member_files(record, directory, config_path)
            manager = _server().Manager(
                directory, self.owner_manager.public_ip, config_path, demo=self.demo,
                origin=self.owner_manager.origin, base_path=self.owner_manager.base_path,
                service_name=self._service(record),
            )
            self._managers[identity] = manager
        manager.account_enabled = record["enabled"]
        manager.disabled = not record["enabled"]
        manager.acceleration = getattr(self, "acceleration", None)
        manager.account_id = record["id"]
        manager.telemetry_source = getattr(self, "telemetry", None)
        return manager

    def _validate_member_files(self, record, directory, config_path):
        server = _server()
        try:
            state = json.loads((directory / "state.private.json").read_text(encoding="utf-8"))
            payload = config_path.read_bytes()
            running = json.loads(payload)
            telemetry.validate_augmentation(state["base"], allow_legacy=True)
            telemetry.validate_augmentation(running, allow_legacy=True)
            inbound = state["base"]["inbounds"][0]
            current = running["inbounds"][0]
            expected_ids = {str(uuid.UUID(inbound["settings"]["clients"][0]["id"])),
                            str(uuid.UUID(state["auto_id"]))}
            expected_ids.update(str(uuid.UUID(item["client_id"])) for item in state["applied_exits"])
            actual_ids = {str(uuid.UUID(item["id"])) for item in current["settings"]["clients"]}
            acceleration = getattr(self, "acceleration", None)
            if acceleration and acceleration.enabled:
                acceleration.validate_running(record, running)
            elif len(running["inbounds"]) != 1:
                raise ValueError("Unmanaged transport inbound")
            if (len(state["base"]["inbounds"]) != 1
                    or inbound["port"] != record["port"] or current["port"] != record["port"]
                    or inbound["protocol"] != "vless" or current["protocol"] != "vless"
                    or inbound["streamSettings"]["security"] != "reality"
                    or current["streamSettings"] != inbound["streamSettings"]
                    or actual_ids != expected_ids
                    or len(current["settings"]["clients"]) != len(expected_ids)
                    or state["managed_hash"] != server.digest(payload)
                    or not isinstance(state["rule_token"], str) or len(state["rule_token"]) < 32
                    or not isinstance(state["public"], str)
                    or not re.fullmatch(r"[A-Za-z0-9_-]{43}", state["public"])):
                raise ValueError("member identity or configuration mismatch")
        except (OSError, ValueError, TypeError, KeyError, IndexError) as error:
            raise server.PanelError("这个用户的独立节点配置需要检查，操作已停止。", 409) from error

    def manager(self, user_id):
        with self.lock:
            record = self._record(user_id)
            if not record["enabled"]:
                raise _server().PanelError("这个账号已停用，请联系管理员。", 403)
            return self._manager(record)

    def _public(self, record):
        manager = self._manager(record)
        with manager.lock:
            state = manager.state
            result = {key: record[key] for key in
                      ("id", "username", "display_name", "role", "enabled", "port")}
            result.update(exit_count=len(state["exits"]),
                          active_target="server" if state["active_id"] in (None, "server") else "static")
        result["service_active"] = (bool(record["enabled"]) if self.demo else
            _server().base.command(["systemctl", "is-active", "--quiet",
                                   getattr(manager, "service_name", "xray.service")], check=False).returncode == 0)
        acceleration = getattr(self, "acceleration", None)
        has_hy2 = bool(acceleration and acceleration.enabled and acceleration.has_record(record))
        result["hy2_port"] = record["port"] if has_hy2 else None
        result["hy2_service_active"] = bool(record["enabled"]) if has_hy2 and self.demo else None
        return result

    def get(self, user_id):
        with self.lock:
            return self._public(self._record(user_id))

    def list_users(self):
        with self.lock:
            return [self._public(self._record("admin"))] + [self._public(item) for item in self.records]

    def authenticate(self, username, password):
        """Return a safe user dictionary on success and None on failed login."""
        if (not isinstance(username, str) or not isinstance(password, str)
                or len(username) > 128 or len(password) > 128):
            return None
        try:
            password.encode("utf-8")
        except UnicodeError:
            return None
        with self.lock:
            record = (self._record("admin") if username == self.owner_auth["username"] else
                      next((item for item in self.records if item["username"] == username), None))
            # Hash unknown usernames too, to avoid a fast username-existence check.
            auth = (self.owner_auth if record is None or record["id"] == "admin"
                    else record["auth"])
            matched = _server().password_matches(password, auth)
            if record is None or not record["enabled"] or not matched:
                return None
            return self._public(record)

    def _save(self, records):
        _server().atomic_write(self.users_path, _server().json_bytes({"version": 1, "users": records}))
        self.records = records

    def _keys(self):
        if self.demo:
            return tuple(base64.urlsafe_b64encode(os.urandom(32)).decode("ascii").rstrip("=")
                         for _ in range(2))
        server = _server()
        return server.base.parse_keys(server.base.command([str(server.base.XRAY), "x25519"]).stdout)

    def _new_state(self, port):
        server = _server()
        private, public = self._keys()
        with self.owner_manager.lock:
            config = copy.deepcopy(self.owner_manager.state["base"])
        inbound = config["inbounds"][0]
        if (inbound.get("protocol") != "vless"
                or inbound.get("streamSettings", {}).get("security") != "reality"):
            raise server.PanelError("基础 REALITY 节点需要检查，未创建用户。", 409)
        config["inbounds"] = [inbound]
        inbound["port"] = port
        inbound["listen"] = "0.0.0.0"
        inbound["settings"]["clients"] = [{"id": str(uuid.uuid4()), "flow": "xtls-rprx-vision"}]
        short = secrets.token_hex(8)
        reality = inbound["streamSettings"]["realitySettings"]
        reality.update(privateKey=private, shortIds=[short])
        if "api" in config:
            config = telemetry.augment_config(config, port)
        state = {"base": config, "public": public, "short": short,
                 "auto_id": str(uuid.uuid4()), "rule_token": secrets.token_urlsafe(32),
                 "exits": [], "applied_exits": [], "active_id": "server",
                 "domains": [], "direct_domains": [], "applied_domains": [],
                 "applied_direct_domains": [], "routing_mode": "smart",
                 "applied_routing_mode": "smart", "history": [], "updated": server.now()}
        candidate, profile = self.owner_manager.build(state, "server")
        payload = server.json_bytes(candidate)
        state.update(profile=profile, managed_hash=server.digest(payload))
        subscriptions.ensure_metadata(state)
        return state, payload

    def _wait_ready(self, record):
        server = _server()
        for _ in range(20):
            if server.base.command(["systemctl", "is-active", "--quiet", self._service(record)],
                                   check=False).returncode == 0:
                try:
                    with socket.create_connection(("127.0.0.1", record["port"]), timeout=0.5):
                        return
                except OSError:
                    pass
            time.sleep(0.25)
        raise server.PanelError("独立节点未能启动，已撤销这个用户的创建。", 500)

    def _start(self, record):
        if not self.demo:
            server = _server()
            server.base.command(["systemctl", "enable", self._service(record)])
            server.base.command(["systemctl", "start", self._service(record)])
            self._wait_ready(record)
        acceleration = getattr(self, "acceleration", None)
        if acceleration and acceleration.enabled:
            # Enabling a member uses the requested future state before the
            # account registry commits its new enabled flag.
            acceleration.start(dict(record, enabled=True))

    def _stop(self, record):
        telemetry_source = getattr(self, "telemetry", None)
        if telemetry_source and any(item["id"] == record["id"] for item in self.records):
            telemetry_source.sample_user(record["id"])
        acceleration = getattr(self, "acceleration", None)
        if acceleration and acceleration.enabled:
            acceleration.stop(record)
        if not self.demo:
            server = _server()
            server.base.command(["systemctl", "stop", self._service(record)])
            server.base.command(["systemctl", "disable", self._service(record)])

    def _remove_created(self, directory, config_path, created_state, created_config):
        # These exact directories were created with mkdir(exist_ok=False) below;
        # no pre-existing resource is eligible for this rollback.
        for target, parent, created in ((directory, self.directory, created_state),
                                        (config_path.parent, CONFIG_ROOT, created_config and not self.demo)):
            if created and target.exists() and not target.is_symlink():
                if target.resolve().parent != parent.resolve():
                    raise _server().PanelError("用户目录清理需要检查。", 500)
                shutil.rmtree(target)

    def create_user(self, request, progress=None):
        server = _server()
        def report(stage, message):
            # Progress is an observer. A notification failure must not undo a
            # successfully committed account or change its allocation.
            if progress is not None:
                try:
                    progress(stage, message)
                except Exception:
                    pass
        report("validating", "正在核对成员资料和入口容量。")
        if not isinstance(request, dict) or set(request) - {"username", "password", "display_name"}:
            raise server.PanelError("只需要填写用户名、显示名称和登录密码，入口由服务器分配。")
        username = request.get("username")
        if not isinstance(username, str) or not USERNAME.fullmatch(username):
            raise server.PanelError("用户名需要 3 至 24 位小写字母、数字、下划线或短横线，并以字母开头。")
        password = _password(request.get("password"))
        display = request.get("display_name", username)
        if (not isinstance(display, str) or not 1 <= len(display.strip()) <= 48
                or any(ord(char) < 32 for char in display)):
            raise server.PanelError("显示名称需要 1 至 48 个字符。")
        try:
            display.encode("utf-8")
        except UnicodeError as error:
            raise server.PanelError("显示名称包含不支持的字符。") from error
        with self.lock:
            if len(self.records) >= len(self.member_ports):
                raise server.PanelError("入口资源池已满，请先准备并确认放行新的成员入口。", 409)
            if username.casefold() in {self.owner_auth["username"].casefold()} | {
                    item["username"].casefold() for item in self.records}:
                raise server.PanelError("用户名已存在，请换一个用户名。", 409)
            report("allocating", "正在分配独立入口并检查内部端口。")
            port = next(value for value in self.member_ports if value not in {item["port"] for item in self.records})
            if not self.demo:
                try:
                    entrances.validate_topology((self._owner_port(),) + self.member_ports)
                    entrances.probe_available((port,))
                except OSError as error:
                    raise server.PanelError(str(error) + " 未创建用户。", 409) from error
            auth = server.password_record(password)
            auth["username"] = username
            record = {"id": secrets.token_hex(8), "username": username,
                      "display_name": display.strip(), "role": "member", "enabled": True,
                      "port": port, "created": server.now(), "auth": auth}
            directory, config_path = self._paths(record)
            _private_directory(self.directory)
            if not self.demo:
                _private_directory(CONFIG_ROOT)
            if directory.exists() or directory.is_symlink() or config_path.parent.is_symlink():
                raise server.PanelError("用户目录已存在，未修改已有文件。", 409)
            created_state = created_config = started = False
            candidate_path = config_path.with_name("candidate.private.json")
            acceleration = getattr(self, "acceleration", None)
            acceleration_snapshot = acceleration.snapshot_registry() if acceleration else None
            original_registry = self.users_path.read_bytes()
            original_records = copy.deepcopy(self.records)
            try:
                report("configuration", "正在生成独立身份与节点配置。")
                if acceleration:
                    acceleration.prepare(record)
                state, payload = self._new_state(port)
                directory.mkdir(mode=0o700)
                created_state = True
                if not self.demo:
                    config_path.parent.mkdir(mode=0o700)
                    created_config = True
                    server.atomic_write(candidate_path, payload)
                    server.base.command([str(server.base.XRAY), "run", "-test", "-config", str(candidate_path)])
                server.atomic_write(config_path, payload)
                server.atomic_write(directory / "state.private.json", server.json_bytes(state))
                if candidate_path.exists():
                    candidate_path.unlink()
                self._manager(record)
                # Treat enable/start as potentially partial, so rollback stops the
                # new instance even if systemctl raises before reporting success.
                started = True
                report("services", "正在启动独立代理服务。")
                self._start(record)
                report("local_ready", "本机服务准备完成；公网连接仍需外部验证。")
                result = self._public(record)
                self._save(self.records + [record])
                report("complete", "成员已创建，可以交付登录资料并验证连接。")
                return result
            except Exception as error:
                if started:
                    try:
                        self._stop(record)
                    except Exception as stop_error:
                        raise server.PanelError("新用户启动失败，独立服务清理需要检查。", 500) from stop_error
                self._managers.pop(record["id"], None)
                self._remove_created(directory, config_path, created_state, created_config)
                if acceleration:
                    acceleration.restore_registry(acceleration_snapshot)
                    acceleration.remove_runtime(record)
                if self.users_path.read_bytes() != original_registry:
                    server.atomic_write(self.users_path, original_registry)
                self.records = original_records
                if isinstance(error, server.PanelError):
                    raise
                raise server.PanelError("创建用户失败，原有账号和出口已保留。", 500) from error

    def _replace_password(self, user_id, password):
        server = _server()
        record = self._record(user_id)
        auth = server.password_record(_password(password))
        auth["username"] = record["username"]
        if user_id == "admin":
            server.atomic_write(self.owner_auth_path, server.json_bytes(auth))
            self.owner_auth = auth
        else:
            records = copy.deepcopy(self.records)
            next(item for item in records if item["id"] == user_id)["auth"] = auth
            self._save(records)
        return self._public(self._record(user_id))

    def reset_password(self, user_id, password):
        with self.lock:
            return self._replace_password(user_id, password)

    def change_password(self, user_id, current, new):
        with self.lock:
            record = self._record(user_id)
            auth = self.owner_auth if user_id == "admin" else record["auth"]
            if not isinstance(current, str) or len(current) > 128:
                raise _server().PanelError("当前密码不正确。", 403)
            try:
                valid = _server().password_matches(current, auth)
            except UnicodeError:
                valid = False
            if not valid:
                raise _server().PanelError("当前密码不正确。", 403)
            return self._replace_password(user_id, new)

    def set_enabled(self, user_id, enabled):
        server = _server()
        if type(enabled) is not bool:
            raise server.PanelError("请设置有效的账号状态。")
        with self.lock:
            record = self._record(user_id)
            if user_id == "admin":
                raise server.PanelError("管理员账号不能停用。", 403)
            manager = self._manager(record)
            if record["enabled"] == enabled:
                return self._public(record)
            if not manager.operation.acquire(blocking=False):
                raise server.PanelError("这个用户正在测试或切换出口，请完成后再设置账号状态。", 409)
            changed_runtime = False
            previously_disabled = manager.disabled
            try:
                if not enabled:
                    manager.disabled = True
                changed_runtime = True
                (self._start if enabled else self._stop)(record)
                records = copy.deepcopy(self.records)
                updated = next(item for item in records if item["id"] == user_id)
                updated["enabled"] = enabled
                result = self._public(updated)
                self._save(records)
                manager.account_enabled = enabled
                manager.disabled = not enabled
                return result
            except Exception as error:
                manager.disabled = previously_disabled
                manager.account_enabled = record["enabled"]
                if changed_runtime:
                    try:
                        (self._start if record["enabled"] else self._stop)(record)
                    except Exception as restore_error:
                        raise server.PanelError("账号设置失败，独立节点恢复需要检查。", 500) from restore_error
                if isinstance(error, server.PanelError):
                    raise
                raise server.PanelError("账号状态设置失败，已恢复原有设置。", 500) from error
            finally:
                manager.operation.release()

    def _delete_targets(self, record):
        """Resolve the two directories belonging to this exact member only."""
        directory, config_path = self._paths(record)
        targets = [(directory, self.directory)]
        if not self.demo:
            targets.append((config_path.parent, CONFIG_ROOT))
        for target, parent in targets:
            if (target.is_symlink() or parent.is_symlink() or not target.is_dir()
                    or target.resolve().parent != parent.resolve()
                    or target.name != record["id"]):
                raise _server().PanelError("用户目录需要检查，未删除账号。", 409)
        return targets

    def delete_user(self, user_id):
        """Revoke one member and release its slot after a reversible commit.

        Renaming into private sibling directories preserves complete rollback
        until the registry commits. A cleanup failure after commit leaves only
        inaccessible private files, never a partially restored live account.
        """
        server = _server()
        with self.lock:
            record = self._record(user_id)
            if user_id == "admin":
                raise server.PanelError("管理员账号不能删除。", 403)
            manager = self._manager(record)
            targets = self._delete_targets(record)
            original_records = copy.deepcopy(self.records)
            original_registry = self.users_path.read_bytes()
            acceleration = getattr(self, "acceleration", None)
            acceleration_snapshot = acceleration.snapshot_registry() if acceleration else None
            if not manager.operation.acquire(blocking=False):
                raise server.PanelError("这个用户正在测试或切换出口，请完成后再删除。", 409)
            previously_disabled = manager.disabled
            changed_runtime = False
            moved = []
            committed = False
            try:
                manager.disabled = True
                changed_runtime = True
                self._stop(record)
                if acceleration:
                    acceleration.forget(record)
                for target, parent in targets:
                    quarantine = parent / (".deleted-" + record["id"] + "-" + secrets.token_hex(8))
                    if quarantine.exists() or quarantine.is_symlink():
                        raise server.PanelError("用户清理目录已存在，未删除账号。", 409)
                    os.replace(str(target), str(quarantine))
                    moved.append((target, quarantine, parent))
                self._save([item for item in self.records if item["id"] != user_id])
                committed = True
                self._managers.pop(user_id, None)
            except Exception as error:
                try:
                    for target, quarantine, parent in reversed(moved):
                        if (target.exists() or target.is_symlink() or quarantine.is_symlink()
                                or quarantine.resolve().parent != parent.resolve()):
                            raise RuntimeError("Member deletion rollback path changed")
                        os.replace(str(quarantine), str(target))
                    if self.users_path.read_bytes() != original_registry:
                        server.atomic_write(self.users_path, original_registry)
                    self.records = original_records
                    if acceleration:
                        acceleration.restore_registry(acceleration_snapshot, [record])
                    manager.disabled = previously_disabled
                    if changed_runtime:
                        (self._start if record["enabled"] else self._stop)(record)
                except Exception as restore_error:
                    raise server.PanelError("删除未完成，这个用户的独立节点恢复需要检查。", 500) from restore_error
                if isinstance(error, server.PanelError):
                    raise
                raise server.PanelError("删除失败，已恢复这个用户的账号和文件。", 500) from error
            finally:
                if not committed:
                    manager.disabled = previously_disabled
                manager.operation.release()
            cleanup_pending = False
            for target, quarantine, parent in moved:
                try:
                    # Check the absolute boundary again immediately before the
                    # only recursive removal in this operation.
                    if (quarantine.is_symlink() or quarantine.resolve().parent != parent.resolve()
                            or not quarantine.name.startswith(".deleted-" + record["id"] + "-")):
                        raise RuntimeError("Member cleanup path changed")
                    shutil.rmtree(str(quarantine))
                except OSError:
                    cleanup_pending = True
                except RuntimeError:
                    cleanup_pending = True
            return {"id": user_id, "deleted": True, "cleanup_pending": cleanup_pending}

    def _ensure_profile_metadata(self, manager):
        with manager.lock:
            state = copy.deepcopy(manager.state)
            if subscriptions.ensure_metadata(state):
                manager.save(state)

    def profile_metadata(self, user_id, include_url=True):
        with self.lock:
            manager = self.manager(user_id)
            self._ensure_profile_metadata(manager)
            with manager.lock:
                return subscriptions.metadata(manager.state, manager.origin, manager.base_path, include_url)

    def rotate_subscription_token(self, user_id):
        server = _server()
        with self.lock:
            manager = self.manager(user_id)
            if not manager.operation.acquire(blocking=False):
                raise server.PanelError("正在测试或应用配置，请完成后再重置订阅链接。", 409)
            try:
                with manager.lock:
                    state = copy.deepcopy(manager.state)
                    state["profile_token"] = secrets.token_urlsafe(32)
                    subscriptions.update_metadata(state, manager.state)
                    manager.save(state)
                    return subscriptions.metadata(state, manager.origin, manager.base_path)
            finally:
                manager.operation.release()

    def subscription_profile(self, token):
        """Read a full profile via an enabled account's independent capability."""
        if not subscriptions.valid_token(token):
            raise _server().PanelError("页面不存在。", 404)
        supplied = token.encode("ascii")
        with self.lock:
            for record in [self._record("admin")] + self.records:
                if not record["enabled"]:
                    continue
                manager = self._manager(record)
                self._ensure_profile_metadata(manager)
                with manager.lock:
                    expected = manager.state["profile_token"].encode("ascii")
                    if hmac.compare_digest(supplied, expected) and manager.state.get("profile"):
                        return manager.state["profile"]
        raise _server().PanelError("页面不存在。", 404)

    def _install_offline(self, manager, original, payload):
        """Validate and replace a manually disabled member without starting it."""
        server = _server()
        candidate = manager.directory / ("credentials-" + secrets.token_hex(8) + ".private.json")
        try:
            if not self.demo:
                server.atomic_write(candidate, payload)
                server.base.command([str(server.base.XRAY), "run", "-test", "-config", str(candidate)])
            if manager.config_path.is_symlink() or manager.config_path.read_bytes() != original:
                raise server.PanelError("独立节点配置已被其他操作修改，重置已停止。", 409)
            server.atomic_write(manager.config_path, payload)
        finally:
            if candidate.exists():
                candidate.unlink()

    def rotate_credentials(self, user_id):
        """Replace proxy identities and capabilities, preserving the web password."""
        server = _server()
        with self.lock:
            record = self._record(user_id)
            manager = self._manager(record)
            if not manager.operation.acquire(blocking=False):
                raise server.PanelError("这个用户正在测试或切换出口，请完成后再重置代理凭据。", 409)
            installed = False
            acceleration = getattr(self, "acceleration", None)
            acceleration_snapshot = acceleration.snapshot_registry() if acceleration else None
            acceleration_changed = False
            try:
                telemetry_source = getattr(self, "telemetry", None)
                if telemetry_source:
                    telemetry_source.sample_user(user_id)
                with manager.lock:
                    original_state = copy.deepcopy(manager.state)
                    original_state_bytes = manager.state_path.read_bytes()
                    original = manager.config_path.read_bytes()
                    if (manager.config_path.is_symlink()
                            or server.digest(original) != original_state["managed_hash"]):
                        raise server.PanelError("独立节点配置已被其他操作修改，重置已停止。", 409)
                    state = copy.deepcopy(original_state)
                    for client in state["base"]["inbounds"][0]["settings"]["clients"]:
                        client["id"] = str(uuid.uuid4())
                    state["auto_id"] = str(uuid.uuid4())
                    identities = {}
                    for collection in (state["exits"], state["applied_exits"]):
                        for item in collection:
                            if item["id"] not in identities:
                                identities[item["id"]] = str(uuid.uuid4())
                            item["client_id"] = identities[item["id"]]
                    state["rule_token"] = secrets.token_urlsafe(32)
                    state["profile_token"] = secrets.token_urlsafe(32)
                    # Config history carries old UUIDs and rule capabilities.
                    # It must not make a revoked identity usable again.
                    state["history"] = []
                    running = copy.deepcopy(state)
                    running["exits"] = copy.deepcopy(state["applied_exits"])
                    if acceleration and acceleration.enabled:
                        acceleration_changed = True
                        acceleration.stop(record)
                        acceleration.rotate(record)
                    config, profile = manager.build(running, state["active_id"])
                    payload = server.json_bytes(config)
                    state.update(profile=profile, managed_hash=server.digest(payload), updated=server.now(),
                                 credentials_rotated_at=server.now())
                    subscriptions.update_metadata(state, original_state)
                    if record["enabled"]:
                        manager.install(original, payload, profile)
                    else:
                        self._install_offline(manager, original, payload)
                    installed = True
                    try:
                        manager.save(state)
                        if acceleration_changed and record["enabled"]:
                            acceleration.start(record)
                    except Exception:
                        if acceleration_changed:
                            acceleration.stop(record)
                            acceleration.restore_registry(acceleration_snapshot, [record])
                        if record["enabled"]:
                            manager.install(payload, original, original_state.get("profile") or "rollback")
                        else:
                            self._install_offline(manager, payload, original)
                        if manager.state_path.read_bytes() != original_state_bytes:
                            server.atomic_write(manager.state_path, original_state_bytes)
                        manager.state = original_state
                        installed = False
                        if acceleration_changed and record["enabled"]:
                            acceleration.start(record)
                        acceleration_changed = False
                        raise
                    result = subscriptions.metadata(state, manager.origin, manager.base_path)
                    result.update(id=user_id, credentials_rotated=True, rollback_cleared=True)
                    return result
            except Exception as error:
                if acceleration_changed and not installed:
                    try:
                        acceleration.restore_registry(acceleration_snapshot, [record])
                        if record["enabled"]:
                            acceleration.start(record)
                    except Exception as restore_error:
                        raise server.PanelError("代理凭据重置失败，加速入口恢复需要检查。", 500) from restore_error
                if isinstance(error, server.PanelError):
                    raise
                message = ("代理凭据已更新，但这个用户的状态文件恢复需要检查。" if installed else
                           "代理凭据重置失败，原有账号和出口已保留。")
                raise server.PanelError(message, 500) from error
            finally:
                manager.operation.release()

    def rule_snapshot(self, token, direction):
        if not isinstance(token, str) or direction not in ("direct", "proxy"):
            raise _server().PanelError("页面不存在。", 404)
        try:
            supplied = token.encode("utf-8")
        except UnicodeError as error:
            raise _server().PanelError("页面不存在。", 404) from error
        with self.lock:
            for record in [self._record("admin")] + self.records:
                if not record["enabled"]:
                    continue
                manager = self._manager(record)
                with manager.lock:
                    expected = manager.state["rule_token"].encode("utf-8")
                if hmac.compare_digest(supplied, expected):
                    return manager.rule_snapshot(token, direction)
        raise _server().PanelError("页面不存在。", 404)
