"""Authenticated encrypted system snapshots with a strict logical-path manifest.

Daily snapshots use a private local key. Portable downloads are re-encrypted
with a user password and can be validated on another host; restore deliberately
requires the same node identity until an explicit migration workflow exists.
No archive-controlled filename ever becomes a filesystem path.
"""

import base64
from contextlib import contextmanager
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import threading
import time
import uuid


MAX_ARCHIVE = 32 * 1024 * 1024
MAX_PLAINTEXT = 24 * 1024 * 1024
ITERATIONS = 600000
BACKUP_ID = re.compile(r"[a-f0-9]{32}\Z")
MEMBER_ID = re.compile(r"[a-f0-9]{16}\Z")
EXTRAS = ("base.private.yaml", "traffic.private.json", "operations.private.json",
          "health.private.json", "audit.private.json", "audit.private.jsonl",
          "activity.private.jsonl", "subscriptions.private.json", "backup-settings.private.json")


def _server():
    from panel import server
    return server


def _b64(data):
    return base64.b64encode(data).decode("ascii")


def _decode(value, maximum=MAX_ARCHIVE):
    if not isinstance(value, str) or len(value) > maximum * 4 // 3 + 8:
        raise ValueError("Invalid encoded data size")
    result = base64.b64decode(value.encode("ascii"), validate=True)
    if len(result) > maximum:
        raise ValueError("Decoded data is too large")
    return result


def _crypto():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.backends import default_backend
        return AESGCM, hashes, PBKDF2HMAC, default_backend
    except ImportError as error:
        raise _server().PanelError("加密备份依赖尚未安装，请联系管理员完成部署。", 503) from error


def _password(value):
    if (not isinstance(value, str) or not 12 <= len(value) <= 128 or not value.strip()
            or any(ord(char) < 32 for char in value)):
        raise _server().PanelError("备份密码需要 12 至 128 个字符，不能包含控制字符。")
    try:
        return value.encode("utf-8")
    except UnicodeError as error:
        raise _server().PanelError("备份密码包含不支持的字符。") from error


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def encrypt(payload, master_key=None, password=None):
    AESGCM, hashes, PBKDF2HMAC, backend = _crypto()
    if len(payload) > MAX_PLAINTEXT:
        raise _server().PanelError("系统备份超过安全大小限制。", 413)
    portable = password is not None
    salt = os.urandom(16)
    nonce = os.urandom(12)
    header = {"format": "node-console-backup", "version": 1, "cipher": "AES-256-GCM",
              "portable": portable, "kdf": "PBKDF2-SHA256" if portable else "server-key",
              "iterations": ITERATIONS if portable else 0, "salt": _b64(salt), "nonce": _b64(nonce)}
    if portable:
        key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                        iterations=ITERATIONS, backend=backend()).derive(_password(password))
    else:
        if not isinstance(master_key, bytes) or len(master_key) != 32:
            raise ValueError("A 32-byte private backup key is required")
        key = master_key
    envelope = dict(header, data=_b64(AESGCM(key).encrypt(nonce, payload, _canonical(header))))
    return _canonical(envelope)


def decrypt(archive, master_key=None, password=None, require_portable=False):
    AESGCM, hashes, PBKDF2HMAC, backend = _crypto()
    try:
        if not isinstance(archive, bytes) or len(archive) > MAX_ARCHIVE:
            raise ValueError("Archive too large")
        envelope = json.loads(archive.decode("utf-8"))
        if (not isinstance(envelope, dict) or set(envelope) != {
                "format", "version", "cipher", "portable", "kdf", "iterations", "salt", "nonce", "data"}
                or envelope["format"] != "node-console-backup" or envelope["version"] != 1
                or envelope["cipher"] != "AES-256-GCM" or type(envelope["portable"]) is not bool):
            raise ValueError("Invalid envelope")
        portable = envelope["portable"]
        if require_portable and not portable:
            raise ValueError("Upload requires a portable encrypted backup")
        if (envelope["kdf"] != ("PBKDF2-SHA256" if portable else "server-key") or
                envelope["iterations"] != (ITERATIONS if portable else 0)):
            raise ValueError("Unsupported password derivation parameters")
        salt, nonce = _decode(envelope["salt"], 16), _decode(envelope["nonce"], 12)
        if len(salt) != 16 or len(nonce) != 12:
            raise ValueError("Invalid cipher parameters")
        if portable:
            key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                            iterations=ITERATIONS, backend=backend()).derive(_password(password))
        else:
            if not isinstance(master_key, bytes) or len(master_key) != 32:
                raise ValueError("Missing local key")
            key = master_key
        header = {key: value for key, value in envelope.items() if key != "data"}
        result = AESGCM(key).decrypt(nonce, _decode(envelope["data"]), _canonical(header))
        if len(result) > MAX_PLAINTEXT:
            raise ValueError("Plaintext too large")
        return result
    except _server().PanelError:
        raise
    except Exception as error:
        raise _server().PanelError("备份密码不正确，或备份文件已损坏。") from error


class BackupManager:
    def __init__(self, accounts, operation_lock=None, runtime=None, clock=None, validate_config=None):
        self.accounts = accounts
        self.directory = accounts.owner_manager.directory / "backups"
        self.key_path = accounts.owner_manager.directory / "backup-key.private.bin"
        self.settings_path = accounts.owner_manager.directory / "backup-settings.private.json"
        self.operation_lock = operation_lock or threading.RLock()
        self.lock = threading.RLock()
        self.clock = clock or time.time
        self.runtime = runtime
        self.validate_config = validate_config
        self.downloads = {}
        self.previews = {}
        for target in (self.directory, self.key_path, self.settings_path):
            self._safe(target)
        self.directory.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            os.chmod(self.directory, 0o700)
        if self.key_path.exists():
            self.master_key = self.key_path.read_bytes()
        else:
            self.master_key = os.urandom(32)
            _server().atomic_write(self.key_path, self.master_key)
        if len(self.master_key) != 32:
            raise _server().PanelError("备份密钥文件需要检查。", 500)
        self.settings = json.loads(self.settings_path.read_text(encoding="utf-8")) if self.settings_path.exists() else {
            "enabled": True, "last_backup": None, "last_backup_time": 0, "last_error": None}

    @staticmethod
    def _safe(path):
        path = Path(path)
        for item in [path] + list(path.parents):
            if item.is_symlink():
                raise _server().PanelError("备份相关目录包含链接，已停止操作。", 409)
        return path

    @contextmanager
    def _locked(self):
        acquired = []
        with self.operation_lock, self.accounts.lock:
            records = [self.accounts._record("admin")] + list(self.accounts.records)
            managers = [self.accounts._manager(record) for record in records]
            try:
                for manager in managers:
                    if not manager.operation.acquire(blocking=False):
                        raise _server().PanelError("有用户正在检测或切换出口，请稍后备份或恢复。", 409)
                    acquired.append(manager.operation)
                yield records, managers
            finally:
                for operation in reversed(acquired):
                    operation.release()

    def _paths(self, records):
        owner = self.accounts.owner_manager
        result = {"admin/auth.json": self.accounts.owner_auth_path,
                  "admin/users.json": self.accounts.users_path,
                  "admin/state.json": owner.state_path,
                  "admin/config.json": owner.config_path}
        for name in EXTRAS:
            result["system/" + name] = owner.directory / name
        for record in records:
            if record["id"] == "admin":
                continue
            if not MEMBER_ID.fullmatch(record["id"]):
                raise _server().PanelError("用户标识需要检查。", 500)
            directory, config_path = self.accounts._paths(record)
            result["members/" + record["id"] + "/state.json"] = directory / "state.private.json"
            result["members/" + record["id"] + "/config.json"] = config_path
        return {name: self._safe(path) for name, path in result.items()}

    def _snapshot(self, records):
        files = {}
        for name, path in self._paths(records).items():
            if not path.exists():
                if not name.startswith("system/"):
                    raise _server().PanelError("完整备份所需的用户文件缺失。", 409)
                continue
            if not path.is_file():
                raise _server().PanelError("备份对象不是普通文件。", 409)
            payload = path.read_bytes()
            files[name] = {"sha256": hashlib.sha256(payload).hexdigest(), "data": _b64(payload),
                           "mode": path.stat().st_mode & 0o777,
                           "uid": path.stat().st_uid, "gid": path.stat().st_gid}
        owner = self.accounts.owner_manager
        return {"version": 1, "created_at": datetime.fromtimestamp(self.clock(), timezone.utc).isoformat(),
                "public_ip": owner.public_ip, "origin": owner.origin, "base_path": owner.base_path,
                "files": files}

    @staticmethod
    def _fingerprint(snapshot):
        return hashlib.sha256(_canonical({name: item["sha256"]
                                         for name, item in snapshot["files"].items()
                                         if not name.startswith("system/") or
                                         name == "system/subscriptions.private.json"})).hexdigest()

    def _metadata(self, backup_id):
        if not isinstance(backup_id, str) or not BACKUP_ID.fullmatch(backup_id):
            raise _server().PanelError("没有找到这个备份。", 404)
        path = self._safe(self.directory / (backup_id + ".json"))
        if not path.is_file():
            raise _server().PanelError("没有找到这个备份。", 404)
        metadata = json.loads(path.read_text(encoding="utf-8"))
        archive = self._safe(self.directory / (backup_id + ".nvbackup"))
        if not archive.is_file() or metadata.get("sha256") != hashlib.sha256(archive.read_bytes()).hexdigest():
            raise _server().PanelError("备份文件校验失败。", 409)
        return metadata, archive

    @staticmethod
    def _public_metadata(item):
        return {key: item[key] for key in ("id", "created_at", "size", "scope", "portable", "name")}

    def list(self):
        with self.lock:
            items = []
            for path in sorted(self.directory.glob("*.json")):
                if not BACKUP_ID.fullmatch(path.stem):
                    continue
                try:
                    item, unused = self._metadata(path.stem)
                    items.append(self._public_metadata(item))
                except (ValueError, OSError, _server().PanelError):
                    continue
            return {"backups": sorted(items, key=lambda item: item["created_at"], reverse=True),
                    "schedule": self.schedule_info(), "encryption": "AES-256-GCM"}

    def schedule_info(self):
        last = self.settings.get("last_backup_time", 0)
        return {"enabled": bool(self.settings.get("enabled", True)), "interval_hours": 24,
                "last_backup": self.settings.get("last_backup"),
                "next_backup": datetime.fromtimestamp(max(self.clock(), last + 86400), timezone.utc).isoformat(),
                "last_error": self.settings.get("last_error")}

    def schedule(self, enabled):
        if type(enabled) is not bool:
            raise _server().PanelError("请设置有效的备份计划。")
        with self.lock:
            self.settings["enabled"] = enabled
            _server().atomic_write(self.settings_path, _server().json_bytes(self.settings))
            return self.schedule_info()

    def create(self, name="", password=None, scheduled=False):
        if not isinstance(name, str) or len(name) > 64 or any(ord(char) < 32 for char in name):
            raise _server().PanelError("备份名称需要 0 至 64 个字符。")
        if password is not None:
            _password(password)
        with self._locked() as (records, unused), self.lock:
            snapshot = self._snapshot(records)
            self._validate_snapshot(snapshot)
            archive = encrypt(_canonical(snapshot), self.master_key, password)
            backup_id = secrets.token_hex(16)
            item = {"id": backup_id, "created_at": snapshot["created_at"], "size": len(archive),
                    "scope": "system", "portable": password is not None,
                    "name": name.strip() or ("每日自动备份" if scheduled else "手动完整备份"),
                    "sha256": hashlib.sha256(archive).hexdigest()}
            _server().atomic_write(self.directory / (backup_id + ".nvbackup"), archive)
            _server().atomic_write(self.directory / (backup_id + ".json"), _server().json_bytes(item))
            self.settings.update(last_backup=snapshot["created_at"], last_backup_time=self.clock(), last_error=None)
            _server().atomic_write(self.settings_path, _server().json_bytes(self.settings))
            return self._public_metadata(item)

    def export(self, backup_id, password):
        _password(password)
        with self.lock:
            item, path = self._metadata(backup_id)
            if item["portable"]:
                # A portable archive is already protected by its original
                # password; verify that password before exposing a download.
                payload = decrypt(path.read_bytes(), password=password, require_portable=True)
            else:
                payload = decrypt(path.read_bytes(), master_key=self.master_key)
            self._validate_snapshot(json.loads(payload.decode("utf-8")))
            encrypted = encrypt(payload, password=password)
            token = secrets.token_urlsafe(32)
            filename = "node-console-" + backup_id + ".nvbackup"
            self.downloads[token] = {"expires": self.clock() + 300, "data": encrypted, "filename": filename}
            self._expire()
            return {"download_token": token, "filename": filename, "expires_in": 300}

    def download(self, token):
        with self.lock:
            self._expire()
            item = self.downloads.get(token) if isinstance(token, str) else None
            if item is None:
                raise _server().PanelError("备份下载已过期，请重新导出。", 404)
            return item["data"], item["filename"]

    def _expire(self):
        now = self.clock()
        self.downloads = {key: item for key, item in self.downloads.items() if item["expires"] > now}
        self.previews = {key: item for key, item in self.previews.items() if item["expires"] > now}
        if len(self.downloads) > 8:
            self.downloads.pop(next(iter(self.downloads)))
        if len(self.previews) > 4:
            self.previews.pop(next(iter(self.previews)))

    @staticmethod
    def _auth(auth):
        if (not isinstance(auth, dict) or not isinstance(auth.get("username"), str)
                or not 1 <= len(auth["username"]) <= 128
                or type(auth.get("iterations")) is not int or not 100000 <= auth["iterations"] <= 2000000
                or not isinstance(auth.get("salt"), str) or not re.fullmatch(r"[a-f0-9]{48}", auth["salt"])
                or not isinstance(auth.get("hash"), str) or not re.fullmatch(r"[a-f0-9]{64}", auth["hash"])):
            raise ValueError("Invalid authentication record")

    def _validate_snapshot(self, snapshot):
        from panel import telemetry
        try:
            owner = self.accounts.owner_manager
            if (not isinstance(snapshot, dict) or snapshot.get("version") != 1
                    or snapshot.get("public_ip") != owner.public_ip or snapshot.get("origin") != owner.origin
                    or snapshot.get("base_path") != owner.base_path):
                raise ValueError("Backup belongs to another node; explicit migration is required")
            files = snapshot.get("files")
            if not isinstance(files, dict) or len(files) > 25:
                raise ValueError("Invalid file manifest")
            decoded = {}
            for name, item in files.items():
                if (not isinstance(name, str) or not isinstance(item, dict) or
                        set(item) != {"sha256", "data", "mode", "uid", "gid"} or
                        not isinstance(item["sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", item["sha256"]) or
                        type(item["mode"]) is not int or not 0 <= item["mode"] <= 0o777 or
                        type(item["uid"]) is not int or type(item["gid"]) is not int):
                    raise ValueError("Invalid file entry")
                payload = _decode(item["data"], MAX_PLAINTEXT)
                if hashlib.sha256(payload).hexdigest() != item["sha256"]:
                    raise ValueError("File hash mismatch")
                decoded[name] = payload
            auth = json.loads(decoded["admin/auth.json"].decode("utf-8"))
            self._auth(auth)
            registry = json.loads(decoded["admin/users.json"].decode("utf-8"))
            # Validate against the backup's owner username, without mutating the
            # live Accounts object even momentarily.
            validator = copy.copy(self.accounts)
            validator.owner_auth = auth
            validator._validate_registry(registry)
            records = [{"id": "admin", "port": owner.state["base"]["inbounds"][0]["port"],
                        "username": auth["username"], "display_name": "管理员", "enabled": True}] + registry["users"]
            allowed = set(self._paths(records))
            required = {name for name in allowed if not name.startswith("system/")}
            if set(files) - allowed or required - set(files):
                raise ValueError("Unexpected or incomplete backup file set")
            for record in records:
                prefix = "admin/" if record["id"] == "admin" else "members/" + record["id"] + "/"
                state = json.loads(decoded[prefix + "state.json"].decode("utf-8"))
                config = json.loads(decoded[prefix + "config.json"].decode("utf-8"))
                if (not isinstance(state, dict) or len(state["base"]["inbounds"]) != 1
                        or len(config["inbounds"]) != 1):
                    raise ValueError("Invalid independent instance")
                inbound = state["base"]["inbounds"][0]
                current = config["inbounds"][0]
                expected_ids = {str(uuid.UUID(inbound["settings"]["clients"][0]["id"]))}
                if state.get("profile"):
                    expected_ids.add(str(uuid.UUID(state["auto_id"])))
                expected_ids.update(str(uuid.UUID(item["client_id"])) for item in state["applied_exits"])
                actual_ids = {str(uuid.UUID(client["id"])) for client in current["settings"]["clients"]}
                if (inbound["port"] != record["port"] or current["port"] != record["port"]
                        or inbound["protocol"] != "vless" or current["protocol"] != "vless"
                        or inbound["streamSettings"]["security"] != "reality"
                        or current["streamSettings"] != inbound["streamSettings"]
                        or expected_ids != actual_ids
                        or state["managed_hash"] != hashlib.sha256(decoded[prefix + "config.json"]).hexdigest()
                        or not isinstance(state["rule_token"], str) or len(state["rule_token"]) < 32
                        or (state["profile"] is not None and not isinstance(state["profile"], str))):
                    raise ValueError("State/config identity mismatch")
                telemetry.validate_augmentation(config, allow_legacy=True)
                if self.validate_config:
                    self.validate_config(config, record["id"])
                elif not self.accounts.demo:
                    self._test_config(decoded[prefix + "config.json"])
            for name, payload in decoded.items():
                if name.startswith("system/") and name.endswith(".json"):
                    value = json.loads(payload.decode("utf-8"))
                    if not isinstance(value, dict):
                        raise ValueError("System metadata must be a JSON object")
                    if name == "system/traffic.private.json":
                        telemetry.validate_store(value)
                    elif name == "system/backup-settings.private.json":
                        if (type(value.get("enabled")) is not bool or
                                type(value.get("last_backup_time", 0)) not in (int, float)
                                or not 0 <= value.get("last_backup_time", 0) < 10 ** 11):
                            raise ValueError("Invalid backup schedule")
                    elif name == "system/health.private.json":
                        if any(not isinstance(identity, str) or not telemetry.IDENTITY.fullmatch(identity)
                               or not isinstance(item, dict) for identity, item in value.items()):
                            raise ValueError("Invalid health records")
                elif name == "system/activity.private.jsonl":
                    for line in payload.decode("utf-8").splitlines():
                        item = json.loads(line)
                        if (not isinstance(item, dict) or any(not isinstance(item.get(key), str)
                                for key in ("id", "at", "actor", "action", "status", "summary"))):
                            raise ValueError("Invalid activity record")
            return records, decoded
        except _server().PanelError:
            raise
        except Exception as error:
            raise _server().PanelError("备份内容校验失败，或它不属于当前服务器。", 409) from error

    def _test_config(self, payload):
        path = self.directory / ("validation-" + secrets.token_hex(12) + ".private.json")
        try:
            _server().atomic_write(path, payload)
            result = subprocess.run([str(_server().base.XRAY), "run", "-test", "-config", str(path)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
            if result.returncode:
                raise ValueError("Xray rejected backup config")
        finally:
            if path.exists():
                path.unlink()

    def _upgrade_statistics(self, snapshot, records):
        """Older snapshots keep their identities but gain the current private API."""
        from panel import telemetry
        snapshot = copy.deepcopy(snapshot)
        upgraded = False
        for record in records:
            prefix = "admin/" if record["id"] == "admin" else "members/" + record["id"] + "/"
            config_item = snapshot["files"][prefix + "config.json"]
            state_item = snapshot["files"][prefix + "state.json"]
            config = json.loads(_decode(config_item["data"]).decode("utf-8"))
            augmented = telemetry.augment_config(config, record["port"])
            if augmented == config:
                continue
            upgraded = True
            payload = _server().json_bytes(augmented)
            state = json.loads(_decode(state_item["data"]).decode("utf-8"))
            state["managed_hash"] = hashlib.sha256(payload).hexdigest()
            config_item.update(data=_b64(payload), sha256=state["managed_hash"])
            state_payload = _server().json_bytes(state)
            state_item.update(data=_b64(state_payload), sha256=hashlib.sha256(state_payload).hexdigest())
        return snapshot, upgraded

    def preview(self, data, password):
        _password(password)
        try:
            archive = _decode(data)
        except (ValueError, UnicodeError) as error:
            raise _server().PanelError("请选择有效的加密备份文件。") from error
        payload = decrypt(archive, password=password, require_portable=True)
        try:
            snapshot = json.loads(payload.decode("utf-8"))
        except (ValueError, UnicodeError) as error:
            raise _server().PanelError("备份内容不是有效的系统记录。") from error
        with self._locked() as (current, unused), self.lock:
            records, decoded = self._validate_snapshot(snapshot)
            snapshot, upgraded = self._upgrade_statistics(snapshot, records)
            if upgraded:
                records, decoded = self._validate_snapshot(snapshot)
                payload = _canonical(snapshot)
            fingerprint = self._fingerprint(self._snapshot(current))
            token = secrets.token_urlsafe(32)
            expiry = self.clock() + 600
            # Keep only authenticated ciphertext in a preview. Decrypting uses
            # the private master key, so the user's passphrase is never retained.
            self.previews[token] = {"archive": encrypt(payload, master_key=self.master_key),
                                    "fingerprint": fingerprint, "expires": expiry}
            self._expire()
            return {"preview_token": token, "created_at": snapshot["created_at"],
                    "users": [{key: record[key] for key in ("username", "display_name", "enabled")}
                              for record in records],
                    "warnings": ["完整恢复将替换所有账号、出口、分流规则及流量记录，并退出所有网页会话。"] +
                        (["旧备份的节点将补充私有统计接口，原有代理身份保留。"] if upgraded else []),
                    "changes": {"files": len(decoded), "users": len(records)},
                    "expires_at": datetime.fromtimestamp(expiry, timezone.utc).isoformat()}

    def _reload_accounts(self):
        owner = self.accounts.owner_manager
        auth = json.loads(self.accounts.owner_auth_path.read_text(encoding="utf-8"))
        registry = json.loads(self.accounts.users_path.read_text(encoding="utf-8"))
        self.accounts.owner_auth = auth
        self.accounts._validate_registry(registry)
        self.accounts.records = registry["users"]
        owner.state = json.loads(owner.state_path.read_text(encoding="utf-8"))
        self.accounts._managers = {"admin": owner}
        for record in self.accounts.records:
            self.accounts._manager(record)
        self.settings = json.loads(self.settings_path.read_text(encoding="utf-8")) if self.settings_path.exists() else {
            "enabled": True, "last_backup": None, "last_backup_time": 0, "last_error": None}

    def _runtime(self, action, records):
        if self.accounts.demo:
            return
        if self.runtime is None:
            raise _server().PanelError("完整恢复的运行控制尚未配置。", 503)
        self.runtime(action, copy.deepcopy(records))

    def _write(self, paths, decoded, snapshot):
        for name, payload in decoded.items():
            path = self._safe(paths[name])
            original_group = path.stat().st_gid if path.exists() else 0
            path.parent.mkdir(parents=True, exist_ok=True)
            if os.name == "posix" and name.startswith("members/"):
                os.chmod(path.parent, 0o700)
            _server().atomic_write(path, payload)
            if os.name == "posix":
                # Passwords and private configs never adopt permissive archive
                # modes. The main Xray group retains its existing read access.
                mode = 0o640 if name == "admin/config.json" else 0o600
                os.chmod(path, mode)
                # Archive-provided ownership is informational. Preserve current
                # host ownership, never grant access to an uploaded UID/GID.
                if name == "admin/config.json":
                    os.chown(path, 0, original_group)
                else:
                    os.chown(path, 0, 0)

    def restore(self, preview_token, confirmation):
        if confirmation != "RESTORE":
            raise _server().PanelError("请输入 RESTORE 确认完整恢复。")
        with self._locked() as (current, unused), self.lock:
            self._expire()
            item = self.previews.get(preview_token) if isinstance(preview_token, str) else None
            if item is None:
                raise _server().PanelError("恢复预览已过期，请重新上传并检查备份。", 409)
            original = self._snapshot(current)
            if item["fingerprint"] != self._fingerprint(original):
                raise _server().PanelError("预览后已有用户修改配置，请重新预览，避免覆盖新内容。", 409)
            snapshot = json.loads(decrypt(item["archive"], master_key=self.master_key).decode("utf-8"))
            records, decoded = self._validate_snapshot(snapshot)
            if self.runtime is None and not self.accounts.demo:
                raise _server().PanelError("完整恢复的运行控制尚未配置。", 503)
            # Always preserve a private encrypted checkpoint before touching any
            # live file. It remains usable if a service rollback needs attention.
            recovery_id = secrets.token_hex(16)
            recovery = encrypt(_canonical(original), master_key=self.master_key)
            _server().atomic_write(self.directory / ("recovery-" + recovery_id + ".nvbackup"), recovery)
            original_records, original_decoded = self._validate_snapshot(original)
            paths = self._paths(records)
            original_paths = self._paths(original_records)
            all_records = {record["id"]: record for record in current + records}
            changed = False
            try:
                changed = True
                self._runtime("stop", list(all_records.values()))
                self._write(paths, decoded, snapshot)
                # Optional state absent in the snapshot must not survive as a
                # misleading runtime record from the newer configuration.
                for name, path in paths.items():
                    if name.startswith("system/") and name not in decoded and path.exists():
                        self._safe(path).unlink()
                self._reload_accounts()
                self._runtime("start", records)
            except Exception as error:
                if changed:
                    try:
                        self._runtime("stop", list(all_records.values()))
                        self._write(original_paths, original_decoded, original)
                        for name, path in paths.items():
                            if name not in original_decoded and path.exists():
                                self._safe(path).unlink()
                        self._reload_accounts()
                        self._runtime("start", original_records)
                    except Exception as rollback_error:
                        raise _server().PanelError("完整恢复失败，自动回滚需要检查；恢复前的加密检查点已保存。", 500) from rollback_error
                raise _server().PanelError("完整恢复失败，已恢复原有用户和配置。", 500) from error
            self.previews.clear()
            self.downloads.clear()
            return {"restored": True, "requires_login": True, "needs_reload": True,
                    "users": len(records), "recovery_checkpoint": recovery_id}

    def tick(self):
        with self.lock:
            self._expire()
            if not self.settings.get("enabled", True) or self.clock() < self.settings.get("last_backup_time", 0) + 86400:
                return
        try:
            self.create(scheduled=True)
        except Exception:
            with self.lock:
                self.settings["last_error"] = "自动备份未完成，请检查服务器磁盘、加密依赖或正在进行的操作。"
                _server().atomic_write(self.settings_path, _server().json_bytes(self.settings))
