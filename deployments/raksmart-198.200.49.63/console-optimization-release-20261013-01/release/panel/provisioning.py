"""Durable, administrator-only member preparation without stored passwords."""

import copy
import hmac
import json
import re
import secrets
import threading


STAGES = (
    ("validating", "检查成员资料"),
    ("allocating", "分配独立入口"),
    ("configuration", "准备并校验配置"),
    ("services", "启动成员服务"),
    ("local_ready", "核对本地监听"),
    ("complete", "准备完成"),
)
REQUEST_ID = re.compile(r"[A-Za-z0-9_-]{16,80}\Z")
RETAINED_TASKS = 32


def _server():
    from panel import server
    return server


class MemberPreparation:
    def __init__(self, app):
        self.app = app
        self.path = app.manager.directory / "member-tasks.private.json"
        self.lock = threading.RLock()
        self.tasks = []
        self.threads = []
        self.pending_checks = {}
        self.check_key = secrets.token_bytes(32)
        self._load()

    def _load(self):
        if not self.path.exists():
            return
        if self.path.is_symlink():
            raise _server().PanelError("成员准备记录需要检查。", 500)
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if (not isinstance(data, dict) or data.get("version") != 1
                    or not isinstance(data.get("tasks"), list) or len(data["tasks"]) > RETAINED_TASKS):
                raise ValueError("Invalid task registry")
            for item in data["tasks"]:
                if (not isinstance(item, dict) or not isinstance(item.get("id"), str)
                        or not REQUEST_ID.fullmatch(item.get("request_id", ""))
                        or item.get("status") not in ("queued", "running", "succeeded", "failed")
                        or not isinstance(item.get("username"), str)):
                    raise ValueError("Invalid task")
                # Pick known metadata; neither requests nor credentials are a task artifact.
                self.tasks.append({key: copy.deepcopy(item[key]) for key in (
                    "id", "request_id", "username", "display_name", "status", "stage", "message",
                    "created_at", "updated_at", "user", "error", "actor"
                ) if key in item})
            changed = False
            for item in self.tasks:
                if item["status"] in ("queued", "running"):
                    item.update(status="failed", error="准备任务被管理服务重启中断。请先核对用户列表，再决定是否重新提交。",
                                message="任务已中断，需要核对现有成员。", updated_at=_server().now())
                    changed = True
            if changed:
                self._persist()
        except (ValueError, TypeError, KeyError) as error:
            raise _server().PanelError("成员准备记录需要检查。", 500) from error

    def _persist(self):
        _server().atomic_write(self.path, _server().json_bytes({"version": 1, "tasks": self.tasks}))

    @staticmethod
    def _public(item):
        result = {key: copy.deepcopy(item[key]) for key in (
            "id", "username", "display_name", "status", "stage", "message", "created_at", "updated_at", "user", "error"
        ) if key in item}
        current = next((index for index, (stage, _) in enumerate(STAGES) if stage == item.get("stage")), -1)
        steps = []
        for index, (stage, label) in enumerate(STAGES):
            state = "pending"
            if item["status"] == "succeeded" or index < current:
                state = "complete"
            elif index == current:
                state = "failed" if item["status"] == "failed" else "running" if item["status"] == "running" else "pending"
            steps.append({"id": stage, "label": label, "status": state})
        result["steps"] = steps
        result["public_verification"] = "not_checked"
        return result

    def list(self):
        with self.lock:
            return [self._public(item) for item in reversed(self.tasks)]

    def has_active(self):
        with self.lock:
            return any(item["status"] in ("queued", "running") for item in self.tasks)

    def get(self, task_id):
        with self.lock:
            item = next((item for item in self.tasks if item["id"] == task_id), None)
            if item is None:
                raise _server().PanelError("没有找到这个成员准备任务。", 404)
            return self._public(item)

    def submit(self, request, actor):
        server = _server()
        if not isinstance(request, dict) or set(request) - {"username", "display_name", "password", "request_id"}:
            raise server.PanelError("成员准备资料格式无效。")
        request_id = request.get("request_id")
        if not isinstance(request_id, str) or not REQUEST_ID.fullmatch(request_id):
            raise server.PanelError("请刷新成员表单后重新提交。")
        from panel.accounts import USERNAME, _password
        username = request.get("username")
        display = request.get("display_name") or username
        if not isinstance(username, str) or not USERNAME.fullmatch(username):
            raise server.PanelError("用户名需要 3 至 24 位小写字母、数字、下划线或短横线，并以字母开头。")
        password = _password(request.get("password"))
        if (not isinstance(display, str) or not 1 <= len(display.strip()) <= 48
                or any(ord(char) < 32 for char in display)):
            raise server.PanelError("显示名称需要 1 至 48 个字符。")
        with self.app.mutation_lock, self.lock:
            duplicate = next((item for item in self.tasks if item["request_id"] == request_id), None)
            if duplicate:
                if duplicate["username"] != username or duplicate.get("display_name") != display.strip():
                    raise server.PanelError("这个提交标识已用于其他成员，请重新提交。", 409)
                if duplicate["status"] == "succeeded":
                    with self.app.accounts.lock:
                        identity = duplicate.get("user", {}).get("id")
                        record = next((item for item in self.app.accounts.records
                                       if item["id"] == identity and item["username"] == username), None)
                        if (record is None or not record["enabled"]
                                or not server.password_matches(password, record["auth"])):
                            raise server.PanelError("这个任务已完成，但账号或密码已变化。请核对用户列表，不能再次交付这份初始资料。", 409)
                elif duplicate["status"] in ("queued", "running"):
                    signature = hmac.new(self.check_key, password.encode("utf-8"), "sha256").digest()
                    if not hmac.compare_digest(self.pending_checks.get(duplicate["id"], b""), signature):
                        raise server.PanelError("这个任务已提交，请保持原始资料重试，或查看现有任务。", 409)
                else:
                    # A failed task has no credential to replay and its worker
                    # will never be restarted by an idempotent retry. Require
                    # the UI to create a fresh request identity explicitly.
                    raise server.PanelError("这个任务已失败，请核对资料后使用新的提交标识重试。", 409)
                return self._public(duplicate)
            if any(item["username"] == username and item["status"] in ("queued", "running") for item in self.tasks):
                raise server.PanelError("这个账号正在准备，请查看已有任务。", 409)
            active = [item for item in self.tasks if item["status"] in ("queued", "running")]
            if len(active) >= 8:
                raise server.PanelError("已有成员准备任务在执行，请稍后再试。", 409)
            with self.app.accounts.lock:
                existing_names = {self.app.accounts.owner_auth["username"].casefold()}
                existing_names.update(item["username"].casefold() for item in self.app.accounts.records)
                if username.casefold() in existing_names:
                    raise server.PanelError("用户名已存在，请换一个用户名。", 409)
                if self.app.accounts.entrance_summary()["available_count"] <= len(active):
                    raise server.PanelError("没有空闲的已配置入口，请先准备入口名额。", 409)
            while len(self.tasks) >= RETAINED_TASKS:
                oldest = next((item for item in self.tasks if item["status"] in ("succeeded", "failed")), None)
                if oldest is None:
                    raise server.PanelError("成员准备记录已满，请稍后再试。", 409)
                self.tasks.remove(oldest)
            item = {"id": secrets.token_hex(16), "request_id": request_id, "username": username,
                    "display_name": display.strip(), "status": "queued", "stage": "validating",
                    "message": "等待准备成员入口。", "created_at": server.now(), "updated_at": server.now(),
                    "actor": {"id": actor["id"], "username": actor["username"]}}
            self.tasks.append(item)
            self.pending_checks[item["id"]] = hmac.new(self.check_key, password.encode("utf-8"), "sha256").digest()
            try:
                self._persist()
            except Exception:
                self.tasks.remove(item)
                self.pending_checks.pop(item["id"], None)
                raise
            payload = {"username": username, "display_name": display.strip(), "password": password}
            thread = threading.Thread(target=self._run, args=(item["id"], payload), daemon=True)
            self.threads = [existing for existing in self.threads if existing.is_alive()]
            self.threads.append(thread)
            try:
                thread.start()
            except Exception:
                payload.clear()
                self.pending_checks.pop(item["id"], None)
                item.update(status="failed", message="任务未能启动，请核对后重新提交。",
                            error="任务未能启动，请核对后重新提交。", updated_at=server.now())
                self._persist()
                raise server.PanelError("任务未能启动，请核对后重新提交。", 500)
            return self._public(item)

    def _update(self, task_id, **changes):
        with self.lock:
            item = next(item for item in self.tasks if item["id"] == task_id)
            item.update(changes, updated_at=_server().now())
            self._persist()

    def _run(self, task_id, request):
        server = _server()
        user = None
        try:
            # Match every existing account/restore/limit mutation's lock order.
            with self.app.mutation_lock:
                self._update(task_id, status="running", message="正在准备独立成员。")

                def progress(stage, message):
                    if stage in {value for value, _ in STAGES}:
                        self._update(task_id, stage=stage, message=message)

                user = self.app.accounts.create_user(request, progress=progress)
                self._update(task_id, status="succeeded", stage="complete", user=user,
                             message="独立账号与本地入口已准备。公网连接仍需从外部验证。")
            with self.lock:
                actor = next(item for item in self.tasks if item["id"] == task_id)["actor"]
            self.app.audit.record(actor, "user.prepare", "success", "成员独立入口准备完成，公网连接待核验", user["id"])
        except Exception as error:
            if user is not None:
                # A logging failure must not turn a committed creation into a failed account.
                with self.lock:
                    item = next(item for item in self.tasks if item["id"] == task_id)
                    item.update(status="succeeded", stage="complete", user=user,
                                message="账号已创建；任务记录保存未完成，请刷新用户列表核对。")
                return
            message = str(error) if isinstance(error, server.PanelError) else "成员准备未完成，请核对用户列表与服务状态后重试。"
            try:
                self._update(task_id, status="failed", error=message, message=message)
            except Exception:
                with self.lock:
                    item = next(item for item in self.tasks if item["id"] == task_id)
                    item.update(status="failed", error=message, message=message)
            try:
                with self.lock:
                    actor = next(item for item in self.tasks if item["id"] == task_id)["actor"]
                self.app.audit.record(actor, "user.prepare", "failed", "成员独立入口准备未完成")
            except Exception:
                pass
        finally:
            request.clear()
            with self.lock:
                self.pending_checks.pop(task_id, None)

    def wait(self, timeout=5):
        for thread in list(self.threads):
            thread.join(timeout)
