"""Paid access terms, independent of private client-profile subscriptions.

Terms live in the account registry so complete backups retain deadlines and
renewal requests. Legacy members have no deadline; new members receive 30 days.
All stored times are integer UTC seconds. Expiry never revokes web login.
"""
import copy
import time


MAX_TIME = 4102444800  # 2100-01-01 UTC
FIELDS = {"plan", "expires_at", "note", "revision", "updated_at",
          "renewal_requested_at", "renewal_message", "suspended"}


def terms(record):
    return record.get("membership", {"plan": "基础订阅", "expires_at": None,
        "note": "", "revision": 0, "updated_at": None,
        "renewal_requested_at": None, "renewal_message": "", "suspended": False})


def validate(value):
    if not isinstance(value, dict) or set(value) != FIELDS:
        raise ValueError("Invalid membership terms")
    for key, limit, minimum in (("plan", 48, 1), ("note", 300, 0), ("renewal_message", 300, 0)):
        text = value[key]
        if (not isinstance(text, str) or not minimum <= len(text.strip()) <= limit
                or any(ord(char) < 32 for char in text)):
            raise ValueError("Invalid membership text")
        text.encode("utf-8")
    for key in ("expires_at", "updated_at", "renewal_requested_at"):
        stamp = value[key]
        if stamp is not None and (type(stamp) is not int or not 0 < stamp <= MAX_TIME):
            raise ValueError("Invalid membership timestamp")
    if (type(value["revision"]) is not int or value["revision"] < 0
            or type(value["suspended"]) is not bool):
        raise ValueError("Invalid membership state")


def expired(record, at=None):
    deadline = terms(record)["expires_at"]
    return record["id"] != "admin" and deadline is not None and deadline <= (time.time() if at is None else at)


def allowed(record, at=None):
    return record["enabled"] and not expired(record, at)


def initial(at):
    value = terms({}).copy()
    value.update(expires_at=int(at) + 30 * 86400, updated_at=int(at), revision=1)
    return value


class Memberships:
    def __init__(self, accounts, telemetry, audit=None):
        self.accounts, self.telemetry, self.audit = accounts, telemetry, audit
        self.stopped = set()
        self.errors = {}

    def snapshot(self, record):
        value = copy.deepcopy(terms(record))
        value.pop("suspended")
        is_expired = expired(record, self.accounts.clock())
        value.update(status="admin" if record["id"] == "admin" else "expired" if is_expired else
                     "active" if value["expires_at"] is not None else "unlimited",
                     expired=is_expired, proxy_allowed=allowed(record, self.accounts.clock()),
                     renewal_pending=value["renewal_requested_at"] is not None,
                     enforcement_error=(self.errors.get(record["id"]) or
                        (getattr(self.telemetry, "enforcement_error", None) if is_expired else None)),
                     timezone="Asia/Shanghai")
        return value

    def update(self, user_id, request):
        from panel.server import PanelError
        if (not {"plan", "expires_at", "revision"} <= set(request)
                or set(request) - {"id", "plan", "expires_at", "note", "revision", "resolve_renewal"}
                or type(request.get("resolve_renewal", False)) is not bool):
            raise PanelError("订阅资料格式无效。")
        with self.accounts.lock:
            record = self.accounts._record(user_id)
            if user_id == "admin":
                raise PanelError("管理员账号长期有效，无需设置订阅。", 403)
            previous = terms(record)
            if type(request.get("revision")) is not int or request["revision"] != previous["revision"]:
                raise PanelError("订阅资料已有更新，请刷新成员列表后重试。", 409)
            value = copy.deepcopy(previous)
            value.update(plan=request.get("plan"), expires_at=request.get("expires_at"),
                         note=request.get("note", ""), updated_at=int(self.accounts.clock()),
                         revision=previous["revision"] + 1)
            if request.get("resolve_renewal"):
                value.update(renewal_requested_at=None, renewal_message="")
            try:
                validate(value)
            except (ValueError, UnicodeError):
                raise PanelError("请填写订阅名称（1–48 字）、有效到期时间和备注（最多 300 字）。")
            value["plan"], value["note"] = value["plan"].strip(), value["note"].strip()
            manager = self.accounts._manager(record)
            if not manager.operation.acquire(blocking=False):
                raise PanelError("成员正在检测或切换出口，请完成后再修改订阅。", 409)
            try:
                records = copy.deepcopy(self.accounts.records)
                updated = next(item for item in records if item["id"] == user_id)
                updated["membership"] = value
                # Remember the required resume across a crash after renewal.
                value["suspended"] = previous["suspended"] or expired(record, self.accounts.clock())
                self.accounts._save(records)
                self.tick()
                if user_id in self.errors or self.telemetry.enforcement_error:
                    raise PanelError("订阅已保存，出口状态执行未完成；系统会重试，请检查成员状态。", 500)
                return self.accounts._public(self.accounts._record(user_id))
            finally:
                manager.operation.release()

    def request_renewal(self, user_id, request):
        from panel.server import PanelError
        message = request.get("message", "")
        if (set(request) - {"message"} or not isinstance(message, str) or len(message) > 300
                or any(ord(char) < 32 for char in message)):
            raise PanelError("续费说明最多 300 字，不能包含换行或控制字符。")
        try:
            message.encode("utf-8")
        except UnicodeError:
            raise PanelError("续费说明包含不支持的字符。")
        with self.accounts.lock:
            record = self.accounts._record(user_id)
            if user_id == "admin":
                raise PanelError("管理员无需申请续费。", 403)
            if not terms(record)["renewal_requested_at"]:
                records = copy.deepcopy(self.accounts.records)
                updated = next(item for item in records if item["id"] == user_id)
                value = copy.deepcopy(terms(record))
                value.update(renewal_requested_at=int(self.accounts.clock()), renewal_message=message.strip(),
                             revision=value["revision"] + 1)
                updated["membership"] = value
                self.accounts._save(records)
            return self.snapshot(self.accounts._record(user_id))

    def tick(self):
        """Persist suspension first, block both protocols, then stop services.

        The network block is independent of systemd success. Other accounts are
        still processed if one service fails. No data/configuration is regenerated.
        """
        with self.accounts.lock:
            records = copy.deepcopy(self.accounts.records)
            changed = False
            for record in records:
                if expired(record, self.accounts.clock()) and not terms(record)["suspended"]:
                    record["membership"] = copy.deepcopy(terms(record))
                    record["membership"]["suspended"] = True
                    changed = True
            if changed:
                self.accounts._save(records)
            network_error = None
            try:
                self.telemetry.apply_enforcement()
            except Exception as error:
                network_error = error
            for record in list(self.accounts.records):
                identity = record["id"]
                try:
                    self.accounts._manager(record)
                    if expired(record, self.accounts.clock()):
                        if identity not in self.stopped:
                            self.accounts._stop(record)
                            self.stopped.add(identity)
                            if self.audit:
                                self.audit.record({"id": "system", "username": "系统"},
                                    "membership.expired", "success", "订阅到期，已关闭 REALITY 和 HY2 出口", identity)
                    elif terms(record)["suspended"]:
                        if record["enabled"]:
                            self.accounts._start(record)
                        latest = copy.deepcopy(self.accounts.records)
                        item = next(item for item in latest if item["id"] == identity)
                        item["membership"]["suspended"] = False
                        self.accounts._save(latest)
                        self.stopped.discard(identity)
                    self.errors.pop(identity, None)
                except Exception:
                    self.errors[identity] = "订阅出口状态执行失败，系统会重试；请管理员检查服务。"
            # A resumed HY2 service can now satisfy the control health check.
            if network_error:
                try:
                    self.telemetry.apply_enforcement()
                except Exception:
                    pass  # Services are still stopped; the next tick retries the network plan.
