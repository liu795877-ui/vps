"""Explain expected rules from saved account data and public provider snapshots.

Never fetch a submitted site or retain its private URL. This is a server-side
prediction; the user's Mihomo cache, DNS and policy selection can differ.
"""

import hashlib
import ipaddress
import json
from pathlib import Path
import re
import threading
import time
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from panel import routing


class RuleDiagnostics:
    def __init__(self, directory):
        self.directory = Path(directory) / "diagnostic-rules"
        self.directory.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.cache = {}

    @staticmethod
    def _payload(text):
        result = []
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("-"):
                continue
            line = line[1:].strip()
            if line.startswith('"'):
                try:
                    line = json.loads(line)
                except ValueError:
                    continue
            elif line.startswith("'") and line.endswith("'"):
                line = line[1:-1].replace("''", "'")
            else:
                line = line.split(" #", 1)[0]
            result.append(line)
        return result

    def provider(self, spec):
        resource = spec.get("resource")
        if resource:
            path = Path(__file__).parent / "rules" / resource
            return self._payload(path.read_text(encoding="utf-8")) if path.is_file() else None
        url = spec.get("url", "")
        key = hashlib.sha256(url.encode("utf-8")).hexdigest()
        with self.lock:
            if key in self.cache:
                return self.cache[key]
            path = self.directory / (key + ".txt")
            if path.is_file():
                value = self._payload(path.read_text(encoding="utf-8"))
                self.cache[key] = value
                return value
        return None

    def refresh(self):
        specs = {}
        for preset in (routing.smart_preset(), routing.preset()):
            for spec in preset["providers"].values():
                if "url" in spec:
                    specs[spec["url"]] = spec
        # Only repository-owned provider URLs are fetched, never user input.
        for url in specs:
            parsed = urlsplit(url)
            if parsed.scheme != "https" or parsed.hostname not in ("raw.githubusercontent.com", "cdn.jsdelivr.net"):
                continue
            key = hashlib.sha256(url.encode("utf-8")).hexdigest()
            path = self.directory / (key + ".txt")
            if path.exists() and time.time() - path.stat().st_mtime < 86400:
                continue
            try:
                with urlopen(Request(url, headers={"User-Agent": "NodeConsole-RuleCheck"}), timeout=10) as response:
                    body = response.read(4000001)
                if len(body) > 4000000:
                    continue
                text = body.decode("utf-8-sig")
                payload = self._payload(text)
                if not payload:
                    continue
                from panel.server import atomic_write
                atomic_write(path, text.encode("utf-8"))
                with self.lock:
                    self.cache[key] = payload
            except (OSError, ValueError, UnicodeError):
                continue

    @staticmethod
    def match(line, domain, behavior="classical"):
        if behavior == "domain":
            value = line.lstrip("+.")
            if "*" in value:
                pattern = re.escape(value).replace(r"\*", ".*")
                return bool(re.fullmatch(pattern, domain))
            return domain == value or domain.endswith("." + value)
        fields = [value.strip() for value in line.split(",")]
        if len(fields) < 2:
            return False
        kind, value = fields[:2]
        if kind == "DOMAIN":
            return domain == value.lower()
        if kind == "DOMAIN-SUFFIX":
            return domain == value.lower() or domain.endswith("." + value.lower())
        if kind == "DOMAIN-KEYWORD":
            return value.lower() in domain
        if kind == "DOMAIN-WILDCARD":
            return bool(re.fullmatch(re.escape(value.lower()).replace(r"\*", ".*"), domain))
        # IP/GEOIP and process conditions require the client's actual resolution.
        return None if kind not in ("MATCH",) else True

    def check(self, manager, value):
        from panel.server import routing_domain
        domain = routing_domain(value.strip(" "))
        with manager.lock:
            state = manager.state
            direct = list(state.get("direct_domains", []))
            proxy = list(state.get("domains", []))
            mode = state.get("routing_mode", "manual")
            current = "服务器自身出口" if state.get("active_id") in (None, "server") else next(
                (item["name"] for item in state.get("applied_exits", []) if item["id"] == state["active_id"]), "已应用静态出口")
        result = {"domain": domain, "decision": "unknown", "source": "待检查", "rule": "",
                  "client_verified": False, "mode": mode, "current_exit": current,
                  "checks": ["客户端使用规则模式", "STATIC-SELECT 选择 AUTO · 网页切换", "更新配置订阅与规则集", "在客户端连接记录核对规则及 DIRECT / 节点"]}

        def finish(decision, source, rule, explanation):
            result.update(decision=decision, source=source, rule=rule, explanation=explanation)
            return result

        if domain.endswith((".lan", ".local", ".home.arpa", ".localhost")):
            return finish("direct", "局域网", "本机与局域网直连", "预计使用本机网络。")
        for item in direct:
            if domain == item or domain.endswith("." + item):
                return finish("direct", "强制直连", "DOMAIN-SUFFIX," + item + ",DIRECT", "命中你已保存的强制直连规则，预计使用本机网络；智能客户端规则集需先同步。")
        if domain == "api.ipify.org":
            return finish("proxy", "出口核对", "DOMAIN,api.ipify.org,STATIC-SELECT", "固定跟随网页出口，用于核对代理出网 IP。")
        for item in proxy:
            if domain == item or domain.endswith("." + item):
                return finish("proxy", "强制代理", "DOMAIN-SUFFIX," + item + ",STATIC-SELECT", "命中你已保存的强制代理规则，预计跟随网页出口。")
        if mode == "manual":
            return finish("direct", "手动方案默认", "MATCH,DIRECT", "未命中强制代理列表，预计使用本机网络。")
        preset = routing.smart_preset() if mode == "smart" else routing.preset()
        uncertain = []
        for line in preset["rules"]:
            fields = [field.strip() for field in line.split(",")]
            kind = fields[0]
            if kind == "RULE-SET" and len(fields) >= 3:
                name, target = fields[1:3]
                spec = preset["providers"].get(name)
                payload = self.provider(spec) if spec else None
                if payload is None:
                    uncertain.append("规则源暂未缓存：" + name)
                    continue
                if spec.get("behavior") == "ipcidr":
                    uncertain.append("客户端解析 IP：" + name)
                    continue
                matches = [self.match(item, domain, spec.get("behavior", "classical")) for item in payload]
                if True not in matches:
                    if None in matches:
                        uncertain.append("规则源含 IP 或客户端条件：" + name)
                    continue
                matched = payload[matches.index(True)]
            elif kind == "MATCH":
                target, matched = fields[1], line
            elif kind in ("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD"):
                if not self.match(line, domain):
                    continue
                target, matched = fields[2], line
            else:
                uncertain.append("需要客户端判断：" + kind)
                continue
            if uncertain:
                return finish("unknown", "需要客户端确认", matched, "前面的规则可能优先命中：" + "；".join(uncertain[:3]) + "。请查看客户端连接记录。")
            if target not in ("DIRECT", "STATIC-SELECT"):
                group = next((group for group in preset.get("groups", []) if group["name"] == target), None)
                choice = group.get("proxies", ["STATIC-SELECT"])[0] if group else "STATIC-SELECT"
                if choice not in ("DIRECT", "STATIC-SELECT", "Proxy"):
                    return finish("unknown", target, matched, "命中服务策略组，实际方向取决于客户端对该组的选择。")
                target = choice
            return finish("direct" if target == "DIRECT" else "proxy", name if kind == "RULE-SET" else "方案规则", matched, "按服务器规则快照预计" + ("使用本机网络。" if target == "DIRECT" else "跟随网页出口。") + "客户端规则版本、解析结果和策略选择可能不同。")
        return finish("unknown", "需要客户端确认", "", "没有足够的规则快照，无法确认预计方向；请查看客户端连接记录。")
