"""Routing contracts and optional tests against the official isolated Mihomo core."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.request import Request, urlopen

from panel import routing


NODES = [{"name": "AUTO · 网页切换"}, {"name": "Server fixed"}]
PROFILE = ('mixed-port: 0\nmode: rule\n'
           'proxies: [{"name":"AUTO · 网页切换","type":"direct"},'
           '{"name":"Server fixed","type":"direct"}]\n'
           'proxy-groups:\n  - name: STATIC-SELECT\nrules:\n  - MATCH,DIRECT\n')
TEST_TOKEN = "test-only-capability-token-1234567890"


def fields(text):
    result = OrderedDict()
    for line in text.splitlines():
        if line and not line.startswith((" ", "#")) and ": " in line:
            key, value = line.split(": ", 1)
            try:
                result[key] = json.loads(value, object_pairs_hook=OrderedDict)
            except ValueError:
                result[key] = value
    return result


def smart(**kwargs):
    return fields(routing.render(PROFILE, NODES, kwargs.pop("domains", []), "smart",
                                 origin="https://example.invalid", rule_token=TEST_TOKEN, **kwargs))


class RoutingTests(unittest.TestCase):
    def test_legacy_outputs_and_optional_direct_overrides(self):
        manual = routing.render(PROFILE, NODES, ["github.com"], "manual")
        self.assertIn('"DOMAIN,api.ipify.org,STATIC-SELECT"', manual)
        self.assertIn('"MATCH,DIRECT"', manual)
        services = fields(routing.render(PROFILE, NODES, [], "services"))
        self.assertEqual(services["rules"][1:], routing.preset()["rules"])
        for mode in ("manual", "services"):
            rendered = routing.render(PROFILE, NODES, ["github.com"], mode,
                                      direct_domains=["example.com"])
            self.assertLess(rendered.index("DOMAIN-SUFFIX,example.com,DIRECT"),
                            rendered.index("DOMAIN-SUFFIX,github.com,STATIC-SELECT"))

    def test_private_networks_and_overrides_precede_public_rules(self):
        rules = smart()["rules"]
        for private in ("IP-CIDR,192.168.0.0/16,DIRECT,no-resolve", "IP-CIDR6,fc00::/7,DIRECT,no-resolve"):
            self.assertLess(rules.index(private), rules.index("RULE-SET,Custom Direct,DIRECT"))
        self.assertLess(rules.index("RULE-SET,Custom Direct,DIRECT"),
                        rules.index("RULE-SET,Custom Proxy,STATIC-SELECT"))
        self.assertLess(rules.index("RULE-SET,Custom Proxy,STATIC-SELECT"),
                        rules.index("RULE-SET,Bilibili,DIRECT"))

    def test_international_variants_and_cn_fallback_priority(self):
        rules = smart()["rules"]
        self.assertLess(rules.index("RULE-SET,IQ International,STATIC-SELECT"),
                        rules.index("RULE-SET,IQIYI,DIRECT"))
        self.assertLess(rules.index("RULE-SET,Overseas Exceptions,STATIC-SELECT"),
                        rules.index("RULE-SET,Bilibili,DIRECT"))
        self.assertLess(rules.index("RULE-SET,WeTV,STATIC-SELECT"),
                        rules.index("RULE-SET,Tencent Video,DIRECT"))
        self.assertLess(rules.index("RULE-SET,Overseas,STATIC-SELECT"),
                        rules.index("RULE-SET,China Domains,DIRECT"))
        self.assertEqual(rules[-3:], ["DOMAIN-SUFFIX,cn,DIRECT", "RULE-SET,China IPs,DIRECT", "MATCH,STATIC-SELECT"])
        self.assertFalse(any(rule.startswith(("GEOIP,", "GEOSITE,")) for rule in rules))
        self.assertNotIn("geo-auto-update", smart())
        self.assertNotIn("geo-update-interval", smart())
        self.assertEqual(smart()["rule-providers"]["China IPs"]["behavior"], "ipcidr")
        self.assertEqual(smart()["rule-providers"]["China IPs"]["format"], "mrs")

    def test_dns_overrides_have_matching_order_and_directions(self):
        dns = smart()["dns"]
        policy = dns["nameserver-policy"]
        keys = list(policy)
        self.assertEqual(keys[:2], ["rule-set:Custom Direct", "rule-set:Custom Proxy"])
        self.assertEqual(keys[-1], "+.cn")
        self.assertTrue(all(url.endswith("#DIRECT") for url in policy[keys[0]]))
        self.assertTrue(all(url.endswith("#STATIC-SELECT") for url in policy[keys[1]]))
        self.assertTrue(all(url.endswith("#STATIC-SELECT") for url in policy[keys[2]]))
        self.assertTrue(all(url.endswith("#DIRECT") for url in policy[keys[3]]))
        self.assertTrue(dns["direct-nameserver-follow-policy"])

    def test_stable_list_subscriptions_and_per_server_cache(self):
        first = smart(domains=["github.com"], direct_domains=["example.com"])
        self.assertEqual(first, smart(domains=["youtube.com"], direct_domains=["other.example"]))
        providers = first["rule-providers"]
        cache_id = hashlib.sha256(TEST_TOKEN.encode("ascii")).hexdigest()[:12]
        for direction, name in (("direct", "Custom Direct"), ("proxy", "Custom Proxy")):
            item = providers[name]
            self.assertEqual(item["url"], "https://example.invalid/node-console/rules/custom/" +
                             TEST_TOKEN + "/" + direction + ".yaml")
            self.assertEqual(item["interval"], 300)
            self.assertEqual(item["proxy"], "DIRECT")
            self.assertEqual(item["format"], "yaml")
            self.assertEqual(item["behavior"], "classical")
            self.assertIn(cache_id, item["path"])
        second = fields(routing.render(PROFILE, NODES, [], "smart", rule_token="different-server-token-1234567890"))
        self.assertNotEqual(providers["Custom Direct"]["path"],
                            second["rule-providers"]["Custom Direct"]["path"])
        self.assertEqual([x["name"] for x in first["proxy-groups"]], ["STATIC-SELECT"])
        self.assertEqual(first["proxy-groups"][0]["proxies"], [x["name"] for x in NODES])

    def test_provider_payloads_and_token_validation(self):
        self.assertEqual(routing.rule_payload(["example.com"], "direct"),
                         'payload:\n  - "DOMAIN-SUFFIX,example.com"\n')
        for direction in ("direct", "proxy"):
            rules = [json.loads(line.strip()[2:]) for line in routing.rule_payload([], direction).splitlines()[1:]]
            self.assertEqual(len(rules), 1)
            self.assertTrue(rules[0].startswith("DOMAIN,"))
            self.assertTrue(rules[0].endswith(".invalid"))
        with self.assertRaises(ValueError):
            routing.rule_payload([], "arbitrary")
        for token in (None, "short", "../bad-url" * 8, "x" * 32 + "\n"):
            with self.assertRaises(ValueError):
                routing.render(PROFILE, NODES, [], "smart", rule_token=token)


@unittest.skipUnless(os.environ.get("SMART_ROUTING_CORE") and os.environ.get("SMART_ROUTING_CACHE"),
                     "Set SMART_ROUTING_CORE and SMART_ROUTING_CACHE for isolated official core tests.")
class OfficialMihomoTests(unittest.TestCase):
    """Uses real provider files, a fresh core directory, and no installed-client settings."""

    def test_fresh_directory_syntax_without_geodata_or_cached_rules(self):
        with tempfile.TemporaryDirectory(prefix="smart-routing-coldstart-") as directory:
            root = Path(directory)
            config = root / "test.yaml"
            config.write_text(routing.render(PROFILE, NODES, [], "smart", origin="https://example.invalid",
                                             rule_token=TEST_TOKEN), encoding="utf-8")
            result = subprocess.run([os.environ["SMART_ROUTING_CORE"], "-t", "-d", str(root), "-f", str(config)],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout.decode("utf-8", errors="replace"))
            self.assertFalse(any(path.name.lower().endswith((".mmdb", ".metadb")) for path in root.rglob("*")))

    def test_provider_loading_and_actual_route_selection(self):
        with tempfile.TemporaryDirectory(prefix="smart-routing-test-") as directory:
            root = Path(directory)
            data = smart()
            custom_domains = {"direct": ["github.com"], "proxy": ["bilibili.com", "forced.cn"]}
            class RuleHandler(BaseHTTPRequestHandler):
                def do_GET(self):
                    direction = "direct" if self.path.endswith("/direct.yaml") else "proxy"
                    payload = routing.rule_payload(custom_domains[direction], direction).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/yaml")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)

                def log_message(self, *args):
                    pass

            provider_server = HTTPServer(("127.0.0.1", 0), RuleHandler)
            provider_thread = threading.Thread(target=provider_server.serve_forever)
            provider_thread.daemon = True
            provider_thread.start()
            for name, item in data["rule-providers"].items():
                if item["type"] != "http":
                    continue
                path = root / item["path"]
                path.parent.mkdir(parents=True, exist_ok=True)
                if name.startswith("Custom "):
                    direction = "direct" if name == "Custom Direct" else "proxy"
                    domains = custom_domains[direction]
                    path.write_text(routing.rule_payload(domains, direction), encoding="utf-8")
                else:
                    source = Path(os.environ["SMART_ROUTING_CACHE"]) / item["path"]
                    self.assertTrue(source.is_file(), "Missing verified provider " + name)
                    shutil.copyfile(str(source), str(path))
            def free_port():
                with socket.socket() as connection:
                    connection.bind(("127.0.0.1", 0))
                    return connection.getsockname()[1]
            mixed_port, controller_port = free_port(), free_port()
            cases = [
                ("www.bilibili.com", "STATIC-SELECT", "Custom Proxy"),
                ("cdn.bilivideo.com", "DIRECT", "Bilibili"),
                ("static.hdslb.com", "DIRECT", "Bilibili"),
                ("www.iqiyi.com", "DIRECT", "IQIYI"),
                ("pic.qiyipic.com", "DIRECT", "IQIYI"),
                ("v.qq.com", "DIRECT", "Tencent Video"),
                ("v.youku.com", "DIRECT", "Youku"),
                ("img.ykimg.com", "DIRECT", "Youku"),
                ("www.mgtv.com", "DIRECT", "Mango TV"),
                ("www.cctv.com", "DIRECT", "CCTV"),
                ("v.douyinvod.com", "DIRECT", "Douyin"),
                ("api.kuaishou.com", "DIRECT", "Kuaishou"),
                ("live.douyuscdn.com", "DIRECT", "Douyu"),
                ("www.huya.com", "DIRECT", "Domestic Media Supplements"),
                ("music.163.com", "DIRECT", "Netease Music"),
                ("y.qq.com", "DIRECT", "Domestic Media Supplements"),
                ("songsearch.kugou.com", "DIRECT", "Kugou Kuwo"),
                ("www.bilibili.tv", "STATIC-SELECT", "Overseas Exceptions"),
                ("intl.iqiyi.com", "STATIC-SELECT", "IQ International"),
                ("www.iq.com", "STATIC-SELECT", "IQ International"),
                ("www.wetv.vip", "STATIC-SELECT", "WeTV"),
                ("www.kwai.com", "STATIC-SELECT", "Overseas Exceptions"),
                ("www.youtube.com", "STATIC-SELECT", "YouTube"),
                ("github.com", "DIRECT", "Custom Direct"),
                ("forced.cn", "STATIC-SELECT", "Custom Proxy"),
                ("www.google.cn", "STATIC-SELECT", "Overseas"),
                ("api.ipify.org", "STATIC-SELECT", "api.ipify.org"),
                ("a-previously-unlisted.cn", "DIRECT", "China Domains"),
                ("china-ip.example.test", "DIRECT", "China IPs"),
                ("unlisted-overseas.example.test", "STATIC-SELECT", ""),
            ]
            hosts = dict((domain, "223.5.5.5" if domain == "china-ip.example.test" else "1.1.1.1")
                         for domain, _, _ in cases)
            content = routing.render(PROFILE.replace("mixed-port: 0", "mixed-port: " + str(mixed_port)),
                                     NODES, [], "smart", origin="http://127.0.0.1:" + str(provider_server.server_port),
                                     rule_token=TEST_TOKEN)
            content += "\nexternal-controller: 127.0.0.1:" + str(controller_port) + "\nhosts: " + json.dumps(hosts) + "\n"
            config = root / "test.yaml"
            config.write_text(content, encoding="utf-8")
            core = os.environ["SMART_ROUTING_CORE"]
            syntax = subprocess.run([core, "-t", "-d", str(root), "-f", str(config)],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
            self.assertEqual(syntax.returncode, 0, syntax.stdout.decode("utf-8", errors="replace"))
            with (root / "runtime.log").open("wb") as log:
                process = subprocess.Popen([core, "-d", str(root), "-f", str(config)], stdout=log, stderr=log)
                try:
                    base = "http://127.0.0.1:" + str(controller_port)
                    for attempt in range(100):
                        try:
                            urlopen(base + "/version", timeout=0.2).close()
                            break
                        except OSError:
                            time.sleep(0.05)
                    else:
                        self.fail("Isolated Mihomo did not start.")
                    # Provider initialization is asynchronous; readiness of the
                    # controller alone does not imply its lists have loaded.
                    for attempt in range(100):
                        with urlopen(base + "/providers/rules", timeout=1) as response:
                            provider_state = json.loads(response.read())["providers"]
                        if all(provider_state[name].get("ruleCount", 0) > 0 for name in data["rule-providers"]):
                            break
                        time.sleep(0.05)
                    else:
                        self.fail("Verified rule providers did not initialize: " + repr([
                            (name, provider_state.get(name, {}).get("ruleCount"),
                             list(provider_state.get(name, {}))) for name in data["rule-providers"]]))
                    for domain, expected_chain, expected_payload in cases:
                        with self.subTest(domain=domain):
                            with socket.create_connection(("127.0.0.1", mixed_port), timeout=3) as connection:
                                connection.settimeout(3)
                                connection.sendall(("CONNECT " + domain + ":443 HTTP/1.1\r\nHost: " + domain + "\r\n\r\n").encode("ascii"))
                                self.assertIn(b"200", connection.recv(1024))
                                # Mihomo lazily opens upstream after the first tunnel byte.
                                connection.sendall(b"x")
                                row = None
                                for attempt in range(50):
                                    with urlopen(base + "/connections", timeout=1) as response:
                                        rows = json.loads(response.read()).get("connections") or []
                                    row = next((item for item in rows if item["metadata"]["host"] == domain), None)
                                    if row:
                                        break
                                    time.sleep(0.05)
                                self.assertIsNotNone(row, "No routed connection for " + domain)
                                self.assertIn(expected_chain, row["chains"])
                                self.assertEqual(row["rulePayload"], expected_payload)
                    # Editing the served lists changes the same running core,
                    # without changing or importing its configuration again.
                    custom_domains["direct"] = []
                    custom_domains["proxy"] = []
                    for name in ("Custom%20Direct", "Custom%20Proxy"):
                        with urlopen(Request(base + "/providers/rules/" + name, method="PUT"), timeout=3) as response:
                            self.assertEqual(response.status, 204)
                    for domain, expected in (("github.com", "STATIC-SELECT"), ("www.bilibili.com", "DIRECT")):
                        with socket.create_connection(("127.0.0.1", mixed_port), timeout=3) as connection:
                            connection.settimeout(3)
                            connection.sendall(("CONNECT " + domain + ":443 HTTP/1.1\r\nHost: " + domain + "\r\n\r\n").encode("ascii"))
                            connection.recv(1024)
                            connection.sendall(b"x")
                            for attempt in range(50):
                                with urlopen(base + "/connections", timeout=1) as response:
                                    rows = json.loads(response.read()).get("connections") or []
                                row = next((item for item in rows if item["metadata"]["host"] == domain), None)
                                if row:
                                    break
                                time.sleep(0.05)
                            self.assertIsNotNone(row)
                            self.assertIn(expected, row["chains"])
                    self.assertFalse(any(path.name.lower().endswith((".mmdb", ".metadb")) for path in root.rglob("*")))
                finally:
                    process.terminate()
                    process.wait(timeout=10)
                    provider_server.shutdown()
                    provider_server.server_close()


if __name__ == "__main__":
    unittest.main()
