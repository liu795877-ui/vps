"""Real generated-profile contracts for one-file HY2 / REALITY access."""

import base64
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

import configure_static_exits as static
from panel import accelerated_client as accelerated
from panel import routing


SERVER = "198.51.100.63"
PASSWORD = "test-only-independent-hy2-password"
PIN = "a1" * 32
TOKEN = "test-only-independent-rule-capability-12345"
NODES = [{"name": accelerated.AUTO, "id": "77777777-7777-4777-8777-777777777777"},
         {"name": "出口 · 测试", "id": "88888888-8888-4888-8888-888888888888"}]


def generated(mode="smart", port=1443):
    public_key = base64.urlsafe_b64encode(bytes(range(1, 33))).decode("ascii").rstrip("=")
    source = static.client_profile(SERVER, public_key, "1234abcd", NODES,
                                   server_port=port)
    return routing.render(source, NODES, ["github.com"], mode,
                          origin="https://example.invalid", direct_domains=["chaoxing.com"],
                          rule_token=TOKEN)


def section(text, name):
    start, end, inline, body = accelerated._section(text, name)
    return text[start:end], inline, body


def compose(source=None, **kwargs):
    return accelerated.compose(source if source is not None else generated(), SERVER,
                               kwargs.pop("port", 1443), kwargs.pop("password", PASSWORD),
                               kwargs.pop("certificate_sha256", PIN), **kwargs)


class AcceleratedProfileTests(unittest.TestCase):
    def test_all_routing_modes_keep_rules_providers_and_dns_exactly(self):
        for mode in ("manual", "smart", "services"):
            with self.subTest(mode=mode):
                original = generated(mode)
                result = compose(original)
                self.assertEqual(result[accelerated._section(result, "proxy-groups")[1]:],
                                 original[accelerated._section(original, "proxy-groups")[1]:])
                self.assertEqual(result[:accelerated._section(result, "proxies")[0]],
                                 original[:accelerated._section(original, "proxies")[0]])
                if mode != "smart":
                    self.assertIn("DOMAIN-SUFFIX,chaoxing.com,DIRECT", result)
                if mode == "smart":
                    self.assertIn(TOKEN, result)
                    self.assertIn('"proxy": "DIRECT"', result)

    def test_auto_fallback_and_explicit_tcp_keep_account_identity_and_fixed_exit(self):
        original = generated()
        result = compose(original)
        blocks = dict(accelerated._proxy_blocks(section(result, "proxies")[2]))
        before = dict(accelerated._proxy_blocks(section(original, "proxies")[2]))
        self.assertEqual(set(blocks), {accelerated.HY2, accelerated.REALITY, "出口 · 测试"})
        self.assertEqual(blocks["出口 · 测试"], before["出口 · 测试"])
        self.assertIn(NODES[0]["id"], blocks[accelerated.REALITY])
        groups = json.loads(section(result, "proxy-groups")[1])
        selection = next(group for group in groups if group["name"] == "STATIC-SELECT")
        self.assertEqual(selection["proxies"], [accelerated.AUTO, accelerated.REALITY, "出口 · 测试"])
        fallback = next(group for group in groups if group["name"] == accelerated.AUTO)
        self.assertEqual(fallback["type"], "fallback")
        self.assertEqual(fallback["proxies"], [accelerated.HY2, accelerated.REALITY])
        self.assertEqual(fallback["url"], "https://api.ipify.org")
        self.assertTrue(fallback["lazy"])

    def test_hy2_tls_pin_and_tcp_only_settings_are_independent_per_port(self):
        for port in (443, 1443, 2443):
            result = compose(generated(port=port), port=port)
            hy2 = dict(accelerated._proxy_blocks(section(result, "proxies")[2]))[accelerated.HY2]
            self.assertIn("    port: " + str(port), hy2)
            self.assertIn("    password: " + json.dumps(PASSWORD), hy2)
            self.assertIn('    fingerprint: "' + PIN + '"', hy2)
            self.assertIn("    skip-cert-verify: false", hy2)
            self.assertIn("    udp: false", hy2)
            self.assertIn("    bbr-profile: standard", hy2)
            self.assertNotIn("uuid:", hy2)

    def test_recomposition_is_idempotent_and_replaces_revoked_hy2_credential(self):
        first = compose()
        self.assertEqual(first, compose(first))
        changed = compose(first, password="replacement-only-test-credential")
        self.assertNotIn(PASSWORD, changed)
        self.assertEqual(len(accelerated._proxy_blocks(section(changed, "proxies")[2])), 3)
        self.assertEqual(sum(group["name"] == accelerated.AUTO
                             for group in json.loads(section(changed, "proxy-groups")[1])), 1)
        self.assertEqual(section(first, "rules")[0], section(changed, "rules")[0])

    def test_service_groups_and_fixed_name_unicode_survive(self):
        original = generated("services")
        source_groups = json.loads(section(original, "proxy-groups")[1])
        actual_groups = json.loads(section(compose(original), "proxy-groups")[1])
        self.assertEqual(actual_groups[1:-1], source_groups[1:])
        self.assertIn('出口 · 测试', compose(original))

    def test_quotes_and_backslashes_in_auth_are_yaml_safe(self):
        password = 'test-only:"quoted"\\password'
        result = compose(password=password)
        encoded = re.search(r'^    password: (.+)$', result, re.M).group(1)
        self.assertEqual(json.loads(encoded), password)

    def test_invalid_inputs_and_reserved_name_collisions_fail_without_private_output(self):
        invalid = [{"port": True}, {"port": 0}, {"port": 65536},
                   {"password": "short"}, {"password": "long-enough\nprivate"},
                   {"certificate_sha256": "private-bad-fingerprint"}, {"sni": "invalid\nname"}]
        for values in invalid:
            with self.subTest(values=list(values)):
                with self.assertRaises(ValueError) as error:
                    compose(**values)
                self.assertNotIn(PASSWORD, str(error.exception))
        with self.assertRaises(ValueError):
            compose(generated().replace(json.dumps(accelerated.AUTO), json.dumps("another node")))
        with self.assertRaises(ValueError):
            accelerated.compose(generated(), "not-a-server-ip", 443, PASSWORD, PIN)

    @unittest.skipUnless(os.environ.get("MIHOMO_TEST_BINARY"), "No official Mihomo test binary")
    def test_official_mihomo_accepts_the_generated_dual_protocol_profile(self):
        # Manual mode requires no external rule source, so validation stays
        # isolated and doesn't fetch private or production subscriptions.
        with tempfile.TemporaryDirectory(prefix="hy2-compose-check-") as folder:
            path = Path(folder) / "client.yaml"
            path.write_text(compose(generated("manual")), encoding="utf-8")
            result = subprocess.run([os.environ["MIHOMO_TEST_BINARY"], "-t", "-d", folder,
                                     "-f", str(path)], stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=25)
            self.assertEqual(result.returncode, 0, "Official Mihomo rejected the generated dual protocol profile")


if __name__ == "__main__":
    unittest.main()
