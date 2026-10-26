import base64
import copy
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import configure_reality as base
import configure_static_exits as static

PRIVATE = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
PUBLIC = base64.urlsafe_b64encode(bytes(range(32, 64))).decode().rstrip("=")
OLD_ID = "22d0b41d-2eec-437b-b87d-e3e1a64d88a6"
SHORT = "0123456789abcdef"


def exit_spec(label="A", address="8.8.8.8", port=1080):
    return {"label": label, "address": address, "port": port,
            "username": "test-user", "password": "test-password"}


def fixture():
    return base.server_config(OLD_ID, PRIVATE, SHORT)


class StaticPolicyTests(unittest.TestCase):
    def test_only_known_base_config_and_matching_profile_are_accepted(self):
        config = fixture()
        profile = base.client_profile("8.8.8.8", OLD_ID, PUBLIC, SHORT)
        self.assertEqual(static.inspect_base(config, profile, "8.8.8.8"), (PUBLIC, SHORT))
        changed = copy.deepcopy(config)
        changed["routing"]["rules"].append({"type": "field", "port": "80", "outboundTag": "direct"})
        for candidate, client in ((changed, profile), (config, profile.replace(PUBLIC, "BAD"))):
            with self.assertRaises(RuntimeError) as caught:
                static.inspect_base(candidate, client, "8.8.8.8")
            self.assertNotIn(PRIVATE, str(caught.exception))

    def test_private_guard_and_existing_identity_are_preserved(self):
        original = fixture()
        extended, nodes = static.extend_config(original, [exit_spec("A"), exit_spec("B")])
        self.assertEqual(original, fixture())
        self.assertEqual(extended["routing"]["rules"][0], original["routing"]["rules"][0])
        self.assertEqual(extended["inbounds"][0]["settings"]["clients"][0],
                         original["inbounds"][0]["settings"]["clients"][0])
        self.assertEqual(extended["inbounds"][0]["streamSettings"],
                         original["inbounds"][0]["streamSettings"])
        self.assertNotEqual(nodes[0]["id"], nodes[1]["id"])
        self.assertNotIn(OLD_ID, [node["id"] for node in nodes])
        for client, node, outbound in zip(extended["inbounds"][0]["settings"]["clients"][1:],
                                         nodes, extended["outbounds"][2:]):
            routes = [rule for rule in extended["routing"]["rules"] if rule.get("user") == [client["email"]]]
            self.assertEqual(len(routes), 2)
            self.assertEqual(routes[0]["network"], "udp")
            self.assertEqual(routes[0]["outboundTag"], "block")
            self.assertEqual(routes[1]["outboundTag"], outbound["tag"])
            self.assertEqual(node["id"], client["id"])

    def test_existing_reality_hostname_is_preserved_and_mismatches_are_rejected(self):
        config = base.server_config(OLD_ID, PRIVATE, SHORT, target="www.cloudflare.com")
        profile = base.client_profile("8.8.8.8", OLD_ID, PUBLIC, SHORT, target="www.cloudflare.com")
        self.assertEqual(static.inspect_base(config, profile, "8.8.8.8"), (PUBLIC, SHORT))
        _, nodes = static.extend_config(config, [exit_spec()])
        exported = static.client_profile("8.8.8.8", PUBLIC, SHORT, nodes, server_name="www.cloudflare.com")
        self.assertIn('servername: "www.cloudflare.com"', exported)
        with self.assertRaises(RuntimeError):
            static.inspect_base(config, base.client_profile("8.8.8.8", OLD_ID, PUBLIC, SHORT), "8.8.8.8")
        altered = copy.deepcopy(config)
        altered["inbounds"][0]["streamSettings"]["realitySettings"]["target"] = "unrelated.example.com:443"
        with self.assertRaises(RuntimeError):
            static.inspect_base(altered, profile, "8.8.8.8")

    def test_new_client_has_switchable_exits_without_provider_credentials(self):
        _, nodes = static.extend_config(fixture(), [exit_spec("A"), exit_spec("B")])
        profile = static.client_profile("8.8.8.8", PUBLIC, SHORT, nodes)
        self.assertIn('name: "STATIC-A"', profile)
        self.assertIn('name: "STATIC-B"', profile)
        self.assertIn("udp: false", profile)
        self.assertIn("DOMAIN,api.ipify.org,STATIC-SELECT", profile)
        group = profile.split("proxy-groups:", 1)[1].split("rules:", 1)[0]
        self.assertNotIn("DIRECT", group)
        for credential in (PRIVATE, "test-user", "test-password", OLD_ID):
            self.assertNotIn(credential, profile)

    def test_duplicate_labels_and_invalid_credentials_are_rejected(self):
        with self.assertRaises(ValueError):
            static.extend_config(fixture(), [exit_spec("A"), exit_spec("a")])
        for username, password in (("user", ""), ("", "pass"), ("user", "secret\nurl=bad"),
                                   ("user:bad", "pass"), ("user", "x" * 256)):
            with self.assertRaises(ValueError) as caught:
                static.validate_credentials(username, password)
            self.assertNotIn("secret", str(caught.exception))

    def test_endpoint_dns_must_resolve_to_public_addresses(self):
        def resolver_for(address):
            return lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 1080))]
        self.assertEqual(static.validate_endpoint("proxy.example.com", 1080,
                                                 resolver_for("8.8.8.8")), "proxy.example.com")
        for address in ("127.0.0.1", "169.254.169.254", "10.0.0.1", "198.18.0.1"):
            with self.assertRaises(ValueError):
                static.validate_endpoint("proxy.example.com", 1080, resolver_for(address))
        with self.assertRaises(ValueError):
            static.validate_endpoint("socks5://user:pass@proxy.example.com", 1080)

    def test_probe_escapes_credentials_and_never_uses_argv_for_secrets(self):
        spec = exit_spec()
        spec["password"] = 'test-"password\\tail'
        config = static.curl_probe_config(spec)
        self.assertIn('proxy-user = "test-user:test-\\"password\\\\tail"', config)
        with mock.patch.object(static.shutil, "which", return_value="curl"), \
                mock.patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, "1.1.1.1\n", "")) as run:
            self.assertEqual(static.probe_exit(spec), "1.1.1.1")
        self.assertNotIn(spec["password"], " ".join(run.call_args[0][0]))
        self.assertEqual(run.call_args[1]["input"], config)

    def test_probe_errors_do_not_echo_credentials_or_untrusted_output(self):
        result = subprocess.CompletedProcess([], 1, "test-password", "test-password")
        with mock.patch.object(static.shutil, "which", return_value="curl"), \
                mock.patch("subprocess.run", return_value=result):
            with self.assertRaises(RuntimeError) as caught:
                static.probe_exit(exit_spec())
        self.assertNotIn("test-password", str(caught.exception))

    def test_generated_console_payload_loads_both_modules_without_running_setup(self):
        path = Path(__file__).parent / "vps-console-static-exits.txt"
        if not path.exists():
            self.skipTest("Build the console artifact first")
        text = path.read_text(encoding="utf-8")
        self.assertLess(max(len(line.encode("utf-8")) for line in text.splitlines()), 4096)
        match = re.search(r"python3 - <<'XRAY_STATIC_PY'\n(.*)\nXRAY_STATIC_PY\n", text, re.S)
        self.assertIsNotNone(match)
        scope = {"__name__": "console_artifact_test"}
        with mock.patch.dict(sys.modules):
            exec(compile(match.group(1), "console_artifact", "exec"), scope)
            config, nodes = scope["extend_config"](fixture(), [exit_spec()])
            self.assertEqual(config["outbounds"][-1]["protocol"], "socks")
            self.assertEqual(len(nodes), 1)


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="static-exits-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = self.root / "config.json"
        self.profile = self.root / "clash-static-exits.yaml"
        self.original = b'{"original": true}\n'
        self.payload = b'{"updated": true}\n'
        self.real_linux_permissions = os.name == "posix" and os.geteuid() == 0
        self.writer = None
        if not self.real_linux_permissions:
            def portable_writer(path, content, uid, gid, mode=0o600):
                with path.open("xb") as stream:
                    stream.write(content)
            patch = mock.patch.object(base, "write_private", side_effect=portable_writer)
            self.writer = patch.start()
            self.addCleanup(patch.stop)
        base.write_private(self.config, self.original, 0, 0, 0o640)

    def apply(self, runner):
        return static.apply_update(self.config, self.original, self.payload,
                                   self.profile, "PRIVATE-CLIENT", 0, 0, 0, runner)

    def test_success_preserves_private_backup_and_requests_private_permissions(self):
        with mock.patch.object(static, "wait_for_listener"):
            backup = self.apply(mock.Mock())
        self.assertEqual(self.config.read_bytes(), self.payload)
        self.assertEqual(backup.read_bytes(), self.original)
        if self.real_linux_permissions:
            self.assertEqual(self.config.stat().st_mode & 0o777, 0o640)
            self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
            self.assertEqual(self.profile.stat().st_mode & 0o777, 0o600)
        else:
            self.writer.assert_any_call(mock.ANY, self.payload, 0, 0, 0o640)
            self.writer.assert_any_call(backup, self.original, 0, 0)
            self.writer.assert_any_call(self.profile, b"PRIVATE-CLIENT", 0, 0)

    def test_validation_failure_does_not_replace_or_restart(self):
        runner = mock.Mock(side_effect=RuntimeError("Invalid candidate"))
        with self.assertRaises(RuntimeError):
            self.apply(runner)
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertFalse(self.profile.exists())
        self.assertEqual(len(runner.call_args_list), 1)
        self.assertFalse(list(self.root.glob("*.private.json")))

    def test_startup_failure_restores_original_and_removes_new_profile(self):
        runner = mock.Mock()
        with mock.patch.object(static, "wait_for_listener", side_effect=[RuntimeError("Startup failed"), None]):
            with self.assertRaisesRegex(RuntimeError, "Startup failed"):
                self.apply(runner)
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertFalse(self.profile.exists())
        self.assertEqual(len([call for call in runner.call_args_list
                              if call[0][0][:2] == ["systemctl", "restart"]]), 2)
        self.assertEqual(len(list(self.root.glob("config.before-static-*.private.json"))), 1)

    def test_concurrent_edit_is_not_overwritten(self):
        def runner(args, **kwargs):
            if args[0] == str(base.XRAY):
                self.config.write_bytes(b"CONCURRENT-EDIT")
        with self.assertRaisesRegex(RuntimeError, "changed during preparation"):
            self.apply(runner)
        self.assertEqual(self.config.read_bytes(), b"CONCURRENT-EDIT")
        self.assertFalse(self.profile.exists())


def receive_exact(stream, length):
    data = b""
    while len(data) < length:
        part = stream.recv(length - len(data))
        if not part:
            raise OSError("Unexpected proxy EOF")
        data += part
    return data


class FakeSocksHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(5)
            version, length = receive_exact(self.request, 2)
            methods = receive_exact(self.request, length)
            if version != 5 or 2 not in methods:
                return
            self.request.sendall(b"\x05\x02")
            version, length = receive_exact(self.request, 2)
            username = receive_exact(self.request, length)
            length = receive_exact(self.request, 1)[0]
            password = receive_exact(self.request, length)
            if version != 1 or username != b"test-user" or password != b"test-password":
                self.request.sendall(b"\x01\x01")
                return
            self.request.sendall(b"\x01\x00")
            version, command, _, address_type = receive_exact(self.request, 4)
            if version != 5 or command != 1:
                return
            if address_type == 3:
                target = receive_exact(self.request, receive_exact(self.request, 1)[0]).decode("ascii")
            elif address_type == 1:
                target = str(ipaddress.ip_address(receive_exact(self.request, 4)))
            elif address_type == 4:
                target = str(ipaddress.ip_address(receive_exact(self.request, 16)))
            else:
                return
            receive_exact(self.request, 2)
            self.server.targets.append(target)
            self.request.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50")
            request = b""
            while b"\r\n\r\n" not in request:
                request += receive_exact(self.request, 1)
            body = self.server.label.encode("ascii")
            self.request.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: " +
                                 str(len(body)).encode("ascii") + b"\r\n\r\n" + body)
        except OSError:
            return


class FakeSocksServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


@unittest.skipUnless(os.environ.get("XRAY_TEST_BINARY"), "No official test binary")
class OfficialCoreTests(unittest.TestCase):
    def setUp(self):
        self.binary = os.environ["XRAY_TEST_BINARY"]
        self.temporary = tempfile.TemporaryDirectory(prefix="static-core-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_official_core_accepts_two_authenticated_socks_exits(self):
        private, public = base.parse_keys(base.command([self.binary, "x25519"]).stdout)
        original = base.server_config(OLD_ID, private, SHORT)
        config, nodes = static.extend_config(original, [exit_spec("A"), exit_spec("B")])
        path = self.root / "config.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        result = base.command([self.binary, "run", "-test", "-config", str(path)])
        self.assertIn("Configuration OK", result.stdout)
        profile = static.client_profile("8.8.8.8", public, SHORT, nodes)
        self.assertNotIn(private, profile)

    def start_core(self, name, config):
        path = self.root / (name + ".json")
        path.write_text(json.dumps(config), encoding="utf-8")
        process = subprocess.Popen([self.binary, "run", "-config", str(path)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        def stop():
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        self.addCleanup(stop)
        return process

    def open_port(self):
        with socket.socket() as stream:
            stream.bind(("127.0.0.1", 0))
            return stream.getsockname()[1]

    def test_real_core_routes_each_identity_to_its_exit_and_blocks_private_targets(self):
        specs = []
        servers = []
        for label in ("A", "B"):
            server = FakeSocksServer(("127.0.0.1", 0), FakeSocksHandler)
            server.label = label
            server.targets = []
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            servers.append(server)
            specs.append(exit_spec(label, "127.0.0.1", server.server_address[1]))
        config, nodes = static.extend_config(fixture(), specs)
        server_port = self.open_port()
        inbound = config["inbounds"][0]
        inbound["listen"] = "127.0.0.1"
        inbound["port"] = server_port
        inbound["streamSettings"] = {"network": "raw", "security": "none"}
        for client in inbound["settings"]["clients"]:
            client.pop("flow", None)
        self.start_core("routing-server", config)
        client_config = {"log": {"loglevel": "warning"}, "inbounds": [], "outbounds": [],
                         "routing": {"rules": []}}
        local_ports = []
        for index, node in enumerate(nodes):
            port = self.open_port()
            local_ports.append(port)
            tag = f"choice-{index}"
            client_config["inbounds"].append({
                "tag": tag, "listen": "127.0.0.1", "port": port,
                "protocol": "socks", "settings": {"auth": "noauth", "udp": False},
            })
            client_config["outbounds"].append({
                "tag": tag, "protocol": "vless", "settings": {"vnext": [{
                    "address": "127.0.0.1", "port": server_port,
                    "users": [{"id": node["id"], "encryption": "none"}],
                }]}, "streamSettings": {"network": "raw", "security": "none"},
            })
            client_config["routing"]["rules"].append({
                "type": "field", "inboundTag": [tag], "outboundTag": tag,
            })
        self.start_core("routing-client", client_config)
        for port in [server_port] + local_ports:
            for _ in range(40):
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    time.sleep(0.1)
            else:
                self.fail("An official-core fixture did not start listening")

        def request(port, target):
            with socket.create_connection(("127.0.0.1", port), timeout=5) as stream:
                stream.settimeout(5)
                stream.sendall(b"\x05\x01\x00")
                self.assertEqual(receive_exact(stream, 2), b"\x05\x00")
                encoded = target.encode("ascii")
                stream.sendall(b"\x05\x01\x00\x03" + bytes([len(encoded)]) + encoded + b"\x00\x50")
                header = receive_exact(stream, 4)
                if header[1] != 0:
                    raise OSError("Proxy target rejected")
                if header[3] == 1:
                    receive_exact(stream, 6)
                elif header[3] == 3:
                    receive_exact(stream, receive_exact(stream, 1)[0] + 2)
                elif header[3] == 4:
                    receive_exact(stream, 18)
                stream.sendall(b"GET / HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n")
                response = b""
                while True:
                    part = stream.recv(4096)
                    if not part:
                        return response
                    response += part

        for index, label in enumerate(("A", "B")):
            response = request(local_ports[index], "api.ipify.org")
            self.assertEqual(response.split(b"\r\n\r\n", 1)[1], label.encode("ascii"))
            self.assertEqual(len(servers[index].targets), 1)
        before = [len(server.targets) for server in servers]
        try:
            self.assertEqual(request(local_ports[0], "127.0.0.1"), b"")
        except OSError:
            pass
        self.assertEqual([len(server.targets) for server in servers], before)


if __name__ == "__main__":
    unittest.main()
