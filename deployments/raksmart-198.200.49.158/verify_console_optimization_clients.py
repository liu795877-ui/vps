"""Verify preserved 158 REALITY and HY2 identities with isolated Mihomo.

--check-local exercises only synthetic client configuration and never contacts
production. --run reads current credentials through the existing pinned SSH
transport, keeps them in memory, and tests HTTPS egress through TCP/UDP 443.
The client receives configuration through a local named pipe; credentials are
never stored in new files, command-line arguments, or raw process logs. Existing
FlClash, Codex, system proxy, firewall and routing settings are not modified.
"""

import argparse
import base64
import copy
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import tempfile
import threading
import time
from urllib.parse import quote
from urllib.request import ProxyHandler, Request, build_opener

import yaml

import smart_access as live

FOLDER = Path(__file__).resolve().parent
REPORT = FOLDER / "console-optimization-clients-verification.json"
BASELINE = FOLDER / "console-optimization-preflight-20261013.json"
OWNER = "/var/lib/vps-panel"
NAMES = {"reality": "REALITY · TCP兼容", "hy2": "HY2 · 网页切换"}
LEGACY_NAME = "REALITY · 原始客户端"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def canonical(value):
    return sha(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def private_read(sftp, name):
    # Do not save or print the bytes returned by private reads.
    import stat
    info = sftp.lstat(name)
    require(stat.S_ISREG(info.st_mode), "A private source is not a regular file")
    require(info.st_size < 2 * 1024 * 1024, "A private source exceeds its expected bound")
    with sftp.open(name, "rb") as stream:
        return stream.read()


def signature(state):
    return {"base_sha256": canonical(state.get("base")),
            "exit_accounts_sha256": canonical(state.get("exits")),
            "history_sha256": canonical(state.get("history")),
            "rules_sha256": canonical({key: state.get(key) for key in
                                       ("routing_mode", "domains", "direct_domains", "rule_token")}),
            "auto_identity_sha256": canonical(state.get("auto_id"))}


def collect(sftp, baseline):
    state = json.loads(private_read(sftp, OWNER + "/state.private.json").decode())
    registry = json.loads(private_read(sftp, OWNER + "/hy2.private.json").decode())
    users = json.loads(private_read(sftp, OWNER + "/users.private.json").decode())
    require(users.get("users") == [], "Acceptance requires the preserved single-administrator baseline")
    require(registry.get("enabled") is True, "HY2 integration is not enabled")
    require(set(registry.get("accounts", {})) == {"admin"}, "HY2 registry contains unexpected accounts")
    current = signature(state)
    require(all(current[key] == baseline["state"][key] for key in current),
            "Existing administrator identity, exit, rules or history changed")
    require(baseline["authenticated"]["active_target"] == "server"
            and state.get("active_id") in (None, "server"), "Current web exit differs from production baseline")
    require(sha(private_read(sftp, OWNER + "/auth.private.json"))
            == baseline["protected_files"][OWNER + "/auth.private.json"]["sha256"],
            "Administrator login authentication changed")
    certificate = private_read(sftp, "/usr/local/etc/raksmart-hy2/server.crt.pem")
    require(sha(certificate) == baseline["protected_files"]["/usr/local/etc/raksmart-hy2/server.crt.pem"]["sha256"],
            "Existing HY2 certificate bytes changed")
    der = ssl.PEM_cert_to_DER_cert(certificate.decode("ascii"))
    pin = sha(der)
    require(pin == baseline["legacy_hy2"]["certificate_sha256"], "Existing HY2 certificate pin changed")
    entry = registry["accounts"]["admin"]
    require(entry.get("port") == 443 and isinstance(entry.get("password"), str)
            and sha(entry["password"].encode()) == baseline["legacy_hy2"]["password_sha256"],
            "Existing HY2 password or public entrance changed")
    require(registry.get("sni") == baseline["legacy_hy2"]["sni"]
            and registry.get("certificate_sha256") == pin, "HY2 registry certificate identity differs")
    profile = yaml.safe_load(state["profile"])
    nodes = {}
    for source, name in NAMES.items():
        matches = [node for node in profile.get("proxies", []) if node.get("name") == name]
        require(len(matches) == 1, "Current profile lacks a unique transport node")
        node = copy.deepcopy(matches[0])
        require(node.get("server") == live.IP and node.get("port") == 443 and not node.get("dialer-proxy"),
                "A transport targets another public entrance or dialer")
        if source == "reality":
            require(node.get("type") == "vless" and node.get("uuid") == state.get("auto_id"),
                    "REALITY profile identity differs from the preserved AUTO identity")
        else:
            require(node.get("type") == "hysteria2" and node.get("password") == entry["password"]
                    and node.get("sni") == registry["sni"] and node.get("skip-cert-verify") is False
                    and node.get("fingerprint", "").replace(":", "").lower() == pin,
                    "HY2 profile does not retain its password, SNI and certificate pin")
        nodes[source] = node
    group = [group for group in profile.get("proxy-groups", []) if group.get("name") == "AUTO · 网页切换"]
    require(len(group) == 1 and group[0].get("type") == "fallback"
            and group[0].get("proxies") == [NAMES["hy2"], NAMES["reality"]],
            "AUTO does not prioritize HY2 then REALITY")
    primary_id = state["base"]["inbounds"][0]["settings"]["clients"][0]["id"]
    require(isinstance(primary_id, str) and primary_id, "Original primary REALITY identity is missing")
    nodes["reality_legacy"] = copy.deepcopy(nodes["reality"])
    nodes["reality_legacy"].update(name=LEGACY_NAME, uuid=primary_id)
    return nodes, current, live.IP


class MemoryPipe:
    """One Windows local named pipe supplies YAML bytes without writing a file."""
    def __init__(self, payload):
        require(os.name == "nt", "This acceptance transport requires Windows")
        self.payload = payload
        self.path = "\\\\.\\pipe\\console158-" + secrets.token_hex(16)
        self.error = None
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.CreateNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID]
        self.kernel.CreateNamedPipeW.restype = wintypes.HANDLE
        self.kernel.ConnectNamedPipe.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
        self.kernel.WriteFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                                       ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
        self.kernel.FlushFileBuffers.argtypes = [wintypes.HANDLE]
        self.kernel.DisconnectNamedPipe.argtypes = [wintypes.HANDLE]
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        self.kernel.CreateFileW.restype = wintypes.HANDLE
        self.kernel.ReadFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                                      ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
        # Go opens a config path both for metadata and to read it. Keep several
        # local instances ready so the metadata probe does not consume the only
        # pipe instance; closed metadata probes can legitimately break writes.
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.handles = set()
        self.threads = []
        for index in range(8):
            handle = self._instance(first=index == 0)
            self.handles.add(handle)
            thread = threading.Thread(target=self._serve, args=(handle,), daemon=True)
            self.threads.append(thread)
            thread.start()

    def _instance(self, first=False):
        handle = self.kernel.CreateNamedPipeW(self.path, 0x00000002 | (0x00080000 if first else 0),
                                               0x00000008, 16, 65536, 65536, 0, None)
        require(handle != ctypes.c_void_p(-1).value, "In-memory client configuration pipe could not be created")
        return handle

    def _serve(self, handle):
        while True:
            try:
                connected = self.kernel.ConnectNamedPipe(handle, None)
                require(connected or ctypes.get_last_error() == 535, "In-memory client configuration pipe did not connect")
                if self.stop.is_set():
                    return
                buffer = ctypes.create_string_buffer(self.payload)
                written = wintypes.DWORD()
                ok = self.kernel.WriteFile(handle, buffer, len(self.payload), ctypes.byref(written), None)
                if not ok and ctypes.get_last_error() in (109, 232, 233):
                    pass  # Metadata reader closed without reading YAML.
                else:
                    require(ok and written.value == len(self.payload), "In-memory client configuration write failed")
                    self.kernel.FlushFileBuffers(handle)
            except Exception:
                self.error = "In-memory client configuration transport failed"
                return
            finally:
                self.kernel.CloseHandle(handle)
                with self.lock:
                    self.handles.discard(handle)
            if self.stop.is_set():
                return
            handle = self._instance()
            with self.lock:
                self.handles.add(handle)

    def close(self):
        self.stop.set()
        for unused in range(16):
            if not any(thread.is_alive() for thread in self.threads):
                break
            # Open and drain a stalled server if a child exited before loading
            # configuration. Nothing is persisted or returned to the caller.
            reader = self.kernel.CreateFileW(self.path, 0x80000000, 0, None, 3, 0, None)
            if reader != ctypes.c_void_p(-1).value:
                buffer = ctypes.create_string_buffer(8192)
                amount = wintypes.DWORD()
                while self.kernel.ReadFile(reader, buffer, len(buffer), ctypes.byref(amount), None) and amount.value:
                    pass
                self.kernel.CloseHandle(reader)
        for thread in self.threads:
            thread.join(timeout=.5)
        require(not any(thread.is_alive() for thread in self.threads), "Client configuration pipe did not close")
        self.payload = b""


def configuration(nodes, proxy_port, control_port, secret):
    return {"mixed-port": proxy_port, "port": 0, "socks-port": 0, "allow-lan": False,
            "bind-address": "127.0.0.1", "ipv6": False, "tun": {"enable": False},
            "interface-name": "WLAN", "dns": {"enable": False}, "log-level": "silent",
            "mode": "rule", "external-controller": "127.0.0.1:" + str(control_port), "secret": secret,
            "profile": {"store-selected": False, "store-fake-ip": False}, "proxies": list(nodes.values()),
            "proxy-groups": [{"name": "VERIFY", "type": "select",
                              "proxies": [node["name"] for node in nodes.values()]}], "rules": ["MATCH,VERIFY"]}


class IsolatedClient:
    def __init__(self, directory, nodes):
        self.directory = directory
        self.proxy_port, self.control_port = live.free_port(), live.free_port()
        while self.proxy_port == self.control_port:
            self.control_port = live.free_port()
        self.secret = secrets.token_urlsafe(32)
        self.payload = yaml.safe_dump(configuration(nodes, self.proxy_port, self.control_port, self.secret),
                                      allow_unicode=True, sort_keys=False).encode("utf-8")
        self.process = None
        self.opener = build_opener(ProxyHandler({}))

    def syntax(self):
        pipe = MemoryPipe(self.payload)
        try:
            result = subprocess.run([str(live.BINARY), "-t", "-d", str(self.directory), "-f", pipe.path],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    timeout=30, creationflags=live.NO_WINDOW)
            require(result.returncode == 0 and pipe.error is None,
                    "Official Mihomo rejected the in-memory isolated transport configuration")
        finally:
            pipe.close()

    def start(self):
        self.syntax()
        pipe = MemoryPipe(self.payload)
        try:
            self.process = subprocess.Popen([str(live.BINARY), "-d", str(self.directory), "-f", pipe.path],
                                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                             stderr=subprocess.DEVNULL, creationflags=live.NO_WINDOW)
            deadline = time.monotonic() + 20
            while True:
                require(self.process.poll() is None, "Isolated official client exited before acceptance")
                try:
                    self.api("/version")
                    break
                except OSError:
                    require(time.monotonic() < deadline, "Isolated client controller did not start")
                    time.sleep(.2)
            require(pipe.error is None, "In-memory configuration could not be supplied")
        except Exception:
            self.close()
            raise
        finally:
            pipe.close()

    def api(self, path, method="GET", data=None):
        request = Request("http://127.0.0.1:" + str(self.control_port) + path,
                          json.dumps(data).encode() if data is not None else None,
                          {"Authorization": "Bearer " + self.secret, "Content-Type": "application/json"}, method=method)
        with self.opener.open(request, timeout=5) as response:
            body = response.read()
            return json.loads(body) if body else None

    def identity(self, name, expected):
        self.api("/connections", "DELETE")
        self.api("/proxies/" + quote("VERIFY", safe=""), "PUT", {"name": name})
        started = time.monotonic()
        for attempt in range(3):
            result = subprocess.run([live.CURL, "--proxy", "socks5h://127.0.0.1:" + str(self.proxy_port),
                "--noproxy", "", "--connect-timeout", "8", "--max-time", "20", "--silent", "--show-error",
                "--write-out", "\n%{http_code}", "https://api.ipify.org"],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=25, creationflags=live.NO_WINDOW)
            if result.returncode == 0:
                break
            time.sleep(.2)
        body, _, status = result.stdout.decode("ascii", errors="replace").rpartition("\n")
        require(result.returncode == 0 and status == "200", "A preserved transport could not establish real HTTPS egress")
        try:
            observed = str(ipaddress.ip_address(body.strip()))
        except ValueError:
            raise RuntimeError("A transport returned an invalid egress address") from None
        require(observed == expected, "Transport egress differs from the preserved current web exit")
        return {"success": True, "http_status": 200, "observed_ip": observed,
                "expected_ip": expected, "seconds": round(time.monotonic() - started, 3)}

    def close(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.payload = b""
        self.secret = ""


def synthetic_nodes():
    nodes = {"reality": {"name": NAMES["reality"], "type": "vless", "server": "192.0.2.158", "port": 443,
            "uuid": "11111111-1111-4111-8111-111111111111", "network": "tcp", "tls": True,
            "flow": "xtls-rprx-vision", "servername": "www.microsoft.com", "client-fingerprint": "chrome",
            "reality-opts": {"public-key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "short-id": "a1b2c3d4"}},
            "hy2": {"name": NAMES["hy2"], "type": "hysteria2", "server": "192.0.2.158", "port": 443,
                    "password": "synthetic-password-123456789012345678901234567", "sni": "example.invalid",
                    "skip-cert-verify": False, "fingerprint": "a" * 64, "udp": False}}
    nodes["reality_legacy"] = copy.deepcopy(nodes["reality"])
    nodes["reality_legacy"].update(name=LEGACY_NAME, uuid="22222222-2222-4222-8222-222222222222")
    return nodes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check-local", action="store_true")
    mode.add_argument("--run", action="store_true")
    args = parser.parse_args()
    report = {"success": False, "checked_at": datetime.now(timezone.utc).isoformat(),
              "deployment_ip": live.IP, "secrets_included": False, "configuration_mutations": 0,
              "configuration_transport": "local Windows named pipe; memory only",
              "system_proxy_changed": False, "flclash_changed": False, "raw_process_output_saved": False,
              "mode": "local-synthetic" if args.check_local else "public-real-clients", "transports": {}}
    client = None
    stage = "local_setup"
    root = FOLDER / ".validation"
    root.mkdir(exist_ok=True)
    try:
        require(live.BINARY.is_file(), "Reviewed official Mihomo executable is unavailable")
        report["client_binary_sha256"] = sha(live.BINARY.read_bytes())
        with tempfile.TemporaryDirectory(prefix="console158-clients-", dir=str(root)) as directory:
            if args.check_local:
                client = IsolatedClient(Path(directory), synthetic_nodes())
                stage = "synthetic_loopback_start"
                client.start()
                client.close()
                report.update(success=True, production_contacted=False, private_data_read=False)
            else:
                baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
                require(baseline.get("success") is True and baseline.get("server") == live.IP
                        and baseline.get("secrets_included") is False, "Verified public preflight is missing")
                stage = "production_identity"
                import ssh_access
                require(ssh_access.HOST_KEYS.is_file(), "Pinned SSH host key is missing")
                live.physical_wifi()
                connection = ssh_access.connect()
                try:
                    actual_key = connection.get_transport().get_remote_server_key()
                    hostkey = base64.b64encode(hashlib.sha256(actual_key.asbytes()).digest()).decode().rstrip("=")
                    require(actual_key.get_name() == "ssh-ed25519"
                            and hostkey == "IteVQXuF4cffrUYsYkgkpc/m5pTp/2n0CLVK0ej9pzs",
                            "SSH host key differs from the verified 158 baseline")
                    with connection.open_sftp() as sftp:
                        nodes, before, expected = collect(sftp, baseline)
                    client = IsolatedClient(Path(directory), nodes)
                    stage = "isolated_client_start"
                    client.start()
                    for source in ("reality", "reality_legacy", "hy2"):
                        stage = "real_" + source + "_egress"
                        report["transports"][source] = client.identity(nodes[source]["name"], expected)
                    stage = "post_acceptance_identity"
                    with connection.open_sftp() as sftp:
                        _, after, _ = collect(sftp, baseline)
                    require(before == after, "Existing routing or identities changed during client acceptance")
                    report.update(success=True, physical_wlan=True, public_tcp443_verified=True,
                                  public_udp443_verified=True, old_reality_identity_preserved=True,
                                  old_primary_reality_identity_preserved=True,
                                  old_hy2_password_preserved=True, old_hy2_tls_pin_preserved=True,
                                  web_exit_preserved=True, hy2_follows_web_exit=True,
                                  expected_current_egress=expected, source_signatures_preserved=True)
                finally:
                    connection.close()
                    if client:
                        client.close()
    except Exception:
        # Only fixed stage and message are retained; no private source,
        # traceback, subprocess output, or profile contents enter the report.
        report["failure"] = {"stage": stage, "message": "Isolated client acceptance did not pass"}
    finally:
        if client:
            client.close()
        report_name = ("console-optimization-clients-local.json" if args.check_local else REPORT.name)
        (FOLDER / report_name).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"success": report["success"], "stage": stage,
                          "transport_count": len(report["transports"]), "report": report_name}))
    return 0 if report["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
