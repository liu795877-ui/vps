"""Trusted HTTPS and an isolated AUTO client; never changes FlClash settings.

Only authenticated reads and session login/logout are sent by this verifier.
Private diagnostics and downloaded client secrets remain in this deployment.
Run after the deployment has initialized its first downloadable AUTO profile.
"""

from datetime import datetime, timedelta, timezone
import argparse
import copy
import http.client
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import time
import traceback
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, Request, build_opener

import yaml

FOLDER = Path(__file__).resolve().parent
HOST = "198-200-49-63.sslip.io"
IP = "198.200.49.63"
ORIGIN = "https://" + HOST + ":8443"
AUTO_NAME = "AUTO · 网页切换"
BINARY = Path("C:/Users/LENOVO/.cockpit_tools/proxy-engine/"
              "release-490ee635-5175-46ca-a8c5-5e8a327cda34/mihomo.exe")
CURL = "C:/Windows/System32/curl.exe"
NO_WINDOW = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
cookie = None
_wifi = None


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def physical_wifi():
    global _wifi
    if _wifi is None:
        result = subprocess.run([
            "powershell.exe", "-NoProfile", "-Command",
            "Get-NetIPAddress -InterfaceAlias WLAN -AddressFamily IPv4 | "
            "Where-Object AddressState -eq Preferred | "
            "Select-Object -First 1 IPAddress,InterfaceIndex | ConvertTo-Json -Compress",
        ], capture_output=True, check=True, timeout=15, creationflags=NO_WINDOW)
        _wifi = json.loads(result.stdout.decode("utf-8-sig"))
        require(isinstance(_wifi, dict) and _wifi.get("IPAddress") and _wifi.get("InterfaceIndex"),
                "The physical WLAN has no usable IPv4 address")
    return _wifi


def physical_socket(port, timeout=12):
    wifi = physical_wifi()
    # Retry only the TCP handshake, before any HTTP request can be sent.
    for attempt in range(3):
        stream = socket.socket()
        try:
            stream.settimeout(timeout)
            stream.setsockopt(socket.IPPROTO_IP, 31, socket.htonl(wifi["InterfaceIndex"]))
            stream.bind((wifi["IPAddress"], 0))
            stream.connect((IP, port))
            return stream
        except OSError:
            stream.close()
            if attempt == 2:
                raise
            time.sleep(.4)
        except Exception:
            stream.close()
            raise


class PhysicalHTTPS(http.client.HTTPSConnection):
    def connect(self):
        stream = physical_socket(self.port, self.timeout)
        try:
            self.sock = self._context.wrap_socket(stream, server_hostname=HOST)
        except Exception:
            stream.close()
            raise


def request(method, path, data=None, headers=None):
    """Bounded retry for GET only; never repeats a mutation or login POST."""
    extra = {"Origin": ORIGIN}
    if cookie:
        extra["Cookie"] = cookie
    if headers:
        extra.update(headers)
    body = json.dumps(data).encode("utf-8") if data is not None else None
    if body is not None:
        extra["Content-Type"] = "application/json"
    attempts = 3 if method == "GET" else 1
    for attempt in range(attempts):
        connection = PhysicalHTTPS(HOST, 8443, timeout=12, context=ssl.create_default_context())
        try:
            connection.request(method, "/node-console/" + path, body=body, headers=extra)
            response = connection.getresponse()
            result = response.status, dict(response.getheaders()), response.read()
            if method == "GET" and response.status in (502, 503, 504) and attempt + 1 < attempts:
                time.sleep(0.4)
                continue
            return result
        except (OSError, http.client.HTTPException):
            if attempt + 1 == attempts:
                raise
            time.sleep(0.4)
        finally:
            connection.close()


def free_port():
    with socket.socket() as stream:
        stream.bind(("127.0.0.1", 0))
        return stream.getsockname()[1]


def controller_api(opener, address, secret, resource):
    query = Request(address + resource, headers={"Authorization": "Bearer " + secret})
    with opener.open(query, timeout=2) as response:
        return json.loads(response.read())


def no_upstream_credentials(value):
    if isinstance(value, dict):
        require(not {"username", "password"}.intersection(value),
                "Client YAML unexpectedly exposes upstream authentication")
        for child in value.values():
            no_upstream_credentials(child)
    elif isinstance(value, list):
        for child in value:
            no_upstream_credentials(child)


def verify_profile(state, report, log):
    require(state.get("download_ready"), "Initial AUTO profile has not been initialized")
    require((state.get("job") or {}).get("status") != "running", "A panel operation is still running")
    status, _, body = request("GET", "api/profile")
    require(status == 200 and body, "Authenticated profile download failed")
    downloaded = FOLDER / "clash-web-switch.private.yaml"
    downloaded.write_bytes(body)
    profile = yaml.safe_load(body)
    require(isinstance(profile, dict), "Client profile is not a YAML mapping")
    no_upstream_credentials(profile)
    metadata = state.get("client_config", {})
    require(metadata.get("group") == "STATIC-SELECT" and metadata.get("auto_node") == AUTO_NAME,
            "Stable AUTO selection metadata is missing")
    fixed = metadata.get("nodes")
    require(isinstance(fixed, list) and len(fixed) == metadata.get("exit_count"),
            "Applied fixed exit metadata is inconsistent")
    nodes = profile.get("proxies", [])
    require([node.get("name") for node in nodes] == [AUTO_NAME, *fixed],
            "Downloaded profile nodes differ from applied exits")
    require(len(nodes) >= 1 and len({node["name"] for node in nodes}) == len(nodes),
            "AUTO profile node names are missing or duplicate")
    for node in nodes:
        require(node.get("server") == IP and node.get("port") == state["server_port"],
                "A client node points to an unexpected entry server")
        require(node.get("type") == "vless" and node.get("tls") is True and
                not node.get("skip-cert-verify", False) and isinstance(node.get("reality-opts"), dict),
                "The client node does not preserve VLESS REALITY settings")
    group = [item for item in profile.get("proxy-groups", []) if item.get("name") == "STATIC-SELECT"]
    require(len(group) == 1 and group[0].get("type") == "select" and
            group[0].get("proxies") == [AUTO_NAME, *fixed], "AUTO selection group is inconsistent")
    validation = FOLDER / "web-switch-validation"
    validation.mkdir(exist_ok=True)
    syntax_dir = validation / "syntax"
    syntax_dir.mkdir(exist_ok=True)
    require(BINARY.is_file(), "The existing official Mihomo binary was not found")
    check = subprocess.run([str(BINARY), "-t", "-d", str(syntax_dir), "-f", str(downloaded)],
                           stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                           timeout=45, creationflags=NO_WINDOW)
    require(check.returncode == 0, "Downloaded complete profile failed official Mihomo validation")
    report["checks"].append("Downloaded complete profile passes official Mihomo validation")
    proxy_port, controller_port = free_port(), free_port()
    while controller_port == proxy_port:
        controller_port = free_port()
    secret = secrets.token_urlsafe(24)
    isolated = {
        "mixed-port": proxy_port, "bind-address": "127.0.0.1", "allow-lan": False,
        "external-controller": "127.0.0.1:" + str(controller_port), "secret": secret,
        "mode": "rule", "interface-name": "WLAN", "tun": {"enable": False},
        "dns": {"enable": False}, "log-level": "warning",
        "profile": {"store-selected": False, "store-fake-ip": False},
        "proxies": [copy.deepcopy(nodes[0])],
        "proxy-groups": [{"name": "STATIC-SELECT", "type": "select", "proxies": [AUTO_NAME]}],
        "rules": ["MATCH,STATIC-SELECT"],
    }
    client_dir = validation / ("client-" + secrets.token_hex(6))
    client_dir.mkdir()
    client_file = client_dir / "mihomo-auto.private.yaml"
    client_file.write_text(yaml.safe_dump(isolated, allow_unicode=True), encoding="utf-8")
    process = subprocess.Popen([str(BINARY), "-d", str(client_dir), "-f", str(client_file)],
                               stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                               creationflags=NO_WINDOW)
    try:
        opener = build_opener(ProxyHandler({}))
        address = "http://127.0.0.1:" + str(controller_port)
        for _ in range(50):
            require(process.poll() is None, "Isolated Mihomo exited during startup")
            try:
                controller_api(opener, address, secret, "/version")
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("Isolated Mihomo did not become ready")
        expected = IP if state["active_target"] == "server" else (
            (state.get("active") or {}).get("observed_ip") or (state.get("active") or {}).get("expected_ip"))
        require(bool(expected), "The active static exit has no verified expected IP")
        observed = None
        for attempt in range(3):
            result = subprocess.run([
                CURL, "--proxy", "socks5h://127.0.0.1:" + str(proxy_port), "--noproxy", "",
                "--connect-timeout", "8", "--max-time", "25", "--fail", "--silent", "--show-error",
                "https://api.ipify.org",
            ], capture_output=True, timeout=30, stdin=subprocess.DEVNULL, creationflags=NO_WINDOW)
            log.write("AUTO ipify attempt " + str(attempt + 1) + ": " + str(result.returncode) + "\n")
            log.write(result.stdout.decode("utf-8", errors="replace") + "\n")
            log.write(result.stderr.decode("utf-8", errors="replace") + "\n")
            log.flush()
            if result.returncode == 0:
                observed = str(ipaddress.ip_address(result.stdout.decode("ascii").strip()))
                if observed == expected and ipaddress.ip_address(observed).is_global:
                    break
            time.sleep(0.4)
        require(observed == expected, "Isolated AUTO client did not expose the active target IP")
        report["auto_egress"] = {"observed_ip": observed, "expected_ip": expected,
                                 "active_target": state["active_target"], "success": True}
        status, _, body = request("GET", "api/state")
        final_state = json.loads(body)
        require(status == 200 and final_state.get("updated") == state.get("updated") and
                final_state.get("active_target") == state.get("active_target") and
                (final_state.get("active") or {}).get("id") == (state.get("active") or {}).get("id"),
                "The active target changed during verification")
        status, _, body = request("GET", "api/profile")
        require(status == 200 and yaml.safe_load(body)["proxies"][0]["uuid"] == nodes[0]["uuid"],
                "Repeated profile read changed the AUTO identity")
        report["checks"].append("Isolated AUTO client matches active target with stable AUTO identity")
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)


def main():
    global cookie
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-target", choices=("server", "static", "any"), default="server")
    arguments = parser.parse_args()
    report = {"checked_at": datetime.now(timezone(timedelta(hours=8))).isoformat(timespec="seconds"),
              "origin": ORIGIN, "success": False, "checks": [], "transport": "Physical WLAN with normal TLS trust"}
    csrf = None
    stage = "trusted_https"
    with (FOLDER / "panel-verification.private.log").open("w", encoding="utf-8") as log:
        try:
            physical_wifi()
            status, _, body = request("GET", "")
            require(status == 200 and b"login-screen" in body, "Trusted HTTPS login page failed")
            status, _, _ = request("GET", "api/state")
            require(status == 401, "Unauthenticated state access was not rejected")
            status, _, body = request("GET", "api/session")
            require(status == 200 and not json.loads(body)["authenticated"], "Unauthenticated session state is wrong")
            report["checks"].append("Trusted HTTPS and unauthenticated API rejection")
            stage = "authenticated_state"
            login = json.loads((FOLDER / "panel-login.private.json").read_text(encoding="utf-8"))
            url = urlsplit(login["url"])
            require(url.scheme == "https" and url.hostname == HOST and url.port == 8443 and
                    url.path == "/node-console/", "Login file does not belong to the 63 deployment")
            status, headers, body = request("POST", "api/login", {"username": login["username"], "password": login["password"]})
            require(status == 200, "Console login failed")
            cookie_header = headers.get("Set-Cookie", "")
            require(all(flag in cookie_header for flag in ("Secure", "HttpOnly", "SameSite=Strict", "Path=/node-console/")),
                    "Session cookie security attributes are missing")
            cookie = cookie_header.split(";", 1)[0]
            csrf = json.loads(body)["csrf"]
            status, _, body = request("GET", "api/state")
            state = json.loads(body)
            require(status == 200 and state.get("server_ip") == IP and state.get("service_active") and not state.get("demo"),
                    "The live entry node state is incorrect")
            require(state.get("active_target") in ("server", "static"), "Active target is unknown")
            require(arguments.expected_target == "any" or state["active_target"] == arguments.expected_target,
                    "The active target differs from the expected deployment target")
            require(state.get("server_location", {}).get("ip") == IP and
                    state.get("server_location", {}).get("country_code") == "US", "Automatic server location is not the 63 server")
            report["state"] = {"server_ip": IP, "server_port": state["server_port"],
                               "exit_count": len(state["exits"]), "active_target": state["active_target"],
                               "service_active": True}
            report["checks"].append("Authenticated live node and automatic location identify 198.200.49.63")
            stage = "csrf_and_assets"
            for headers in ({}, {"Origin": "https://invalid.example", "X-CSRF-Token": csrf}):
                status, _, _ = request("POST", "api/routing", {"domains": state["domains"], "mode": state["routing_mode"]}, headers=headers)
                require(status == 403, "CSRF or request origin protection failed")
            for path in ("app.js", "style.css", "mark.svg", "rules/domestic-dns.yaml"):
                status, _, body = request("GET", path)
                require(status == 200 and body, "A public asset or rule file is unavailable")
            report["checks"].append("Secure session, CSRF enforcement and public assets")
            stage = "auto_profile"
            verify_profile(state, report, log)
            stage = "logout"
            status, _, _ = request("POST", "api/logout", {}, headers={"X-CSRF-Token": csrf})
            require(status == 200, "Logout failed")
            csrf = None
            status, _, _ = request("GET", "api/state")
            require(status == 401, "Logged out session still grants access")
            cookie = None
            report["checks"].append("Logout revokes authenticated access")
            report["success"] = True
        except Exception:
            traceback.print_exc(file=log)
            report["failed_stage"] = stage
            report["error"] = "Verification failed; inspect the private diagnostic log."
        finally:
            if csrf:
                try:
                    request("POST", "api/logout", {}, headers={"X-CSRF-Token": csrf})
                except Exception:
                    traceback.print_exc(file=log)
            cookie = None
    (FOLDER / "panel-verification.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
