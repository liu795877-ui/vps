"""Read-only unified profile checks using trusted HTTPS and isolated Mihomo.

Writes the downloaded client credentials and diagnostic logs only to private
artifacts. It never saves/applies panel settings or touches active FlClash.
"""

from datetime import datetime, timedelta, timezone
import copy
import importlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import time
import traceback
from unittest.mock import patch
from urllib.parse import quote
from urllib.request import Request, ProxyHandler, build_opener

import yaml


FOLDER = Path(__file__).resolve().parent
VALIDATION = FOLDER / "unified-profile-validation"
DOWNLOADED = FOLDER / "clash-unified-exits.private.yaml"
REPORT = FOLDER / "unified-profile-verification.json"
BINARY = Path(
    "C:/Users/LENOVO/.cockpit_tools/proxy-engine/"
    "release-490ee635-5175-46ca-a8c5-5e8a327cda34/mihomo.exe"
)
CURL = "C:/Windows/System32/curl.exe"
NO_WINDOW = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def panel_transport():
    # verify_panel discovers the physical WLAN on import. Preserve its request()
    # and TLS behavior while hiding that existing PowerShell subprocess too.
    original_run = subprocess.run

    def hidden_run(*args, **kwargs):
        kwargs.setdefault("creationflags", NO_WINDOW)
        return original_run(*args, **kwargs)

    with patch("subprocess.run", hidden_run):
        return importlib.import_module("verify_panel")


def free_port():
    with socket.socket() as stream:
        stream.bind(("127.0.0.1", 0))
        return stream.getsockname()[1]


def panel_request(panel, *args, **kwargs):
    for attempt in range(3):
        try:
            return panel.request(*args, **kwargs)
        except (OSError, http.client.HTTPException):
            if attempt == 2:
                raise


def no_upstream_credentials(value):
    if isinstance(value, dict):
        require(not {"username", "password"}.intersection(value),
                "Downloaded YAML contains unexpected upstream credential fields")
        for item in value.values():
            no_upstream_credentials(item)
    elif isinstance(value, list):
        for item in value:
            no_upstream_credentials(item)


def verify_structure(profile, state):
    require(isinstance(profile, dict), "Downloaded profile is not a YAML mapping")
    metadata = state.get("client_config")
    require(isinstance(metadata, dict), "Unified client metadata is not deployed")
    require(metadata.get("group") == "STATIC-SELECT", "Unexpected selection group")
    require(metadata.get("auto_node") == "AUTO · 网页切换", "Unexpected AUTO node")
    fixed = metadata.get("nodes")
    require(isinstance(fixed, list) and all(isinstance(name, str) for name in fixed),
            "Fixed node metadata is malformed")
    require(len(fixed) == metadata.get("exit_count") and len(fixed) > 0,
            "Applied exit count differs from metadata")
    expected_names = [metadata["auto_node"], *fixed]
    require(len(expected_names) == len(set(expected_names)), "Node names are not unique")
    nodes = profile.get("proxies")
    require(isinstance(nodes, list) and all(isinstance(node, dict) for node in nodes),
            "Downloaded proxies are malformed")
    require([node.get("name") for node in nodes] == expected_names,
            "Downloaded proxy list differs from all applied exits")
    groups = profile.get("proxy-groups", [])
    require(isinstance(groups, list) and all(isinstance(group, dict) for group in groups),
            "Downloaded proxy groups are malformed")
    selection = [group for group in groups if group.get("name") == metadata["group"]]
    require(len(selection) == 1 and selection[0].get("type") == "select",
            "Unified selection group is missing or is not selectable")
    require(selection[0].get("proxies") == expected_names,
            "Unified group does not contain AUTO and every applied fixed exit")
    for node in nodes:
        require(node.get("type") == "vless", "Unexpected outbound proxy protocol")
        require(node.get("server") == state["server_ip"] == "198.200.49.158",
                "Node connects to an unexpected entry server")
        require(node.get("port") == state["server_port"] == 443,
                "Node connects to an unexpected entry port")
        require(node.get("tls") is True and node.get("skip-cert-verify", False) is False,
                "Node does not preserve TLS validation")
        require(node.get("udp") is False, "Static node unexpectedly enables UDP")
        require(isinstance(node.get("reality-opts"), dict), "REALITY settings are missing")
    no_upstream_credentials(profile)
    return metadata, nodes


def expected_ips(state, metadata):
    values = {}
    for item in state.get("exits", []):
        if not item.get("pending"):
            values["出口 · " + item["name"]] = item.get("observed_ip") or item.get("expected_ip")
    active = state.get("active")
    if active:
        observed = active.get("observed_ip") or active.get("expected_ip")
        values[metadata["auto_node"]] = observed
        values["出口 · " + active["name"]] = observed
    return values


def controller_api(opener, address, secret, resource, method="GET", payload=None):
    request = Request(
        address + resource,
        method=method,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8") if payload is not None else None,
        headers={"Authorization": "Bearer " + secret, "Content-Type": "application/json"},
    )
    with opener.open(request, timeout=2) as response:
        body = response.read()
        return json.loads(body) if body else None


def check_exit(port, expected, log):
    attempts = []
    for attempt in range(1, 3):
        observed = None
        success = False
        try:
            result = subprocess.run(
                [CURL, "--proxy", "socks5h://127.0.0.1:" + str(port), "--noproxy", "",
                 "--connect-timeout", "8", "--max-time", "25", "--fail", "--silent",
                 "--show-error", "https://api.ipify.org"],
                capture_output=True, timeout=30, stdin=subprocess.DEVNULL,
                creationflags=NO_WINDOW,
            )
            log.write("IP probe attempt " + str(attempt) + ": " + str(result.returncode) + "\n")
            log.write(result.stdout.decode("utf-8", errors="replace") + "\n")
            log.write(result.stderr.decode("utf-8", errors="replace") + "\n")
            if result.returncode == 0:
                observed = str(ipaddress.ip_address(result.stdout.decode("ascii").strip()))
                success = ipaddress.ip_address(observed).is_global and (not expected or observed == expected)
        except Exception:
            traceback.print_exc(file=log)
        attempts.append({"attempt": attempt, "ip": observed, "success": success})
        log.flush()
        if success:
            break
    return {"success": success, "ip": observed, "expected_ip": expected, "attempts": attempts}


def main():
    VALIDATION.mkdir(exist_ok=True)
    report = {
        "checked_at": datetime.now(timezone(timedelta(hours=8))).isoformat(timespec="seconds"),
        "success": False,
        "counts": {},
        "ips": [],
    }
    panel = None
    csrf = None
    process = None
    stage = "login"
    with (VALIDATION / "verification.private.log").open("w", encoding="utf-8") as log:
        try:
            panel = panel_transport()
            login = json.loads((FOLDER / "panel-login.private.json").read_text(encoding="utf-8"))
            status, headers, body = panel_request(panel, "POST", "api/login", {
                "username": login["username"], "password": login["password"],
            })
            require(status == 200, "Console login failed")
            cookie = headers["Set-Cookie"]
            require(all(item in cookie for item in ("Secure", "HttpOnly", "SameSite=Strict")),
                    "Console cookie flags differ from expected")
            panel.cookie = cookie.split(";", 1)[0]
            csrf = json.loads(body)["csrf"]
            stage = "download"
            status, _, body = panel_request(panel, "GET", "api/state")
            require(status == 200, "Authenticated state request failed")
            state = json.loads(body)
            require(state.get("download_ready") and state.get("service_active") and not state.get("demo"),
                    "The production unified profile is not ready")
            require((state.get("job") or {}).get("status") != "running",
                    "Panel currently has an operation in progress; retry verification later")
            status, _, body = panel_request(panel, "GET", "api/profile")
            require(status == 200 and body, "Unified profile download failed")
            DOWNLOADED.write_bytes(body)
            stage = "structure"
            profile = yaml.safe_load(body)
            metadata, nodes = verify_structure(profile, state)
            report["counts"] = {"fixed_exits": metadata["exit_count"], "auto_nodes": 1,
                                "proxies": len(nodes), "selection_options": len(nodes)}
            stage = "full_mihomo_config"
            require(BINARY.is_file(), "Official local Mihomo binary was not found")
            syntax_dir = VALIDATION / "syntax"
            syntax_dir.mkdir(exist_ok=True)
            check = subprocess.run(
                [str(BINARY), "-t", "-d", str(syntax_dir), "-f", str(DOWNLOADED)],
                stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                timeout=45, creationflags=NO_WINDOW,
            )
            require(check.returncode == 0, "Complete downloaded profile failed Mihomo validation")
            report["full_config_valid"] = True
            stage = "isolated_mihomo"
            proxy_port, control_port = free_port(), free_port()
            while control_port == proxy_port:
                control_port = free_port()
            secret = secrets.token_urlsafe(24)
            group = metadata["group"]
            temporary = {
                "mixed-port": proxy_port, "bind-address": "127.0.0.1", "allow-lan": False,
                "external-controller": "127.0.0.1:" + str(control_port), "secret": secret,
                "mode": "rule", "interface-name": "WLAN", "tun": {"enable": False},
                "dns": {"enable": False}, "log-level": "warning",
                "unified-delay": True, "tcp-concurrent": True,
                "profile": {"store-selected": False, "store-fake-ip": False},
                "proxies": copy.deepcopy(nodes),
                "proxy-groups": [{"name": group, "type": "select", "proxies": [node["name"] for node in nodes]}],
                "rules": ["MATCH," + group],
            }
            client_dir = VALIDATION / ("client-" + secrets.token_hex(6))
            client_dir.mkdir()
            client_config = client_dir / "mihomo-unified.private.yaml"
            client_config.write_text(yaml.safe_dump(temporary, allow_unicode=True), encoding="utf-8")
            log.flush()
            process = subprocess.Popen(
                [str(BINARY), "-d", str(client_dir), "-f", str(client_config)],
                stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                creationflags=NO_WINDOW,
            )
            opener = build_opener(ProxyHandler({}))
            address = "http://127.0.0.1:" + str(control_port)
            for _ in range(50):
                require(process.poll() is None, "Isolated Mihomo exited before becoming ready")
                try:
                    controller_api(opener, address, secret, "/version")
                    break
                except OSError:
                    time.sleep(0.1)
            else:
                raise RuntimeError("Isolated Mihomo controller did not become ready")
            stage = "egress_probes"
            expected = expected_ips(state, metadata)
            resource = "/proxies/" + quote(group, safe="")
            for index, node in enumerate(nodes):
                log.write("Selecting private test node " + node["name"] + "\n")
                controller_api(opener, address, secret, resource, "PUT", {"name": node["name"]})
                selected = controller_api(opener, address, secret, resource)
                require(selected.get("now") == node["name"], "Temporary node selection did not take effect")
                check = check_exit(proxy_port, expected.get(node["name"]), log)
                check.update(kind="auto" if index == 0 else "fixed", index=index)
                report["ips"].append(check)
            require(all(item["success"] for item in report["ips"]),
                    "A unified profile exit failed its bounded IP check")
            stage = "stable_snapshot"
            status, _, body = panel_request(panel, "GET", "api/state")
            require(status == 200, "Final authenticated state request failed")
            final_state = json.loads(body)
            require(final_state.get("updated") == state.get("updated") and
                    (final_state.get("active") or {}).get("id") == (state.get("active") or {}).get("id") and
                    final_state.get("client_config") == metadata,
                    "Applied panel state changed while verifying; repeat against a stable snapshot")
            report["success"] = True
        except Exception:
            traceback.print_exc(file=log)
            report["failed_stage"] = stage
            report["error"] = "Verification failed; inspect the private diagnostic log."
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            if panel is not None and csrf:
                try:
                    panel_request(panel, "POST", "api/logout", {}, headers={"X-CSRF-Token": csrf})
                except Exception:
                    traceback.print_exc(file=log)
                panel.cookie = None
    REPORT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report))
    return 0 if report["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
